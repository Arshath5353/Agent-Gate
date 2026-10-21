import os
import shutil
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.main as api
from app.config import WORKSPACE


def test_fastapi_lifecycle_starts_and_stops_workspace_monitor(monkeypatch):
    calls = {"start": 0, "stop": 0, "lease_release": 0}

    class FakeLease:
        def release(self):
            calls["lease_release"] += 1

    class FakeMonitor:
        def __init__(self, task_id, submit_action):
            calls["task_id"] = task_id
            calls["submit_action"] = submit_action
            self.is_running = False

        def start(self):
            calls["start"] += 1
            self.is_running = True
            return True

        def stop(self):
            calls["stop"] += 1
            self.is_running = False

    monkeypatch.setattr(api, "_windows_monitor_enabled", lambda: True)
    monkeypatch.setattr(api, "_acquire_workspace_monitor_lease", lambda workspace: FakeLease())
    monkeypatch.setattr(api, "_ensure_runtime_task", lambda: "TASK-LIFECYCLE-TEST")
    monkeypatch.setattr(api, "WorkspaceRuntimeMonitor", FakeMonitor)

    with TestClient(api.app) as client:
        runtime = client.get("/api/runtime/mode").json()
        assert runtime["mode"] == "WINDOWS_MONITOR"
        assert runtime["monitor_status"] == "ACTIVE"
        assert calls["start"] == 1
        assert calls["task_id"] == "TASK-LIFECYCLE-TEST"
        assert api.app.state.windows_workspace_monitor is not None

    assert calls["stop"] == 1
    assert calls["lease_release"] == 1
    assert api.app.state.windows_workspace_monitor is None
    runtime = api.get_runtime_mode()
    assert runtime["mode"] == "NOT_ACTIVE"
    assert runtime["monitor_status"] == "OFFLINE"


def test_fastapi_lifecycle_reports_offline_when_monitor_start_fails(monkeypatch):
    class FakeLease:
        def __init__(self):
            self.released = False

        def release(self):
            self.released = True

    lease = FakeLease()

    class FailedMonitor:
        is_running = False

        def __init__(self, task_id, submit_action):
            pass

        def start(self):
            raise OSError("watcher could not start")

    monkeypatch.setattr(api, "_windows_monitor_enabled", lambda: True)
    monkeypatch.setattr(api, "_acquire_workspace_monitor_lease", lambda workspace: lease)
    monkeypatch.setattr(api, "_ensure_runtime_task", lambda: "TASK-FAILED-MONITOR-TEST")
    monkeypatch.setattr(api, "WorkspaceRuntimeMonitor", FailedMonitor)

    with TestClient(api.app) as client:
        runtime = client.get("/api/runtime/mode").json()
        assert runtime["monitor_status"] == "OFFLINE"
        assert runtime["mode"] == "NOT_ACTIVE"
        assert api.app.state.windows_workspace_monitor is None
    assert lease.released


def test_fastapi_lifecycle_skips_monitor_when_another_backend_owns_workspace(monkeypatch):
    class ShouldNotStartMonitor:
        def __init__(self, *args, **kwargs):
            pytest.fail("a second backend must not create another workspace watcher")

    monkeypatch.setattr(api, "_windows_monitor_enabled", lambda: True)
    monkeypatch.setattr(api, "_acquire_workspace_monitor_lease", lambda workspace: None)
    monkeypatch.setattr(api, "_ensure_runtime_task", lambda: pytest.fail("task setup must not run without ownership"))
    monkeypatch.setattr(api, "WorkspaceRuntimeMonitor", ShouldNotStartMonitor)

    with TestClient(api.app) as client:
        runtime = client.get("/api/runtime/mode").json()
        assert runtime["mode"] == "NOT_ACTIVE"
        assert runtime["monitor_status"] == "OFFLINE"
        assert api.app.state.windows_workspace_monitor is None


@pytest.mark.skipif(os.name != "nt", reason="Uses the Windows named-mutex API")
def test_workspace_monitor_lease_is_exclusive_and_released(tmp_path):
    first = api._acquire_workspace_monitor_lease(tmp_path)
    assert first is not None
    try:
        assert api._acquire_workspace_monitor_lease(tmp_path) is None
    finally:
        first.release()

    second = api._acquire_workspace_monitor_lease(tmp_path)
    assert second is not None
    second.release()


def test_monitor_health_status_distinguishes_lifecycle_and_unreadable_health():
    class RunningMonitor:
        is_running = True

    class StoppedMonitor:
        is_running = False

    class UnknownMonitor:
        @property
        def is_running(self):
            raise RuntimeError("health unavailable")

    assert api._windows_monitor_health_status(None, "STARTING") == "STARTING"
    assert api._windows_monitor_health_status(RunningMonitor(), "ACTIVE") == "ACTIVE"
    assert api._windows_monitor_health_status(StoppedMonitor(), "ACTIVE") == "OFFLINE"
    assert api._windows_monitor_health_status(None, "OFFLINE") == "OFFLINE"
    assert api._windows_monitor_health_status(None, "UNKNOWN") == "UNKNOWN"
    assert api._windows_monitor_health_status(UnknownMonitor(), "ACTIVE") == "UNKNOWN"


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows ReadDirectoryChangesW API")
def test_real_workspace_change_reaches_policy_sqlite_and_websocket_pipeline():
    folder = WORKSPACE / f"runtime_lifecycle_test_{uuid4().hex}"
    relative_file = f"{folder.name}/hello.txt"
    try:
        with TestClient(api.app) as client:
            runtime = client.get("/api/runtime/mode").json()
            assert runtime["mode"] == "WINDOWS_MONITOR"
            assert runtime["monitor_status"] == "ACTIVE"
            with client.websocket_connect("/ws/events") as websocket:
                folder.mkdir()
                (folder / "hello.txt").write_text("first harmless version\n", encoding="utf-8")

                deadline = time.monotonic() + 10
                stored_action = None
                while time.monotonic() < deadline:
                    actions = client.get("/api/actions?source=runtime").json()
                    stored_action = next((item for item in actions if item["resource"] == relative_file), None)
                    if stored_action:
                        break
                    time.sleep(0.1)

                assert stored_action is not None, "filesystem notification was not stored as an AgentGate action"
                assert stored_action["agent"] == "WINDOWS_MONITOR"
                assert stored_action["agent_source"] == "windows_monitor"
                assert stored_action["action_type"] == "WRITE"
                assert stored_action["decision"] in {"ALLOW", "MONITOR", "APPROVAL", "BLOCK"}
                assert stored_action["pid"] is None
                assert stored_action["metadata"]["process_attribution"] == "unavailable_from_directory_notification"

                event = websocket.receive_json()
                assert event["type"] == "ACTION_DECISION"
                assert event["resource"] == relative_file
                assert event["agent_source"] == "windows_monitor"
                assert event["action_id"] in {
                    item["action_id"] for item in actions if item["resource"] == relative_file
                }
    finally:
        shutil.rmtree(folder, ignore_errors=True)
