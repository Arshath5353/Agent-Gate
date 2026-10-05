import os
import shutil
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.main as api
from app.config import WORKSPACE


def test_fastapi_lifecycle_starts_and_stops_workspace_monitor(monkeypatch):
    calls = {"start": 0, "stop": 0}

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
    monkeypatch.setattr(api, "_ensure_runtime_task", lambda: "TASK-LIFECYCLE-TEST")
    monkeypatch.setattr(api, "WorkspaceRuntimeMonitor", FakeMonitor)

    with TestClient(api.app) as client:
        assert client.get("/api/runtime/mode").json()["mode"] == "WINDOWS_MONITOR"
        assert calls["start"] == 1
        assert calls["task_id"] == "TASK-LIFECYCLE-TEST"
        assert api.app.state.windows_workspace_monitor is not None

    assert calls["stop"] == 1
    assert api.app.state.windows_workspace_monitor is None
    assert api.get_runtime_mode()["mode"] == "NOT_ACTIVE"


@pytest.mark.skipif(os.name != "nt", reason="Requires the Windows ReadDirectoryChangesW API")
def test_real_workspace_change_reaches_policy_sqlite_and_websocket_pipeline():
    folder = WORKSPACE / f"runtime_lifecycle_test_{uuid4().hex}"
    relative_file = f"{folder.name}/hello.txt"
    try:
        with TestClient(api.app) as client:
            assert client.get("/api/runtime/mode").json()["mode"] == "WINDOWS_MONITOR"
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
                assert stored_action["decision"] in {"ALLOW", "APPROVAL", "BLOCK"}
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
