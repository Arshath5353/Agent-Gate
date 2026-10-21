from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time
from uuid import uuid4

from fastapi.testclient import TestClient

from app import main
from app.config import WORKSPACE
from app.main import app
from app.models import AuditEvent, BrokerExecution
from app.database.database import SessionLocal
from sqlalchemy import select

DEMO = WORKSPACE / "enforcement_demo"


def _task(client):
    response = client.post("/api/tasks", json={
        "name": f"Broker test {uuid4().hex[:10]}",
        "allowed_scope": ["enforcement_demo/"],
    })
    assert response.status_code == 200, response.text
    return response.json()["task_id"]


def _broker(client, task_id, action_type, resource, metadata=None):
    response = client.post("/api/broker/execute", json={
        "task_id": task_id, "agent": "broker-test-agent",
        "action_type": action_type, "resource": resource,
        "metadata": metadata or {},
    })
    assert response.status_code == 200, response.text
    return response.json()


def _protect(client, path, decision="APPROVAL"):
    response = client.post("/api/protected-resources", json={
        "path": path, "classification": "SENSITIVE", "decision": decision,
        "description": "Broker lifecycle test rule",
    })
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _await_pending(client, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = client.get("/api/approvals").json()
        broker_items = [item for item in pending if item["action"]["metadata"].get("broker_managed")]
        if broker_items:
            return broker_items[0]
        time.sleep(0.02)
    raise AssertionError("Broker approval did not appear")


def _wait_future(future, timeout=5):
    return future.result(timeout=timeout)


def test_allow_executes_only_controlled_fixture_and_records_result():
    fixture = DEMO / "allowed_demo.py"
    original = fixture.read_text(encoding="utf-8")
    try:
        with TestClient(app) as client:
            result = _broker(client, _task(client), "READ", "enforcement_demo/allowed_demo.py")
            assert result["action"]["decision"] == "ALLOW"
            assert result["action"]["executed"] is True
            assert result["execution"]["execution_status"] == "EXECUTED"
            assert result["execution"]["execution_id"]
            assert "DEMO_VALUE" in result["execution"]["result"]["content"]
            assert client.get(f"/api/executions/{result['execution']['execution_id']}").json()["execution_status"] == "EXECUTED"

            written = _broker(client, _task(client), "WRITE", "enforcement_demo/allowed_demo.py", {"content": "DEMO_VALUE = 'written by broker'\n"})
            assert written["action"]["decision"] == "ALLOW"
            assert written["execution"]["execution_status"] == "EXECUTED"
            assert fixture.read_text(encoding="utf-8") == "DEMO_VALUE = 'written by broker'\n"
    finally:
        fixture.write_text(original, encoding="utf-8")


def test_delete_is_limited_to_disposable_fixture():
    fixture = DEMO / "delete_me.py"
    original = fixture.read_text(encoding="utf-8") if fixture.exists() else None
    fixture.write_text('"""Disposable fixture."""\n', encoding="utf-8")
    try:
        with TestClient(app) as client:
            result = _broker(client, _task(client), "DELETE", "enforcement_demo/delete_me.py")
            assert result["execution"]["execution_status"] == "EXECUTED"
            assert not fixture.exists()
    finally:
        if original is not None:
            fixture.write_text(original, encoding="utf-8")
        elif fixture.exists():
            fixture.unlink()


def test_blocked_action_never_calls_executor(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "execute_controlled_action", lambda *args, **kwargs: calls.append(args))
    with TestClient(app) as client:
        result = _broker(client, _task(client), "EXECUTE", "rm -rf controlled_workspace")
    assert result["action"]["decision"] == "BLOCK"
    assert result["execution"]["execution_status"] == "NOT_EXECUTED"
    assert not calls


def test_approval_holds_operation_until_allow_once_then_executes_once(monkeypatch):
    monkeypatch.setattr(main, "BROKER_APPROVAL_TIMEOUT_SECONDS", 3)
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        task_id = _task(client)
        policy_id = _protect(client, "enforcement_demo/approval_demo.py")
        try:
            future = pool.submit(_broker, client, task_id, "READ", "enforcement_demo/approval_demo.py")
            pending = _await_pending(client)
            execution = client.get(f"/api/actions/{pending['action_id']}").json()["metadata"]
            assert execution["execution_status"] == "PENDING_APPROVAL"
            assert not future.done()
            allowed = client.post(f"/api/approvals/{pending['approval_id']}/approve", json={})
            assert allowed.status_code == 200
            result = _wait_future(future)
            assert result["execution"]["execution_status"] == "EXECUTED"
            assert result["action"]["executed"] is True
            assert result["execution"]["approval_id"] == pending["approval_id"]
        finally:
            client.delete(f"/api/protected-resources/{policy_id}")


def test_exact_allowlisted_command_runs_only_after_approval(monkeypatch):
    monkeypatch.setattr(main, "BROKER_APPROVAL_TIMEOUT_SECONDS", 3)
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        task_id = _task(client)
        future = pool.submit(_broker, client, task_id, "EXECUTE", "python --version")
        pending = _await_pending(client)
        assert not future.done()
        assert client.post(f"/api/approvals/{pending['approval_id']}/approve", json={}).status_code == 200
        result = _wait_future(future)
        assert result["execution"]["execution_status"] == "EXECUTED"
        assert result["execution"]["result"]["resource"] == "python --version"
        assert result["execution"]["result"]["output"].lower().startswith("python ")


def test_approval_deny_does_not_execute(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "BROKER_APPROVAL_TIMEOUT_SECONDS", 3)
    monkeypatch.setattr(main, "execute_controlled_action", lambda *args, **kwargs: calls.append(args))
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        task_id = _task(client)
        policy_id = _protect(client, "enforcement_demo/approval_demo.py")
        try:
            future = pool.submit(_broker, client, task_id, "READ", "enforcement_demo/approval_demo.py")
            pending = _await_pending(client)
            assert client.post(f"/api/approvals/{pending['approval_id']}/deny", json={}).status_code == 200
            result = _wait_future(future)
            assert result["execution"]["execution_status"] == "DENIED"
            assert result["action"]["executed"] is False
            assert not calls
        finally:
            client.delete(f"/api/protected-resources/{policy_id}")


def test_expired_approval_never_executes(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "BROKER_APPROVAL_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(main, "BROKER_APPROVAL_POLL_SECONDS", 0.02)
    monkeypatch.setattr(main, "execute_controlled_action", lambda *args, **kwargs: calls.append(args))
    with TestClient(app) as client:
        policy_id = _protect(client, "enforcement_demo/approval_demo.py")
        try:
            result = _broker(client, _task(client), "READ", "enforcement_demo/approval_demo.py")
            assert result["execution"]["execution_status"] == "EXPIRED"
            assert result["action"]["decision"] == "BLOCK"
            assert not calls
        finally:
            client.delete(f"/api/protected-resources/{policy_id}")


def test_replay_is_newly_evaluated_and_old_approval_is_not_reused(monkeypatch):
    monkeypatch.setattr(main, "BROKER_APPROVAL_TIMEOUT_SECONDS", 0.15)
    monkeypatch.setattr(main, "BROKER_APPROVAL_POLL_SECONDS", 0.02)
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        task_id = _task(client)
        policy_id = _protect(client, "enforcement_demo/approval_demo.py")
        try:
            first_future = pool.submit(_broker, client, task_id, "READ", "enforcement_demo/approval_demo.py")
            first_pending = _await_pending(client)
            first = client.post(f"/api/approvals/{first_pending['approval_id']}/approve", json={}).json()
            first_result = _wait_future(first_future)
            assert first["status"] == "APPROVED"
            assert first_result["execution"]["execution_status"] == "EXECUTED"

            replay = _broker(client, task_id, "READ", "enforcement_demo/approval_demo.py")
            assert replay["action"]["action_id"] != first_result["action"]["action_id"]
            assert replay["execution"]["approval_id"] != first_pending["approval_id"]
            assert replay["execution"]["execution_status"] == "EXPIRED"
        finally:
            client.delete(f"/api/protected-resources/{policy_id}")


def test_protected_block_and_unknown_command_fail_closed(monkeypatch):
    monkeypatch.setattr(main, "BROKER_APPROVAL_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(main, "BROKER_APPROVAL_POLL_SECONDS", 0.02)
    with TestClient(app) as client:
        task = _task(client)
        blocked_id = _protect(client, "enforcement_demo/protected_demo.txt", decision="BLOCK")
        try:
            protected = _broker(client, task, "READ", "enforcement_demo/protected_demo.txt")
            assert protected["action"]["decision"] == "BLOCK"
            assert protected["execution"]["execution_status"] == "NOT_EXECUTED"
        finally:
            client.delete(f"/api/protected-resources/{blocked_id}")

        unknown = _broker(client, task, "EXECUTE", "python -c print('not run')")
        assert unknown["execution"]["execution_status"] == "EXPIRED"
        assert unknown["execution"]["approval_id"]
        assert any(match["id"] == "AG-CMD-003" for match in unknown["action"]["matched_policies"])


def test_invalid_resource_and_execution_failure_are_recorded(monkeypatch):
    with TestClient(app) as client:
        task = _task(client)
        invalid = _broker(client, task, "READ", "enforcement_demo/nested/allowed_demo.py")
        assert invalid["execution"]["execution_status"] == "FAILED"
        assert invalid["action"]["executed"] is False

    monkeypatch.setattr(main, "execute_controlled_action", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("private detail")))
    with TestClient(app) as client:
        failed = _broker(client, _task(client), "READ", "enforcement_demo/allowed_demo.py")
    assert failed["execution"]["execution_status"] == "FAILED"
    assert failed["execution"]["error"] == "Controlled operation failed"
    assert failed["action"]["executed"] is False


def test_audit_correlates_action_approval_and_execution():
    with TestClient(app) as client:
        result = _broker(client, _task(client), "READ", "enforcement_demo/allowed_demo.py")
        action_id = result["action"]["action_id"]
        execution_id = result["execution"]["execution_id"]
        with SessionLocal() as db:
            rows = db.scalars(select(AuditEvent).where(AuditEvent.action_id == action_id)).all()
            correlated = [row for row in rows if row.details.get("execution_id") == execution_id]
        assert {row.event_type for row in correlated} >= {
            "BROKER_ACTION_REQUESTED", "EXECUTION_STARTED", "EXECUTION_COMPLETED"
        }
        with SessionLocal() as db:
            stored = db.scalar(select(BrokerExecution).where(BrokerExecution.id == execution_id))
            assert stored.action_id == action_id
            assert stored.approval_id is None


def test_existing_simulator_execute_remains_simulated():
    with TestClient(app) as client:
        task = _task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task, "action_type": "READ", "resource": "enforcement_demo/allowed_demo.py",
        }).json()
        response = client.post(f"/api/actions/{action['action_id']}/execute")
        assert response.status_code == 200
        assert response.json()["result"].startswith("SIMULATED:")
        assert response.json()["metadata"].get("broker_managed") is not True


def test_network_action_is_recorded_as_simulation_without_opening_a_socket():
    with TestClient(app) as client:
        result = _broker(client, _task(client), "NETWORK_CONNECT", "localhost")
    assert result["action"]["decision"] == "ALLOW"
    assert result["execution"]["execution_status"] == "EXECUTED"
    assert result["execution"]["result"]["simulated"] is True
    assert "no connection was opened" in result["execution"]["result"]["message"]
