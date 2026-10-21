from uuid import uuid4

from fastapi.testclient import TestClient

from app.database.database import SessionLocal
from app.main import app
from app.models import Approval


def _clear_pending(client):
    for item in client.get("/api/approvals").json():
        client.post(f"/api/approvals/{item['approval_id']}/deny", json={})


def _request(client, resource):
    task = client.post("/api/tasks", json={"name": f"Approval test {uuid4().hex[:8]}"}).json()
    response = client.post("/api/actions/check", json={
        "task_id": task["task_id"],
        "agent": "generic-agent",
        "action_type": "READ",
        "resource": resource,
    })
    assert response.status_code == 200, response.text
    action = response.json()
    assert action["decision"] == "APPROVAL"
    return action


def _approval(client, action):
    return next(item for item in client.get("/api/approvals").json() if item["approval_id"] == action["approval_id"])


def test_approval_request_has_explanation_audit_and_websocket_resolution():
    with TestClient(app) as client:
        _clear_pending(client)
        with client.websocket_connect("/ws/events") as websocket:
            action = _request(client, ".env")
            action_event = websocket.receive_json()
            requested_event = websocket.receive_json()
            assert action_event["type"] == "ACTION_DECISION"
            assert requested_event["type"] == "APPROVAL_REQUESTED"
            assert requested_event["approval_id"] == action["approval_id"]
            pending = _approval(client, action)
            assert pending["status"] == "PENDING"
            assert pending["action"]["agent"] == "generic-agent"
            assert pending["action"]["metadata"]["resource_classification"]["classification"] == "SENSITIVE"
            assert pending["created_at"]
            response = client.post(f"/api/approvals/{pending['approval_id']}/approve", json={"note": "Reviewed"})
            resolved_event = websocket.receive_json()
        assert response.status_code == 200
        resolved = response.json()
        assert resolved["status"] == "APPROVED"
        assert resolved["resolved_at"]
        assert resolved["action"]["result"].startswith("SIMULATED: approved once")
        assert resolved_event["type"] == "APPROVAL_RESOLVED"
        assert resolved_event["status"] == "APPROVED"
        audit = client.get("/api/audit").json()
        requested = next(item for item in audit if item["event_type"] == "APPROVAL_REQUESTED" and item["action_id"] == action["action_id"])
        approved = next(item for item in audit if item["event_type"] == "APPROVAL_APPROVED" and item["action_id"] == action["action_id"])
        assert requested["details"]["resource"] == ".env"
        assert requested["details"]["agent"] == "generic-agent"
        assert approved["details"]["note"] == "Reviewed"
        assert approved["details"]["result"] == resolved["action"]["result"]


def test_allow_once_does_not_change_future_policy_decisions():
    with TestClient(app) as client:
        _clear_pending(client)
        rule = client.post("/api/protected-resources", json={
            "path": "step4_once/*",
            "classification": "PRIVATE",
            "decision": "APPROVAL",
            "description": "Step 4 allow once test",
        }).json()
        try:
            first = _request(client, "step4_once/report.bin")
            resolved = client.post(f"/api/approvals/{first['approval_id']}/approve", json={})
            assert resolved.status_code == 200
            assert resolved.json()["status"] == "APPROVED"
            assert resolved.json()["action"]["decision"] == "ALLOW"
            second = _request(client, "step4_once/report.bin")
            assert second["decision"] == "APPROVAL"
            current_rule = next(row for row in client.get("/api/protected-resources").json() if row["id"] == rule["id"])
            assert current_rule["decision"] == "APPROVAL" and current_rule["enabled"] is True
        finally:
            client.delete(f"/api/protected-resources/{rule['id']}")
            _clear_pending(client)


def test_deny_and_already_resolved_approval():
    with TestClient(app) as client:
        _clear_pending(client)
        action = _request(client, ".env")
        denied = client.post(f"/api/approvals/{action['approval_id']}/deny", json={})
        assert denied.status_code == 200
        assert denied.json()["status"] == "DENIED"
        assert denied.json()["action"]["decision"] == "BLOCK"
        assert denied.json()["action"]["executed"] is False
        assert "denied" in denied.json()["action"]["result"].lower()
        repeated = client.post(f"/api/approvals/{action['approval_id']}/approve", json={})
        assert repeated.status_code == 409


def test_bulk_resolves_only_pending_and_leaves_protected_policies_unchanged():
    with TestClient(app) as client:
        _clear_pending(client)
        rule = client.post("/api/protected-resources", json={
            "path": "step4_bulk/*",
            "classification": "PRIVATE",
            "decision": "APPROVAL",
            "description": "Step 4 bulk test",
        }).json()
        try:
            first = _request(client, "step4_bulk/one.bin")
            second = _request(client, "step4_bulk/two.bin")
            third = _request(client, "step4_bulk/three.bin")
            individual = client.post(f"/api/approvals/{first['approval_id']}/approve", json={})
            assert individual.status_code == 200
            before = next(row for row in client.get("/api/protected-resources").json() if row["id"] == rule["id"])
            bulk_approved = client.post("/api/approvals/approve-pending", json={}).json()
            assert bulk_approved["resolved_count"] == 2
            assert {item["approval_id"] for item in bulk_approved["approvals"]} == {second["approval_id"], third["approval_id"]}
            assert all(item["status"] == "APPROVED" for item in bulk_approved["approvals"])
            with SessionLocal() as db:
                assert db.get(Approval, first["approval_id"]).status == "APPROVED"
            fourth = _request(client, "step4_bulk/four.bin")
            bulk_denied = client.post("/api/approvals/deny-pending", json={}).json()
            assert bulk_denied["resolved_count"] == 1
            assert bulk_denied["approvals"][0]["approval_id"] == fourth["approval_id"]
            assert bulk_denied["approvals"][0]["status"] == "DENIED"
            after = next(row for row in client.get("/api/protected-resources").json() if row["id"] == rule["id"])
            assert after == before
            assert client.post("/api/approvals/approve-pending", json={}).json()["resolved_count"] == 0
        finally:
            client.delete(f"/api/protected-resources/{rule['id']}")
            _clear_pending(client)


def test_legacy_block_endpoint_resolves_as_denied():
    with TestClient(app) as client:
        _clear_pending(client)
        action = _request(client, ".env")
        response = client.post(f"/api/approvals/{action['approval_id']}/block", json={})
        assert response.status_code == 200
        assert response.json()["status"] == "DENIED"
