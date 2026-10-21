from fastapi.testclient import TestClient
import pytest

from app.config import WORKSPACE
from app.main import app
from app.services.resource_classifier import normalize_protected_pattern


@pytest.fixture(autouse=True)
def clean_protected_resources():
    # Run lifespan first so legacy SQLite databases receive the additive migration.
    with TestClient(app) as client:
        for item in client.get("/api/protected-resources").json():
            client.delete(f"/api/protected-resources/{item['id']}")
    yield
    with TestClient(app) as client:
        for item in client.get("/api/protected-resources").json():
            client.delete(f"/api/protected-resources/{item['id']}")


def create_task(client):
    response = client.post("/api/tasks", json={"name": "Protected-resource test"})
    assert response.status_code == 200
    return response.json()["task_id"]


def create_protected(client, path, classification="SENSITIVE", decision="BLOCK", enabled=True):
    return client.post("/api/protected-resources", json={
        "path": path,
        "classification": classification,
        "decision": decision,
        "description": "Protected-resource test rule",
        "enabled": enabled,
    })


def test_protected_resource_crud():
    with TestClient(app) as client:
        created = create_protected(client, "secrets/*", "CRITICAL", "BLOCK")
        assert created.status_code == 200
        item = created.json()
        assert item["id"] and item["path"] == "secrets/*"
        assert item["classification"] == "CRITICAL" and item["decision"] == "BLOCK"
        assert item["enabled"] is True and item["created_at"]

        listed = client.get("/api/protected-resources")
        assert listed.status_code == 200
        assert any(row["id"] == item["id"] for row in listed.json())

        updated = client.put(f"/api/protected-resources/{item['id']}", json={
            "path": "private/reports/*",
            "classification": "PRIVATE",
            "decision": "APPROVAL",
            "description": "Updated rule",
            "enabled": False,
        })
        assert updated.status_code == 200
        assert updated.json()["path"] == "private/reports/*"
        assert updated.json()["classification"] == "PRIVATE"
        assert updated.json()["decision"] == "APPROVAL"
        assert updated.json()["enabled"] is False
        assert updated.json()["updated_at"]

        deleted = client.delete(f"/api/protected-resources/{item['id']}")
        assert deleted.status_code == 200 and deleted.json()["deleted"] is True
        assert all(row["id"] != item["id"] for row in client.get("/api/protected-resources").json())


def test_exact_path_matching_and_security_explanation_are_persisted():
    with TestClient(app) as client:
        policy = create_protected(client, "secrets/password.txt", "CRITICAL", "BLOCK").json()
        task_id = create_task(client)
        response = client.post("/api/actions/check", json={
            "task_id": task_id,
            "agent": "generic-agent",
            "action_type": "READ",
            "resource": "secrets/password.txt",
        })
        assert response.status_code == 200
        action = response.json()
        assert action["decision"] == "BLOCK"
        assert action["metadata"]["resource_classification"]["classification"] == "CRITICAL"
        match = action["metadata"]["protected_resource_matches"][0]
        assert match["id"] == policy["id"]
        assert match["pattern"] == "secrets/password.txt"
        assert match["classification"] == "CRITICAL" and match["decision"] == "BLOCK"
        assert match["reason"] == "Explicit protected-resource policy"
        event = next(item for item in client.get("/api/audit").json() if item["action_id"] == action["action_id"] and item["event_type"] == "ACTION_EVALUATED")
        assert event["details"]["protected_resource_matches"][0]["id"] == policy["id"]


def test_pattern_matching_applies_approval():
    with TestClient(app) as client:
        policy = create_protected(client, "private/reports/*", "PRIVATE", "APPROVAL").json()
        task_id = create_task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": "private/reports/report.pdf",
        }).json()
        assert action["decision"] == "APPROVAL"
        assert action["metadata"]["resource_classification"]["classification"] == "PRIVATE"
        assert action["metadata"]["protected_resource_matches"][0]["id"] == policy["id"]


def test_protected_monitor_decision_is_applied():
    with TestClient(app) as client:
        create_protected(client, "review/*", "UNKNOWN", "MONITOR")
        task_id = create_task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": "review/unknown.data",
        }).json()
        assert action["decision"] == "MONITOR"


def test_protected_file_policy_does_not_match_network_or_command_resources():
    with TestClient(app) as client:
        create_protected(client, "secrets/*", "CRITICAL", "BLOCK")
        task_id = create_task(client)
        network = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "NETWORK_CONNECT",
            "resource": "secrets.example.com",
        }).json()
        assert network["decision"] == "APPROVAL"
        assert network["metadata"]["protected_resource_matches"] == []


def test_windows_absolute_path_normalizes_case_insensitively():
    with TestClient(app) as client:
        protected_path = str(WORKSPACE / "Secrets" / "Credentials.JSON").replace("/", "\\")
        policy = create_protected(client, protected_path, "CRITICAL", "BLOCK").json()
        assert policy["path"] == "secrets/credentials.json"
        task_id = create_task(client)
        action_path = str(WORKSPACE / "secrets" / "credentials.json")
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": action_path,
        }).json()
        assert action["decision"] == "BLOCK"
        assert action["metadata"]["protected_resource_matches"][0]["id"] == policy["id"]


def test_protected_policy_overrides_automatic_classification():
    with TestClient(app) as client:
        policy = create_protected(client, "reports/salary.xlsx", "PRIVATE", "APPROVAL").json()
        task_id = create_task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": "reports/salary.xlsx",
        }).json()
        assert action["decision"] == "APPROVAL"
        result = action["metadata"]["resource_classification"]
        assert result["classification"] == "PRIVATE"
        assert "Explicit protected-resource policy" in result["reasons"]
        assert any(indicator.get("id") == policy["id"] for indicator in result["matched_indicators"])


def test_disabled_protected_resource_does_not_match():
    with TestClient(app) as client:
        create_protected(client, "secrets/*", "CRITICAL", "BLOCK", enabled=False)
        task_id = create_task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": "secrets/password.txt",
        }).json()
        assert action["decision"] != "BLOCK"
        assert action["metadata"]["protected_resource_matches"] == []


def test_prefix_collision_does_not_match_a_protected_pattern():
    with TestClient(app) as client:
        create_protected(client, "secrets/*", "CRITICAL", "BLOCK")
        task_id = create_task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": "secrets-backup/password.txt",
        }).json()
        assert action["decision"] != "BLOCK"
        assert action["metadata"]["protected_resource_matches"] == []


def test_traversal_cannot_bypass_workspace_security_or_match_policy():
    with TestClient(app) as client:
        create_protected(client, "secrets/*", "CRITICAL", "MONITOR")
        task_id = create_task(client)
        action = client.post("/api/actions/check", json={
            "task_id": task_id,
            "action_type": "READ",
            "resource": "secrets/../secrets/password.txt",
        }).json()
        assert action["decision"] == "BLOCK"
        assert action["metadata"]["protected_resource_matches"] == []


def test_malformed_paths_outside_workspace_and_traversal_are_rejected():
    with TestClient(app) as client:
        assert create_protected(client, "../secrets/*").status_code == 422
        assert create_protected(client, str(WORKSPACE.parent / "outside" / "*.txt")).status_code == 422


def test_protected_pattern_cannot_escape_through_symlink(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    with pytest.raises(ValueError, match="inside the controlled workspace"):
        normalize_protected_pattern("escape/*", root)
