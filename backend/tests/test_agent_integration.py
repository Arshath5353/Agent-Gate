from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def request_body(action_type="READ", resource="src/example.py", **overrides):
    body = {
        "agent": {"id": "example-agent", "name": "Example Coding Agent", "version": "1.0"},
        "session_id": f"session-{uuid4().hex[:8]}",
        "source": "test-connector",
        "action": {"type": action_type, "resource": resource, "metadata": {}},
    }
    body.update(overrides)
    return body


def check(client, action_type="READ", resource="src/example.py", **overrides):
    return client.post("/api/agent/actions/check", json=request_body(action_type, resource, **overrides))


@pytest.mark.parametrize(
    ("action_type", "resource", "decision"),
    [
        ("READ", "src/integration_read.py", {"ALLOW", "MONITOR"}),
        ("WRITE", "src/integration_write.py", {"ALLOW", "MONITOR"}),
        ("DELETE", "src/integration_delete.py", {"ALLOW", "MONITOR"}),
        ("EXECUTE", "npm test", {"ALLOW", "MONITOR"}),
        ("NETWORK_CONNECT", "localhost", {"ALLOW", "MONITOR"}),
        ("TOOL_CALL", "browser.search", {"MONITOR", "APPROVAL"}),
    ],
)
def test_generic_agent_supports_normalized_action_types(client, action_type, resource, decision):
    response = check(client, action_type, resource)
    assert response.status_code == 200, response.text
    assert response.json()["decision"] in decision
    assert response.json()["action"]["action_type"] == action_type


def test_generic_agent_response_preserves_identity_session_and_classification(client):
    body = request_body("READ", ".env")
    body["session_id"] = "review-session-9"
    response = client.post("/api/agent/actions/check", json=body)
    result = response.json()
    assert response.status_code == 200
    assert result["decision"] == "APPROVAL"
    assert result["approval_id"]
    assert result["resource"]["classification"] == "SENSITIVE"
    assert result["risk"]["level"] == "HIGH"
    assert result["risk"]["score"] >= 70
    assert result["agent"] == {"id": "example-agent", "name": "Example Coding Agent", "version": "1.0"}
    assert result["session_id"] == "review-session-9"
    assert result["source"] == "agent_api"
    assert result["integration_source"] == "test-connector"
    assert result["action"]["metadata"]["session_id"] == "review-session-9"
    assert result["action"]["metadata"]["integration_source"] == "test-connector"
    assert result["action"]["agent"] == "Example Coding Agent"


def test_generic_agent_uses_protected_resource_policy(client):
    rule = client.post("/api/protected-resources", json={
        "path": "src/integration-protected/*",
        "classification": "PRIVATE",
        "decision": "BLOCK",
        "description": "Integration protected test resource",
    }).json()
    try:
        response = check(client, "READ", "src/integration-protected/finance.csv")
        assert response.status_code == 200
        result = response.json()
        assert result["decision"] == "BLOCK"
        assert any(match["id"] == rule["id"] for match in result["protected_resource_matches"])
    finally:
        client.delete(f"/api/protected-resources/{rule['id']}")


def test_generic_agent_dangerous_command_is_blocked(client):
    response = check(client, "EXECUTE", "rm -rf /")
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"


def test_agent_metadata_cannot_spoof_network_destination(client):
    body = request_body("NETWORK_CONNECT", "https://evil.example/path")
    body["action"]["metadata"]["host"] = "localhost"
    response = client.post("/api/agent/actions/check", json=body)
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"


@pytest.mark.parametrize(
    "body",
    [
        request_body("SLEEP", "src/example.py"),
        {**request_body(), "agent": {"id": " ", "name": ""}},
        request_body("READ", "   "),
    ],
)
def test_generic_agent_rejects_invalid_action_or_identity(client, body):
    response = client.post("/api/agent/actions/check", json=body)
    assert response.status_code == 422


def test_generic_agent_task_id_is_optional_and_creates_scoped_task(client):
    response = client.post("/api/agent/actions/check", json=request_body("READ", "src/without_task.py"))
    assert response.status_code == 200
    result = response.json()
    assert result["task_id"]
    task = client.get(f"/api/tasks/{result['task_id']}").json()
    assert task["allowed_scope"] == ["src/", "tests/", "package.json"]


def test_agent_metadata_cannot_expand_the_declared_task_scope(client):
    task = client.post("/api/tasks", json={
        "name": "Integration scope boundary",
        "allowed_scope": ["tests/"],
    }).json()
    body = request_body("READ", "src/outside-declared-scope.py", task_id=task["task_id"])
    body["action"]["metadata"]["allowed_scope"] = [""]
    response = client.post("/api/agent/actions/check", json=body)
    assert response.status_code == 200
    result = response.json()
    assert "Resource is outside the task's declared scope" in result["reasons"]
    assert result["action"]["metadata"]["allowed_scope"] == ["tests/"]


def test_generic_agent_actions_appear_in_runtime_filter_without_changing_windows_sources(client):
    task = client.post("/api/tasks", json={"name": "Generic source filter test"}).json()
    generic = client.post("/api/agent/actions/check", json=request_body("WRITE", "src/api_source.py", task_id=task["task_id"])).json()
    observed = client.post("/api/actions/check", json={
        "task_id": task["task_id"],
        "agent": "WINDOWS_MONITOR",
        "agent_source": "windows_monitor",
        "action_type": "WRITE",
        "resource": "src/windows_source.py",
    }).json()
    simulated = client.post("/api/actions/check", json={
        "task_id": task["task_id"],
        "agent": "simulator",
        "action_type": "WRITE",
        "resource": "src/simulator_source.py",
    }).json()
    runtime_ids = {item["action_id"] for item in client.get("/api/actions?source=runtime").json()}
    assert generic["action_id"] in runtime_ids
    assert observed["action_id"] in runtime_ids
    assert simulated["action_id"] not in runtime_ids


def test_existing_action_check_contract_remains_available(client):
    task = client.post("/api/tasks", json={"name": "Legacy action check test"}).json()
    response = client.post("/api/actions/check", json={
        "task_id": task["task_id"],
        "action_type": "READ",
        "resource": "src/legacy.py",
    })
    assert response.status_code == 200
    assert {"action_id", "decision", "risk_level", "risk_score", "approval_id"} <= response.json().keys()
