from fastapi.testclient import TestClient
from app.main import app

def test_action_approval_audit_and_websocket():
    with TestClient(app) as client:
        task=client.post("/api/tasks",json={"name":"API test"}).json()
        with client.websocket_connect("/ws/events") as ws:
            result=client.post("/api/actions/check",json={"task_id":task["task_id"],"action_type":"READ","resource":".env"}).json()
            event=ws.receive_json()
        assert result["decision"]=="APPROVAL" and result["approval_id"]
        assert event["type"]=="ACTION_DECISION" and event["action_id"]==result["action_id"]
        approvals=client.get("/api/approvals").json(); pending=next(x for x in approvals if x["approval_id"]==result["approval_id"])
        response=client.post(f"/api/approvals/{pending['approval_id']}/approve",json={})
        assert response.status_code==200 and response.json()["status"]=="APPROVED"
        assert response.json()["action"]["executed"] is True
        executed=client.post(f"/api/actions/{result['action_id']}/execute")
        assert executed.status_code==200 and executed.json()["executed"] is True
        assert client.get("/api/audit").json()

def test_demo_scenarios():
    with TestClient(app) as client:
        result=client.post("/api/demo/run").json()
        assert [x["decision"] for x in result["actions"]]==["ALLOW","ALLOW","APPROVAL","BLOCK","BLOCK","ALLOW","BLOCK","APPROVAL"]
        assert all(x["agent_source"]=="simulator" for x in result["actions"])

def test_action_source_filter_excludes_historical_simulator_events_from_runtime_feed():
    with TestClient(app) as client:
        task=client.post("/api/tasks",json={"name":"Live source filtering test"}).json()
        simulated=client.post("/api/actions/check",json={"task_id":task["task_id"],"action_type":"WRITE","resource":"real_agent_demo/simulated.txt"}).json()
        observed=client.post("/api/actions/check",json={"task_id":task["task_id"],"agent":"WINDOWS_MONITOR","agent_source":"windows_monitor","action_type":"WRITE","resource":"real_agent_demo/observed.txt","metadata":{"source":"windows_monitor"}}).json()
        runtime=client.get("/api/actions?source=runtime").json()
        simulator=client.get("/api/actions?source=simulator").json()
        assert simulated["agent_source"]=="simulator"
        assert observed["agent_source"]=="windows_monitor"
        assert simulated["action_id"] not in {item["action_id"] for item in runtime}
        assert observed["action_id"] in {item["action_id"] for item in runtime}
        assert simulated["action_id"] in {item["action_id"] for item in simulator}
        assert observed["action_id"] not in {item["action_id"] for item in simulator}

def test_development_origins_and_dashboard_routes():
    origins=["http://localhost:5173","http://localhost:5174","http://127.0.0.1:5173","http://127.0.0.1:5174"]
    with TestClient(app) as client:
        for origin in origins:
            response=client.options("/api/stats",headers={"Origin":origin,"Access-Control-Request-Method":"GET"})
            assert response.headers.get("access-control-allow-origin")==origin
        schema=client.get("/openapi.json").json()
        required={("/api/stats","get"),("/api/actions","get"),("/api/approvals","get"),("/api/tasks","get"),("/api/tasks","post"),("/api/policies","get"),("/api/audit","get"),("/api/demo/run","post"),("/api/runtime/mode","get"),("/api/runtime/mode","put"),("/api/approvals/{approval_id}/approve","post"),("/api/approvals/{approval_id}/block","post")}
        actual={(path,method) for path,methods in schema["paths"].items() for method in methods}
        assert required <= actual

def test_windows_monitor_source_is_stored_in_action_metadata():
    with TestClient(app) as client:
        task=client.post("/api/tasks",json={"name":"Windows observation test"}).json()
        response=client.post("/api/actions/check",json={"task_id":task["task_id"],"agent":"WINDOWS_MONITOR","agent_source":"windows_monitor","pid":None,"process_name":None,"process_path":None,"action_type":"WRITE","resource":"runtime_test/test_output.txt","metadata":{"source":"windows_monitor","process_attribution":"unavailable_from_directory_notification"}})
        assert response.status_code==200
        action=response.json()
        assert action["agent_source"]=="windows_monitor" and action["pid"] is None
        assert action["metadata"]["process_attribution"]=="unavailable_from_directory_notification"
        mode=client.put("/api/runtime/mode",json={"mode":"WINDOWS_MONITOR","details":{"pid":123}})
        assert mode.json()["mode"]=="WINDOWS_MONITOR"
        assert client.get("/api/runtime/mode").json()["details"]["pid"]==123
        client.put("/api/runtime/mode",json={"mode":"SIMULATOR","details":{}})

def test_windows_security_audit_source_is_stored_without_schema_changes():
    with TestClient(app) as client:
        task=client.post("/api/tasks",json={"name":"Windows audit observation"}).json()
        response=client.post("/api/actions/check",json={"task_id":task["task_id"],"agent":"WINDOWS_SECURITY_AUDIT","agent_source":"windows_security_audit","pid":12345,"process_name":"python.exe","process_path":"D:/Agent-Gate/.venv/Scripts/python.exe","action_type":"READ","resource":"runtime_test/dummy.txt","timestamp":"2026-09-26T10:20:30Z","metadata":{"source":"windows_security_audit","event_id":4663,"record_id":8123,"access_mask":"0x1","access_rights":["ReadData"],"evidence":"ReadData"}})
        assert response.status_code==200
        action=response.json()
        assert action["agent_source"]=="windows_security_audit"
        assert action["pid"]==12345 and action["metadata"]["record_id"]==8123
        mode=client.put("/api/runtime/mode",json={"mode":"WINDOWS_SECURITY_AUDIT","details":{"pid":12345}})
        assert mode.json()["mode"]=="WINDOWS_SECURITY_AUDIT"
        client.put("/api/runtime/mode",json={"mode":"SIMULATOR","details":{}})
