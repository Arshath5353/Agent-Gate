from contextlib import asynccontextmanager
from datetime import datetime, timezone
import asyncio
import logging
import os
from uuid import uuid4
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Literal
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.config import CORS_ORIGINS, WORKSPACE
from app.database.database import Base, engine, get_db, SessionLocal
from app.models import Task, Action, Approval, AuditEvent, Policy
from app.services.event_bus import bus
from app.services.policy_engine import evaluate
from app.services.windows_monitor import WorkspaceRuntimeMonitor

logger = logging.getLogger("agentgate.api")
runtime_mode = "NOT_ACTIVE"
runtime_details: dict = {}

def uid(prefix): return f"{prefix}-{uuid4().hex[:10].upper()}"
def iso(dt): return dt.isoformat() if dt else None
def action_data(a):
    metadata=a.metadata_json or {}
    return {"action_id":a.id,"task_id":a.task_id,"agent":a.agent,"agent_source":metadata.get("agent_source","simulator"),"pid":a.pid,"process_name":metadata.get("process_name"),"process_path":metadata.get("process_path"),"observed_at":metadata.get("observed_at"),"action_type":a.action_type,"resource":a.resource,"metadata":metadata,"risk_level":a.risk_level,"risk_score":a.risk_score,"decision":a.decision,"reasons":a.reasons,"executed":a.executed,"result":a.result,"timestamp":iso(a.created_at),"approval_id":a.approval.id if a.approval else None}
def task_data(t): return {"task_id":t.id,"name":t.name,"description":t.description,"workspace":t.workspace,"allowed_scope":t.allowed_scope,"status":t.status,"created_at":iso(t.created_at)}
def approval_data(p):
    a=p.action
    return {"approval_id":p.id,"action_id":a.id,"status":p.status,"created_at":iso(p.created_at),"action":action_data(a)}
def audit(db, event, task_id=None, action_id=None, details=None):
    item=AuditEvent(id=uid("EVT"),event_type=event,task_id=task_id,action_id=action_id,details=details or {}); db.add(item); db.flush(); return item
async def emit(event, **data): await bus.publish({"type":event,"timestamp":datetime.now(timezone.utc).isoformat(),**data})

RUNTIME_TASK_NAME = "AgentGate controlled workspace monitor"

def _windows_monitor_enabled() -> bool:
    return os.name == "nt" and WORKSPACE.is_dir()

def _ensure_runtime_task() -> str:
    with SessionLocal() as db:
        task = db.scalar(select(Task).where(Task.name == RUNTIME_TASK_NAME))
        if task is None:
            task = Task(
                id=uid("TASK"),
                name=RUNTIME_TASK_NAME,
                description="Automatic observation of controlled_workspace file changes",
                workspace=str(WORKSPACE),
                # Policy/risk still evaluates every event; the empty prefix scope means
                # any path already contained by controlled_workspace is in this task's scope.
                allowed_scope=[""],
            )
            db.add(task)
            audit(db, "TASK_CREATED", task.id, details={"source": "windows_monitor", "workspace": str(WORKSPACE)})
        elif task.allowed_scope != [""]:
            task.allowed_scope = [""]
        task.status = "RUNNING"
        db.commit()
        return task.id

@asynccontextmanager
async def lifespan(app):
    global runtime_mode, runtime_details
    Base.metadata.create_all(engine)
    with next(get_db()) as db:
        if not db.scalar(select(Policy.id).limit(1)):
            rows=[("sensitive",".env","HIGH","APPROVAL","Sensitive environment configuration"),("sensitive","*.key / *.pem","CRITICAL","APPROVAL","Private key and certificate files"),("sensitive","id_rsa / id_ed25519","CRITICAL","BLOCK","Private SSH keys"),("personal","passport.pdf","CRITICAL","BLOCK","Personal identity documents"),("command","rm -rf","CRITICAL","BLOCK","Destructive deletion"),("command","sudo","HIGH","BLOCK","Privilege escalation"),("command","chmod 777","HIGH","BLOCK","Unsafe world-writable permissions"),("network","localhost","LOW","ALLOW","Trusted local development"),("network","unknown external","MEDIUM","APPROVAL","External destinations require review"),("network","blocked test domains","CRITICAL","BLOCK","Known unsafe simulation destinations")]
            db.add_all([Policy(id=uid("POL"),category=c,pattern=p,severity=s,outcome=o,description=d) for c,p,s,o,d in rows]); db.commit()
    monitor = None
    runtime_mode = "NOT_ACTIVE"
    runtime_details = {}
    try:
        if _windows_monitor_enabled():
            task_id = _ensure_runtime_task()
            loop = asyncio.get_running_loop()

            def forward_to_pipeline(payload: dict) -> None:
                try:
                    future = asyncio.run_coroutine_threadsafe(_submit_runtime_action(payload), loop)
                    future.result(timeout=15)
                except Exception:
                    logger.exception("Failed to forward Windows filesystem event into AgentGate pipeline")

            monitor = WorkspaceRuntimeMonitor(task_id, forward_to_pipeline)
            try:
                if monitor.start():
                    runtime_mode = "WINDOWS_MONITOR"
                    runtime_details = {"task_id": task_id, "workspace": str(WORKSPACE), "recursive": True}
                    logger.info("Windows workspace monitor started recursively for %s", WORKSPACE)
                else:
                    monitor = None
            except Exception:
                monitor = None
                logger.exception("Windows workspace monitor could not start for %s", WORKSPACE)
        else:
            logger.info("Windows workspace monitor inactive on this platform or workspace missing")
        app.state.windows_workspace_monitor = monitor
        yield
    finally:
        if monitor is not None:
            monitor.stop()
            logger.info("Windows workspace monitor stopped")
        app.state.windows_workspace_monitor = None
        runtime_mode = "NOT_ACTIVE"
        runtime_details = {}
app=FastAPI(title="AgentGate API",version="2.0.0",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=CORS_ORIGINS,allow_methods=["*"],allow_headers=["*"])

@app.middleware("http")
async def log_api_failures(request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("API request failed: %s %s", request.method, request.url.path)
        raise
    if request.url.path.startswith("/api/") and response.status_code >= 400:
        logger.warning("API request returned %s: %s %s", response.status_code, request.method, request.url.path)
    return response

class TaskIn(BaseModel): name:str=Field(min_length=1,max_length=160); description:str=Field(default="",max_length=4000); allowed_scope:list[str]=Field(default_factory=lambda:["src/","tests/","package.json"],max_length=32)
class ActionIn(BaseModel): task_id:str=Field(min_length=1,max_length=80); agent:str=Field(default="simulator",min_length=1,max_length=80); agent_source:Literal["simulator","windows_monitor","windows_security_audit"]="simulator"; pid:int|None=Field(default=None,ge=0); process_name:str|None=Field(default=None,max_length=260); process_path:str|None=Field(default=None,max_length=2000); timestamp:datetime|None=None; action_type:str=Field(min_length=1,max_length=32); resource:str=Field(min_length=1,max_length=2000); metadata:dict=Field(default_factory=dict,max_length=32)
class Resolution(BaseModel): note:str|None=Field(default=None,max_length=1000)
class RuntimeModeIn(BaseModel): mode:Literal["NOT_ACTIVE","SIMULATOR","WINDOWS_MONITOR","WINDOWS_SECURITY_AUDIT"]; details:dict=Field(default_factory=dict,max_length=32)

async def _process_action(body: ActionIn, db: Session):
    task=db.get(Task,body.task_id)
    if not task: raise HTTPException(404,"Task not found")
    kind=body.action_type.upper()
    if kind not in {"READ","WRITE","DELETE","EXECUTE","NETWORK_CONNECT"}: raise HTTPException(422,"Unsupported action_type")
    metadata=dict(body.metadata)
    if "allowed_scope" not in metadata: metadata["allowed_scope"]=task.allowed_scope
    metadata.update({"agent_source":body.agent_source,"process_name":body.process_name,"process_path":body.process_path,"observed_at":iso(body.timestamp)})
    verdict=evaluate(kind,body.resource,metadata)
    a=Action(id=uid("ACT"),task_id=task.id,agent=body.agent,pid=body.pid,action_type=kind,resource=body.resource,metadata_json=metadata,risk_level=verdict["risk_level"],risk_score=verdict["risk_score"],decision=verdict["decision"],reasons=verdict["reasons"])
    db.add(a); db.flush()
    if a.decision=="APPROVAL": db.add(Approval(id=uid("APR"),action_id=a.id,status="PENDING"))
    audit(db,"ACTION_EVALUATED",task.id,a.id,{"decision":a.decision,"risk":a.risk_level,"reasons":a.reasons,"agent_source":body.agent_source}); db.commit(); db.refresh(a)
    result=action_data(a); await emit("ACTION_DECISION",**result); return result

async def _submit_runtime_action(payload: dict):
    body = ActionIn.model_validate(payload)
    with SessionLocal() as db:
        return await _process_action(body, db)

@app.post("/api/tasks")
def create_task(body:TaskIn,db:Session=Depends(get_db)):
    t=Task(id=uid("TASK"),name=body.name.strip(),description=body.description,workspace=str(WORKSPACE),allowed_scope=body.allowed_scope); db.add(t); audit(db,"TASK_CREATED",t.id,details={"name":t.name}); db.commit(); return task_data(t)
@app.get("/api/tasks")
def tasks(db:Session=Depends(get_db)): return [task_data(t) for t in db.scalars(select(Task).order_by(Task.created_at.desc())).all()]
@app.get("/api/tasks/{task_id}")
def get_task(task_id:str,db:Session=Depends(get_db)):
    t=db.get(Task,task_id)
    if not t: raise HTTPException(404,"Task not found")
    return {**task_data(t),"actions":[action_data(a) for a in db.scalars(select(Action).where(Action.task_id==task_id).order_by(Action.created_at.desc())).all()]}
@app.post("/api/actions/check")
async def check_action(body:ActionIn,db:Session=Depends(get_db)):
    return await _process_action(body, db)
@app.get("/api/actions")
def actions(task_id:str|None=None,decision:str|None=None,source:Literal["all","runtime","simulator"]="all",db:Session=Depends(get_db)):
    q=select(Action).order_by(Action.created_at.desc())
    if task_id:q=q.where(Action.task_id==task_id)
    if decision:q=q.where(Action.decision==decision.upper())
    provenance=func.coalesce(func.json_extract(Action.metadata_json,"$.agent_source"),"simulator")
    if source=="runtime":q=q.where(provenance.in_(["windows_monitor","windows_security_audit"]))
    elif source=="simulator":q=q.where(provenance=="simulator")
    return [action_data(a) for a in db.scalars(q.limit(500)).all()]
@app.get("/api/actions/{action_id}")
def get_action(action_id:str,db:Session=Depends(get_db)):
    a=db.get(Action,action_id)
    if not a:raise HTTPException(404,"Action not found")
    return action_data(a)
@app.post("/api/actions/{action_id}/execute")
async def execute_action(action_id:str,db:Session=Depends(get_db)):
    a=db.get(Action,action_id)
    if not a:raise HTTPException(404,"Action not found")
    if a.decision=="BLOCK":raise HTTPException(403,"Blocked actions cannot be executed")
    if a.decision=="APPROVAL" and (not a.approval or a.approval.status!="APPROVED"):raise HTTPException(409,"Action requires approval")
    # Deliberately a simulated acknowledgement: no shell command or filesystem operation is run.
    a.executed=True; a.result="SIMULATED: action authorized; no operating-system operation was performed"; audit(db,"ACTION_SIMULATED",a.task_id,a.id,{"result":a.result}); db.commit(); db.refresh(a)
    data=action_data(a); await emit("ACTION_SIMULATED",**data); return data
@app.get("/api/approvals")
def approvals(db:Session=Depends(get_db)): return [approval_data(p) for p in db.scalars(select(Approval).where(Approval.status=="PENDING").order_by(Approval.created_at)).all()]
async def resolve_approval(approval_id,decision,db):
    p=db.get(Approval,approval_id)
    if not p:raise HTTPException(404,"Approval not found")
    if p.status!="PENDING":raise HTTPException(409,"Approval has already been resolved")
    p.status=decision; p.resolved_at=datetime.now(timezone.utc); p.action.decision="ALLOW" if decision=="APPROVED" else "BLOCK"
    if decision=="APPROVED":
        p.action.executed=True
        p.action.result="SIMULATED: approved once; no operating-system operation was performed"
    audit(db,f"APPROVAL_{decision}",p.action.task_id,p.action_id,{"approval_id":p.id}); db.commit(); db.refresh(p)
    data=approval_data(p); await emit("APPROVAL_RESOLVED",**data); return data
@app.post("/api/approvals/{approval_id}/approve")
async def approve(approval_id:str,body:Resolution,db:Session=Depends(get_db)):return await resolve_approval(approval_id,"APPROVED",db)
@app.post("/api/approvals/{approval_id}/block")
async def block(approval_id:str,body:Resolution,db:Session=Depends(get_db)):return await resolve_approval(approval_id,"REJECTED",db)
@app.get("/api/audit")
def audit_events(limit:int=Query(200,ge=1,le=1000),db:Session=Depends(get_db)):
    rows=db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)).all()
    return [{"event_id":e.id,"event_type":e.event_type,"task_id":e.task_id,"action_id":e.action_id,"details":e.details,"timestamp":iso(e.created_at)} for e in rows]
@app.get("/api/stats")
def stats(db:Session=Depends(get_db)):
    counts={d:int(db.scalar(select(func.count()).select_from(Action).where(Action.decision==d)) or 0) for d in ["ALLOW","MONITOR","APPROVAL","BLOCK"]}
    risk={r:int(db.scalar(select(func.count()).select_from(Action).where(Action.risk_level==r)) or 0) for r in ["LOW","MEDIUM","HIGH","CRITICAL"]}
    return {"active_sessions":int(db.scalar(select(func.count()).select_from(Task).where(Task.status=="RUNNING")) or 0),"total_actions":sum(counts.values()),"decisions":counts,"risk_distribution":risk,"pending_approvals":int(db.scalar(select(func.count()).select_from(Approval).where(Approval.status=="PENDING")) or 0)}
@app.get("/api/policies")
def policies(db:Session=Depends(get_db)):
    return [{"id":p.id,"category":p.category,"pattern":p.pattern,"severity":p.severity,"outcome":p.outcome,"description":p.description} for p in db.scalars(select(Policy).order_by(Policy.category,Policy.pattern)).all()]
@app.get("/api/runtime/mode")
def get_runtime_mode():
    global runtime_mode, runtime_details
    monitor = getattr(app.state, "windows_workspace_monitor", None)
    if runtime_mode == "WINDOWS_MONITOR" and (monitor is None or not monitor.is_running):
        runtime_mode = "NOT_ACTIVE"
        runtime_details = {}
    return {"mode":runtime_mode,"details":runtime_details}
@app.put("/api/runtime/mode")
async def set_runtime_mode(body:RuntimeModeIn):
    global runtime_mode, runtime_details
    if body.mode == "SIMULATOR":
        monitor = getattr(app.state, "windows_workspace_monitor", None)
        runtime_mode = "WINDOWS_MONITOR" if monitor is not None and monitor.is_running else "NOT_ACTIVE"
        runtime_details = runtime_details if runtime_mode == "WINDOWS_MONITOR" else {}
    else:
        runtime_mode=body.mode; runtime_details=body.details
    await emit("RUNTIME_MODE_CHANGED",mode=runtime_mode,details=runtime_details)
    return {"mode":runtime_mode,"details":runtime_details}
@app.post("/api/demo/run")
async def demo(db:Session=Depends(get_db)):
    task=Task(id=uid("TASK"),name="AgentGate Security Demo",description="Eight safe policy-evaluation scenarios",workspace=str(WORKSPACE),allowed_scope=["src/","tests/","package.json"]); db.add(task); audit(db,"TASK_CREATED",task.id,details={"name":task.name,"source":"demo"}); db.commit()
    scenarios=[("READ","src/login.js",{}),("READ","src/auth.js",{}),("READ",".env",{}),("READ","~/.ssh/id_rsa",{}),("READ","passport.pdf",{}),("EXECUTE","npm test",{}),("EXECUTE","rm -rf /",{}),("NETWORK_CONNECT","telemetry.unknown.example",{"host":"telemetry.unknown.example"})]
    out=[]
    for kind,res,meta in scenarios:
        verdict=evaluate(kind,res,{**meta,"allowed_scope":task.allowed_scope}); a=Action(id=uid("ACT"),task_id=task.id,agent="simulator",action_type=kind,resource=res,metadata_json=meta,risk_level=verdict["risk_level"],risk_score=verdict["risk_score"],decision=verdict["decision"],reasons=verdict["reasons"]); db.add(a); db.flush()
        if a.decision=="APPROVAL":db.add(Approval(id=uid("APR"),action_id=a.id,status="PENDING"))
        a.metadata_json={**meta,"agent_source":"simulator"}
        audit(db,"ACTION_EVALUATED",task.id,a.id,{"decision":a.decision,"risk":a.risk_level,"reasons":a.reasons,"source":"demo","agent_source":"simulator"}); db.commit(); db.refresh(a); result=action_data(a); out.append(result); await emit("ACTION_DECISION",**result)
    return {"task":task_data(task),"actions":out}
@app.websocket("/ws/events")
async def websocket_events(ws:WebSocket):
    await bus.connect(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: bus.disconnect(ws)
@app.get("/health")
def health():return {"status":"ok","workspace":str(WORKSPACE)}
