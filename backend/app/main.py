from contextlib import asynccontextmanager
from datetime import datetime, timezone
import asyncio
import ctypes
import hashlib
import logging
import os
import threading
from uuid import uuid4
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Literal
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.config import CORS_ORIGINS, WORKSPACE
from app.database.database import Base, engine, get_db, SessionLocal, migrate_policy_columns
from app.models import Task, Action, Approval, AuditEvent, Policy, BrokerExecution
from app.services.event_bus import bus
from app.services.policy_engine import evaluate
from app.services.policy_engine import NormalizedAction
from app.services.agent_adapter import AgentActionRequest, AgentAdapter
from app.services.resource_classifier import normalize_protected_pattern
from app.services.policy_catalogue import ensure_policy_catalog
from app.services.windows_monitor import WorkspaceRuntimeMonitor
from app.services.enforcement_broker import execute_controlled_action

logger = logging.getLogger("agentgate.api")
runtime_mode = "NOT_ACTIVE"
runtime_details: dict = {}


def _windows_monitor_health_status(monitor, lifecycle_status: str) -> str:
    """Report monitor health from lifecycle state and its live watcher thread."""
    if lifecycle_status == "STARTING":
        return "STARTING"
    if monitor is None:
        return "OFFLINE" if lifecycle_status in {"ACTIVE", "OFFLINE"} else "UNKNOWN"
    try:
        return "ACTIVE" if monitor.is_running else "OFFLINE"
    except Exception:
        logger.exception("Could not determine Windows workspace monitor health")
        return "UNKNOWN"

def uid(prefix): return f"{prefix}-{uuid4().hex[:10].upper()}"
def iso(dt): return dt.isoformat() if dt else None
def action_data(a):
    metadata=a.metadata_json or {}
    return {"action_id":a.id,"task_id":a.task_id,"agent":a.agent,"agent_source":metadata.get("agent_source","simulator"),"pid":a.pid,"process_name":metadata.get("process_name"),"process_path":metadata.get("process_path"),"observed_at":metadata.get("observed_at"),"action_type":a.action_type,"resource":a.resource,"metadata":metadata,"risk_level":a.risk_level,"risk_score":a.risk_score,"decision":a.decision,"reasons":a.reasons,"matched_policies":metadata.get("matched_policies",[]),"executed":a.executed,"result":a.result,"timestamp":iso(a.created_at),"approval_id":a.approval.id if a.approval else None}
def task_data(t): return {"task_id":t.id,"name":t.name,"description":t.description,"workspace":t.workspace,"allowed_scope":t.allowed_scope,"status":t.status,"created_at":iso(t.created_at)}
def approval_data(p):
    a=p.action
    return {"approval_id":p.id,"action_id":a.id,"status":p.status,"created_at":iso(p.created_at),"resolved_at":iso(p.resolved_at),"action":action_data(a)}
def audit(db, event, task_id=None, action_id=None, details=None):
    item=AuditEvent(id=uid("EVT"),event_type=event,task_id=task_id,action_id=action_id,details=details or {}); db.add(item); db.flush(); return item
async def emit(event, **data): await bus.publish({"type":event,"timestamp":datetime.now(timezone.utc).isoformat(),**data})

BROKER_APPROVAL_TIMEOUT_SECONDS = max(0.1, float(os.getenv("AGENTGATE_BROKER_APPROVAL_TIMEOUT_SECONDS", "120")))
BROKER_APPROVAL_POLL_SECONDS = 0.1

def execution_data(item: BrokerExecution, action: Action | None = None):
    return {
        "action_id": item.action_id,
        "approval_id": item.approval_id,
        "execution_id": item.id,
        "decision": action.decision if action else None,
        "execution_status": item.status,
        "resource": action.resource if action else None,
        "result": item.result_json,
        "error": item.error,
        "timestamp": iso(item.completed_at or item.created_at),
    }

RUNTIME_TASK_NAME = "AgentGate controlled workspace monitor"

_monitor_lease_lock = threading.Lock()
_active_monitor_workspaces: set[str] = set()


class _WorkspaceMonitorLease:
    """Own the cross-process Windows mutex for one workspace monitor."""

    def __init__(self, kernel32, handle, workspace_key: str):
        self._kernel32 = kernel32
        self._handle = handle
        self._workspace_key = workspace_key
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            if not self._kernel32.ReleaseMutex(self._handle):
                logger.warning("Could not release Windows workspace monitor mutex")
        finally:
            self._kernel32.CloseHandle(self._handle)
            with _monitor_lease_lock:
                _active_monitor_workspaces.discard(self._workspace_key)


def _acquire_workspace_monitor_lease(workspace) -> _WorkspaceMonitorLease | None:
    """Acquire exclusive process ownership before starting a workspace watcher.

    A named mutex prevents another AgentGate backend process from starting a
    second ReadDirectoryChangesW watcher over the same controlled workspace.
    """
    if os.name != "nt":
        return None

    workspace_key = hashlib.sha256(
        os.path.normcase(str(workspace.resolve())).encode("utf-8")
    ).hexdigest()[:24]
    with _monitor_lease_lock:
        if workspace_key in _active_monitor_workspaces:
            return None

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    kernel32.ReleaseMutex.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)

    mutex_name = f"Local\\AgentGateWorkspaceMonitor-{workspace_key}"
    handle = kernel32.CreateMutexW(None, False, mutex_name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    wait_result = kernel32.WaitForSingleObject(handle, 0)
    if wait_result == 0x00000102:  # WAIT_TIMEOUT: another backend owns the mutex.
        kernel32.CloseHandle(handle)
        return None
    if wait_result not in (0x00000000, 0x00000080):  # WAIT_OBJECT_0 / WAIT_ABANDONED.
        error = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise ctypes.WinError(error)

    with _monitor_lease_lock:
        if workspace_key in _active_monitor_workspaces:
            kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
            return None
        _active_monitor_workspaces.add(workspace_key)
    return _WorkspaceMonitorLease(kernel32, handle, workspace_key)

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
    migrate_policy_columns()
    with next(get_db()) as db:
        ensure_policy_catalog(db)
    monitor = None
    monitor_lease = None
    runtime_mode = "NOT_ACTIVE"
    runtime_details = {}
    app.state.windows_workspace_monitor = None
    app.state.windows_monitor_status = "UNKNOWN"
    try:
        if _windows_monitor_enabled():
            app.state.windows_monitor_status = "STARTING"
            try:
                monitor_lease = _acquire_workspace_monitor_lease(WORKSPACE)
            except Exception:
                app.state.windows_monitor_status = "OFFLINE"
                logger.exception("Could not acquire exclusive Windows workspace monitor ownership")
            else:
                if monitor_lease is None:
                    app.state.windows_monitor_status = "OFFLINE"
                    logger.warning("Windows workspace monitor is owned by another AgentGate backend: %s", WORKSPACE)
                else:
                    task_id = _ensure_runtime_task()
                    loop = asyncio.get_running_loop()

                    def forward_to_pipeline(payload: dict) -> None:
                        try:
                            future = asyncio.run_coroutine_threadsafe(_submit_runtime_action(payload), loop)
                            future.result(timeout=15)
                        except Exception:
                            logger.exception("Failed to forward Windows filesystem event into AgentGate pipeline")

                    monitor = WorkspaceRuntimeMonitor(task_id, forward_to_pipeline)
                    app.state.windows_workspace_monitor = monitor
                    try:
                        if monitor.start() and monitor.is_running:
                            runtime_mode = "WINDOWS_MONITOR"
                            runtime_details = {"task_id": task_id, "workspace": str(WORKSPACE), "recursive": True}
                            app.state.windows_monitor_status = "ACTIVE"
                            logger.info("Windows workspace monitor started recursively for %s", WORKSPACE)
                        else:
                            monitor = None
                            app.state.windows_workspace_monitor = None
                            app.state.windows_monitor_status = "OFFLINE"
                    except Exception:
                        monitor = None
                        app.state.windows_workspace_monitor = None
                        app.state.windows_monitor_status = "OFFLINE"
                        logger.exception("Windows workspace monitor could not start for %s", WORKSPACE)
        else:
            app.state.windows_monitor_status = "OFFLINE"
            logger.info("Windows workspace monitor inactive on this platform or workspace missing")
        app.state.windows_workspace_monitor = monitor
        yield
    finally:
        try:
            if monitor is not None:
                monitor.stop()
                logger.info("Windows workspace monitor stopped")
        finally:
            if monitor_lease is not None:
                monitor_lease.release()
            app.state.windows_monitor_status = "OFFLINE"
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
class ActionIn(BaseModel):
    task_id:str=Field(min_length=1,max_length=80)
    agent:str=Field(default="simulator",min_length=1,max_length=80)
    agent_source:Literal["simulator","windows_monitor","windows_security_audit","agent_api"]="simulator"
    pid:int|None=Field(default=None,ge=0)
    process_name:str|None=Field(default=None,max_length=260)
    process_path:str|None=Field(default=None,max_length=2000)
    timestamp:datetime|None=None
    action_type:str=Field(min_length=1,max_length=32)
    resource:str=Field(min_length=1,max_length=2000)
    metadata:dict=Field(default_factory=dict,max_length=32)

    @field_validator("agent", "resource")
    @classmethod
    def reject_blank_values(cls,value):
        if not value.strip():
            raise ValueError("value must not be blank")
        return value
class AgentIdentityIn(BaseModel):
    id:str|None=Field(default=None,min_length=1,max_length=80)
    name:str|None=Field(default=None,min_length=1,max_length=80)
    version:str|None=Field(default=None,max_length=80)
    @model_validator(mode="after")
    def require_identity(self):
        self.id=self.id.strip() if self.id else None
        self.name=self.name.strip() if self.name else None
        self.version=self.version.strip() if self.version else None
        if not any(value and value.strip() for value in (self.id,self.name)):
            raise ValueError("agent.id or agent.name must be a non-empty value")
        return self

class AgentActionPayload(BaseModel):
    type:str=Field(min_length=1,max_length=32)
    resource:str=Field(min_length=1,max_length=2000)
    metadata:dict=Field(default_factory=dict,max_length=32)
    timestamp:datetime|None=None
    @field_validator("type")
    @classmethod
    def normalize_action_type(cls,value):
        kind=value.strip().upper()
        if kind not in {"READ","WRITE","DELETE","EXECUTE","NETWORK_CONNECT","TOOL_CALL"}:
            raise ValueError("Unsupported action type")
        return kind
    @field_validator("resource")
    @classmethod
    def require_resource(cls,value):
        if not value.strip():
            raise ValueError("resource must be a non-empty value")
        return value

class AgentActionRequestIn(BaseModel):
    agent:AgentIdentityIn
    action:AgentActionPayload
    session_id:str|None=Field(default=None,max_length=128)
    task_id:str|None=Field(default=None,min_length=1,max_length=80)
    source:str|None=Field(default=None,min_length=1,max_length=80)
    @field_validator("session_id","source")
    @classmethod
    def non_blank_optional_identifier(cls,value):
        if value is not None and not value.strip():
            raise ValueError("value must not be blank")
        return value
class Resolution(BaseModel): note:str|None=Field(default=None,max_length=1000)
class RuntimeModeIn(BaseModel): mode:Literal["NOT_ACTIVE","SIMULATOR","WINDOWS_MONITOR","WINDOWS_SECURITY_AUDIT"]; details:dict=Field(default_factory=dict,max_length=32)
class ProtectedResourceIn(BaseModel):
    path:str=Field(min_length=1,max_length=2000)
    classification:Literal["WORKING","SENSITIVE","PRIVATE","CRITICAL","UNKNOWN"]
    decision:Literal["MONITOR","APPROVAL","BLOCK"]
    description:str=Field(default="",max_length=1000)
    enabled:bool=True

def protected_resource_data(policy:Policy):
    return {"id":policy.id,"path":policy.pattern,"classification":policy.resource_classification or "UNKNOWN","decision":policy.outcome,"enabled":policy.enabled is not False,"description":policy.description,"created_at":iso(policy.created_at),"updated_at":iso(policy.updated_at)}

def _normalize_protected_path(value:str) -> str:
    try:
        return normalize_protected_pattern(value, WORKSPACE)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

async def _process_action(body: ActionIn, db: Session):
    task=db.get(Task,body.task_id)
    if not task: raise HTTPException(404,"Task not found")
    kind=body.action_type.upper()
    if kind not in {"READ","WRITE","DELETE","EXECUTE","NETWORK_CONNECT","TOOL_CALL"}: raise HTTPException(422,"Unsupported action_type")
    metadata=dict(body.metadata)
    if "allowed_scope" not in metadata: metadata["allowed_scope"]=task.allowed_scope
    metadata.update({"agent_source":body.agent_source,"process_name":body.process_name,"process_path":body.process_path,"observed_at":iso(body.timestamp)})
    policies=db.scalars(select(Policy)).all()
    normalized_action=NormalizedAction.create(kind,body.resource,metadata)
    verdict=evaluate(normalized_action,policies=policies)
    metadata["matched_policies"]=verdict["matched_policies"]
    metadata["resource_classification"]=verdict["resource_classification"]
    metadata["protected_resource_matches"]=verdict["protected_resource_matches"]
    a=Action(id=uid("ACT"),task_id=task.id,agent=body.agent,pid=body.pid,action_type=kind,resource=body.resource,metadata_json=metadata,risk_level=verdict["risk_level"],risk_score=verdict["risk_score"],decision=verdict["decision"],reasons=verdict["reasons"])
    db.add(a); db.flush()
    approval=None
    if a.decision=="APPROVAL":
        approval=Approval(id=uid("APR"),action_id=a.id,status="PENDING")
        db.add(approval)
    audit(db,"ACTION_EVALUATED",task.id,a.id,{"decision":a.decision,"risk":a.risk_level,"reasons":a.reasons,"matched_policies":verdict["matched_policies"],"resource_classification":verdict["resource_classification"],"protected_resource_matches":verdict["protected_resource_matches"],"agent_source":body.agent_source})
    if approval:
        audit(db,"APPROVAL_REQUESTED",task.id,a.id,{"approval_id":approval.id,"status":"PENDING","agent":a.agent,"action_type":a.action_type,"resource":a.resource,"risk_level":a.risk_level,"risk_score":a.risk_score,"reasons":a.reasons,"matched_policies":verdict["matched_policies"],"resource_classification":verdict["resource_classification"],"protected_resource_matches":verdict["protected_resource_matches"]})
    db.commit(); db.refresh(a)
    result=action_data(a); await emit("ACTION_DECISION",**result)
    # Keep ACTION_DECISION first for existing WebSocket consumers; the additional
    # event lets approval-focused clients refresh immediately without changing the
    # established action event contract.
    if approval:
        await emit("APPROVAL_REQUESTED",**approval_data(approval))
    return result

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

@app.post("/api/broker/execute")
async def broker_execute(body:ActionIn, request:Request, db:Session=Depends(get_db)):
    """Evaluate and, only when authorized, perform one narrow demo operation.

    This endpoint gates only requests explicitly routed through this broker. It is
    not an interceptor for arbitrary agent processes or direct OS operations.
    """
    metadata = dict(body.metadata)
    metadata["broker_managed"] = True
    broker_body = body.model_copy(update={"metadata": metadata})
    evaluated = await _process_action(broker_body, db)
    action = db.get(Action, evaluated["action_id"])
    if action is None:
        raise HTTPException(500, "Evaluated action could not be reloaded")

    approval = action.approval
    status = "PENDING_APPROVAL" if action.decision == "APPROVAL" else "NOT_EXECUTED"
    execution = BrokerExecution(
        id=uid("EXE"), action_id=action.id, approval_id=approval.id if approval else None,
        status=status,
    )
    metadata = dict(action.metadata_json or {})
    metadata.update({"execution_id": execution.id, "execution_status": status})
    action.metadata_json = metadata
    db.add(execution)
    audit(db, "BROKER_ACTION_REQUESTED", action.task_id, action.id, {
        "action_id": action.id, "approval_id": execution.approval_id,
        "execution_id": execution.id, "decision": action.decision,
        "execution_status": status,
    })
    db.commit()

    def set_status(new_status: str, result: dict | None = None, error: str | None = None,
                   event: str | None = None, started: bool = False):
        execution.status = new_status
        execution.result_json = result
        execution.error = error
        if started:
            execution.started_at = datetime.now(timezone.utc)
        if new_status not in {"PENDING_APPROVAL", "RUNNING"}:
            execution.completed_at = datetime.now(timezone.utc)
        current_metadata = dict(action.metadata_json or {})
        current_metadata["execution_status"] = new_status
        current_metadata["execution_id"] = execution.id
        action.metadata_json = current_metadata
        db.commit()
        db.refresh(execution)
        db.refresh(action)
        details = {
            "action_id": action.id, "approval_id": execution.approval_id,
            "execution_id": execution.id, "decision": action.decision,
            "execution_status": new_status, "result": result, "error": error,
        }
        if event:
            audit(db, event, action.task_id, action.id, details)
            db.commit()
        return details

    # MONITOR records are observational decisions, not authorization to perform an
    # operating-system operation. Only explicit ALLOW or a resolved approval proceeds.
    if action.decision == "BLOCK":
        action.executed = False
        set_status("NOT_EXECUTED", error="Policy blocked this action", event="EXECUTION_DENIED")
    elif action.decision == "MONITOR":
        action.executed = False
        set_status("NOT_EXECUTED", error="MONITOR is not authorization for broker execution", event="EXECUTION_DENIED")
    elif action.decision == "APPROVAL":
        deadline = asyncio.get_running_loop().time() + BROKER_APPROVAL_TIMEOUT_SECONDS
        resolved_status = None
        try:
            while asyncio.get_running_loop().time() < deadline:
                if await request.is_disconnected():
                    with SessionLocal() as poll_db:
                        pending = poll_db.get(Approval, execution.approval_id)
                        if pending and pending.status == "PENDING":
                            pending.status = "CANCELLED"
                            pending.resolved_at = datetime.now(timezone.utc)
                            pending.action.decision = "BLOCK"
                            pending.action.executed = False
                            pending.action.result = "Broker request cancelled; no operation was performed"
                            audit(poll_db, "APPROVAL_CANCELLED", pending.action.task_id, pending.action_id,
                                  {"approval_id": pending.id, "execution_id": execution.id})
                            poll_db.commit()
                    resolved_status = "CANCELLED"
                    break
                with SessionLocal() as poll_db:
                    pending = poll_db.get(Approval, execution.approval_id)
                    resolved_status = pending.status if pending else "DENIED"
                if resolved_status != "PENDING":
                    break
                await asyncio.sleep(BROKER_APPROVAL_POLL_SECONDS)
            if resolved_status == "PENDING" or resolved_status is None:
                # Resolve only this still-pending approval; a concurrent human decision wins.
                with SessionLocal() as poll_db:
                    pending = poll_db.get(Approval, execution.approval_id)
                    if pending and pending.status == "PENDING":
                        pending.status = "EXPIRED"
                        pending.resolved_at = datetime.now(timezone.utc)
                        pending.action.decision = "BLOCK"
                        pending.action.executed = False
                        pending.action.result = "Approval expired; no operation was performed"
                        audit(poll_db, "APPROVAL_EXPIRED", pending.action.task_id, pending.action_id,
                              {"approval_id": pending.id, "execution_id": execution.id})
                        poll_db.commit()
                        resolved_status = "EXPIRED"
                    else:
                        resolved_status = pending.status if pending else "DENIED"
            if resolved_status == "APPROVED":
                db.expire(action)
                db.refresh(action)
            elif resolved_status == "EXPIRED":
                db.expire(action)
                db.refresh(action)
                set_status("EXPIRED", error="Approval expired; operation was not executed", event="EXECUTION_DENIED")
            else:
                db.expire(action)
                db.refresh(action)
                set_status("DENIED", error="Approval was denied or cancelled; operation was not executed", event="EXECUTION_DENIED")
        except asyncio.CancelledError:
            # If the request task is cancelled while waiting, invalidate the approval
            # before propagating cancellation. It cannot later release the operation.
            with SessionLocal() as poll_db:
                pending = poll_db.get(Approval, execution.approval_id)
                if pending and pending.status == "PENDING":
                    pending.status = "CANCELLED"
                    pending.resolved_at = datetime.now(timezone.utc)
                    pending.action.decision = "BLOCK"
                    pending.action.executed = False
                    audit(poll_db, "APPROVAL_CANCELLED", pending.action.task_id, pending.action_id,
                          {"approval_id": pending.id, "execution_id": execution.id})
                    poll_db.commit()
                interrupted = poll_db.get(BrokerExecution, execution.id)
                if interrupted:
                    interrupted.status = "DENIED"
                    interrupted.error = "Broker request was cancelled; operation was not executed"
                    interrupted.completed_at = datetime.now(timezone.utc)
                    interrupted_action = poll_db.get(Action, interrupted.action_id)
                    if interrupted_action:
                        interrupted_metadata = dict(interrupted_action.metadata_json or {})
                        interrupted_metadata["execution_status"] = "DENIED"
                        interrupted_action.metadata_json = interrupted_metadata
                        interrupted_action.executed = False
                    audit(poll_db, "EXECUTION_DENIED", interrupted.action.task_id,
                          interrupted.action_id, {"approval_id": execution.approval_id,
                          "execution_id": execution.id, "execution_status": "DENIED"})
                    poll_db.commit()
            raise

    if action.decision == "ALLOW" and execution.status not in {"DENIED", "EXPIRED"}:
        action.executed = False
        set_status("RUNNING", event="EXECUTION_STARTED", started=True)
        try:
            result = await asyncio.to_thread(
                execute_controlled_action, action.action_type, action.resource,
                {key: value for key, value in (action.metadata_json or {}).items() if key != "broker_managed"},
            )
            action.executed = True
            action.result = "BROKER EXECUTED: " + str(result.get("message") or result.get("output") or result.get("operation"))
            set_status("EXECUTED", result=result, event="EXECUTION_COMPLETED")
        except Exception as exc:
            action.executed = False
            action.result = "BROKER FAILED: operation was not completed"
            safe_error = str(exc) if isinstance(exc, ValueError) else "Controlled operation failed"
            set_status("FAILED", error=safe_error, event="EXECUTION_FAILED")

    result = execution_data(execution, action)
    await emit("ACTION_EXECUTION_UPDATED", action=action_data(action), execution=result)
    return {"action": action_data(action), "execution": result}

@app.get("/api/executions/{execution_id}")
def get_execution(execution_id: str, db:Session=Depends(get_db)):
    execution = db.get(BrokerExecution, execution_id)
    if not execution:
        raise HTTPException(404, "Execution not found")
    return execution_data(execution, execution.action)

def _agent_api_task(db:Session, agent_id:str, agent_name:str) -> Task:
    task_name=f"Agent API: {agent_id or agent_name}"[:160]
    task=db.scalar(select(Task).where(Task.name==task_name))
    if task is None:
        task=Task(id=uid("TASK"),name=task_name,description="Default scoped task for generic AgentGate integration requests",workspace=str(WORKSPACE),allowed_scope=["src/","tests/","package.json"])
        db.add(task)
        audit(db,"TASK_CREATED",task.id,details={"name":task.name,"source":"agent_api"})
        db.flush()
    return task

@app.post("/api/agent/actions/check")
async def check_agent_action(body:AgentActionRequestIn,db:Session=Depends(get_db)):
    agent_id=(body.agent.id or body.agent.name or "").strip()
    agent_name=(body.agent.name or body.agent.id or "").strip()
    normalized_request=AgentActionRequest(
        agent_id=agent_id,
        agent_name=agent_name,
        agent_version=body.agent.version.strip() if body.agent.version else None,
        session_id=body.session_id.strip() if body.session_id else None,
        integration_source=body.source.strip() if body.source else None,
        task_id=body.task_id,
        action_type=body.action.type,
        resource=body.action.resource,
        timestamp=body.action.timestamp,
        metadata=body.action.metadata,
    )
    normalized_action=AgentAdapter.normalize_request(normalized_request)
    task_id=body.task_id or _agent_api_task(db,agent_id,agent_name).id
    action_body=ActionIn(task_id=task_id,agent=agent_name,agent_source="agent_api",timestamp=body.action.timestamp,action_type=normalized_action.action_type,resource=normalized_action.resource,metadata=normalized_action.context)
    result=await _process_action(action_body,db)
    classification=result["metadata"]["resource_classification"]
    return {
        "decision":result["decision"],
        "risk":{"level":result["risk_level"],"score":result["risk_score"]},
        "resource":{"classification":classification["classification"],"details":classification},
        "reasons":result["reasons"],
        "matched_policies":result["matched_policies"],
        "protected_resource_matches":result["metadata"].get("protected_resource_matches",[]),
        "action_id":result["action_id"],
        "approval_id":result["approval_id"],
        "task_id":result["task_id"],
        "agent":{"id":agent_id,"name":agent_name,"version":normalized_request.agent_version},
        "session_id":normalized_request.session_id,
        "source":"agent_api",
        "integration_source":normalized_request.integration_source,
        "action":result,
    }

@app.get("/api/actions")
def actions(task_id:str|None=None,decision:str|None=None,source:Literal["all","runtime","simulator"]="all",db:Session=Depends(get_db)):
    q=select(Action).order_by(Action.created_at.desc())
    if task_id:q=q.where(Action.task_id==task_id)
    if decision:q=q.where(Action.decision==decision.upper())
    provenance=func.coalesce(func.json_extract(Action.metadata_json,"$.agent_source"),"simulator")
    if source=="runtime":q=q.where(provenance.in_(["windows_monitor","windows_security_audit","agent_api"]))
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
def _approval_audit_details(p:Approval, status:str, note:str|None=None):
    action=p.action
    details={
        "approval_id":p.id,
        "status":status,
        "decision":action.decision,
        "result":action.result,
        "agent":action.agent,
        "action_type":action.action_type,
        "resource":action.resource,
        "risk_level":action.risk_level,
        "risk_score":action.risk_score,
        "reasons":action.reasons or [],
        "matched_policies":(action.metadata_json or {}).get("matched_policies",[]),
        "resource_classification":(action.metadata_json or {}).get("resource_classification"),
        "protected_resource_matches":(action.metadata_json or {}).get("protected_resource_matches",[]),
    }
    if note:
        details["note"]=note
    return details

def _resolve_pending_approval(p:Approval, decision:str, note:str|None=None):
    """Resolve one pending request; approval authorizes this action only."""
    p.status=decision
    p.resolved_at=datetime.now(timezone.utc)
    action=p.action
    action.decision="ALLOW" if decision=="APPROVED" else "BLOCK"
    if decision=="APPROVED":
        if (action.metadata_json or {}).get("broker_managed"):
            # Broker-managed approval releases this one request to its waiting executor.
            action.executed=False
            action.result="APPROVED ONCE: waiting for the controlled broker executor"
        else:
            # Preserve existing simulator/API acknowledgement behavior.
            action.executed=True
            action.result="SIMULATED: approved once; no operating-system operation was performed"
    else:
        action.executed=False
        action.result="SIMULATED: request denied; no operating-system operation was performed"
    return _approval_audit_details(p,decision,note)

async def resolve_approval(approval_id,decision,db,note=None):
    p=db.get(Approval,approval_id)
    if not p:raise HTTPException(404,"Approval not found")
    if p.status!="PENDING":raise HTTPException(409,"Approval has already been resolved")
    details=_resolve_pending_approval(p,decision,note)
    audit(db,f"APPROVAL_{decision}",p.action.task_id,p.action_id,details)
    db.commit(); db.refresh(p)
    data=approval_data(p); await emit("APPROVAL_RESOLVED",**data); return data

async def resolve_pending_approvals(decision:str, db:Session, note:str|None=None):
    pending=db.scalars(select(Approval).where(Approval.status=="PENDING").order_by(Approval.created_at)).all()
    if not pending:
        return {"status":decision,"resolved_count":0,"approvals":[]}
    resolved=[]
    for p in pending:
        details=_resolve_pending_approval(p,decision,note)
        audit(db,f"APPROVAL_{decision}",p.action.task_id,p.action_id,details)
        resolved.append(p)
    db.commit()
    data=[]
    for p in resolved:
        db.refresh(p)
        item=approval_data(p)
        data.append(item)
        await emit("APPROVAL_RESOLVED",**item)
    return {"status":decision,"resolved_count":len(data),"approvals":data}
@app.post("/api/approvals/{approval_id}/approve")
async def approve(approval_id:str,body:Resolution,db:Session=Depends(get_db)):return await resolve_approval(approval_id,"APPROVED",db,body.note)
@app.post("/api/approvals/{approval_id}/deny")
async def deny(approval_id:str,body:Resolution,db:Session=Depends(get_db)):return await resolve_approval(approval_id,"DENIED",db,body.note)
@app.post("/api/approvals/{approval_id}/block")
async def block(approval_id:str,body:Resolution,db:Session=Depends(get_db)):return await resolve_approval(approval_id,"DENIED",db,body.note)
@app.post("/api/approvals/approve-pending")
async def approve_pending(body:Resolution,db:Session=Depends(get_db)):return await resolve_pending_approvals("APPROVED",db,body.note)
@app.post("/api/approvals/deny-pending")
async def deny_pending(body:Resolution,db:Session=Depends(get_db)):return await resolve_pending_approvals("DENIED",db,body.note)
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
    return [{"id":p.id,"policy_id":p.id,"name":p.name,"category":p.category,"action_type":p.action_type,"pattern":p.pattern,"resource_pattern":p.pattern,"classification":p.resource_classification,"severity":p.severity,"risk_level":p.risk_level or p.severity,"outcome":p.outcome,"decision":p.outcome,"description":p.description,"rationale":p.rationale,"reference_name":p.reference_name,"reference_url":p.reference_url,"version":p.version,"enabled":p.enabled,"created_at":iso(p.created_at),"updated_at":iso(p.updated_at)} for p in db.scalars(select(Policy).order_by(Policy.category,Policy.pattern)).all()]
@app.get("/api/protected-resources")
def protected_resources(db:Session=Depends(get_db)):
    rows=db.scalars(select(Policy).where(Policy.category=="protected_resource").order_by(Policy.created_at.desc(),Policy.id)).all()
    return [protected_resource_data(row) for row in rows]
@app.post("/api/protected-resources")
def create_protected_resource(body:ProtectedResourceIn,db:Session=Depends(get_db)):
    path=_normalize_protected_path(body.path)
    timestamp=datetime.now(timezone.utc)
    severity={"WORKING":"LOW","UNKNOWN":"LOW","SENSITIVE":"HIGH","PRIVATE":"HIGH","CRITICAL":"CRITICAL"}[body.classification]
    policy=Policy(id=uid("PRT"),category="protected_resource",pattern=path,severity=severity,outcome=body.decision,description=body.description.strip(),resource_classification=body.classification,enabled=body.enabled,created_at=timestamp,updated_at=timestamp)
    db.add(policy)
    audit(db,"PROTECTED_RESOURCE_CREATED",details={"protected_resource_id":policy.id,"path":path,"classification":body.classification,"decision":body.decision,"enabled":body.enabled})
    db.commit(); db.refresh(policy)
    return protected_resource_data(policy)
@app.put("/api/protected-resources/{resource_id}")
def update_protected_resource(resource_id:str,body:ProtectedResourceIn,db:Session=Depends(get_db)):
    policy=db.get(Policy,resource_id)
    if not policy or policy.category!="protected_resource": raise HTTPException(404,"Protected resource not found")
    path=_normalize_protected_path(body.path)
    policy.pattern=path
    policy.resource_classification=body.classification
    policy.outcome=body.decision
    policy.severity={"WORKING":"LOW","UNKNOWN":"LOW","SENSITIVE":"HIGH","PRIVATE":"HIGH","CRITICAL":"CRITICAL"}[body.classification]
    policy.description=body.description.strip()
    policy.enabled=body.enabled
    policy.updated_at=datetime.now(timezone.utc)
    audit(db,"PROTECTED_RESOURCE_UPDATED",details={"protected_resource_id":policy.id,"path":path,"classification":body.classification,"decision":body.decision,"enabled":body.enabled})
    db.commit(); db.refresh(policy)
    return protected_resource_data(policy)
@app.delete("/api/protected-resources/{resource_id}")
def delete_protected_resource(resource_id:str,db:Session=Depends(get_db)):
    policy=db.get(Policy,resource_id)
    if not policy or policy.category!="protected_resource": raise HTTPException(404,"Protected resource not found")
    details={"protected_resource_id":policy.id,"path":policy.pattern}
    db.delete(policy)
    audit(db,"PROTECTED_RESOURCE_DELETED",details=details)
    db.commit()
    return {"deleted":True,"id":resource_id}
@app.get("/api/runtime/mode")
def get_runtime_mode():
    global runtime_mode, runtime_details
    monitor = getattr(app.state, "windows_workspace_monitor", None)
    monitor_status = _windows_monitor_health_status(
        monitor, getattr(app.state, "windows_monitor_status", "UNKNOWN")
    )
    if runtime_mode == "WINDOWS_MONITOR" and monitor_status == "OFFLINE":
        runtime_mode = "NOT_ACTIVE"
        runtime_details = {}
    return {"mode":runtime_mode,"details":runtime_details,"monitor_status":monitor_status}
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
    policies=db.scalars(select(Policy)).all()
    for kind,res,meta in scenarios:
        verdict=evaluate(kind,res,{**meta,"allowed_scope":task.allowed_scope},policies=policies); meta={**meta,"matched_policies":verdict["matched_policies"],"resource_classification":verdict["resource_classification"],"protected_resource_matches":verdict["protected_resource_matches"]}; a=Action(id=uid("ACT"),task_id=task.id,agent="simulator",action_type=kind,resource=res,metadata_json=meta,risk_level=verdict["risk_level"],risk_score=verdict["risk_score"],decision=verdict["decision"],reasons=verdict["reasons"]); db.add(a); db.flush()
        if a.decision=="APPROVAL":db.add(Approval(id=uid("APR"),action_id=a.id,status="PENDING"))
        a.metadata_json={**meta,"agent_source":"simulator"}
        audit(db,"ACTION_EVALUATED",task.id,a.id,{"decision":a.decision,"risk":a.risk_level,"reasons":a.reasons,"matched_policies":verdict["matched_policies"],"resource_classification":verdict["resource_classification"],"protected_resource_matches":verdict["protected_resource_matches"],"source":"demo","agent_source":"simulator"}); db.commit(); db.refresh(a); result=action_data(a); out.append(result); await emit("ACTION_DECISION",**result)
    return {"task":task_data(task),"actions":out}
@app.websocket("/ws/events")
async def websocket_events(ws:WebSocket):
    await bus.connect(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: bus.disconnect(ws)
@app.get("/health")
def health():return {"status":"ok","workspace":str(WORKSPACE)}
