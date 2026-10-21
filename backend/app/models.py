from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base
def now(): return datetime.now(timezone.utc)
class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    workspace: Mapped[str] = mapped_column(String)
    allowed_scope: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String, default="RUNNING")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    actions: Mapped[list["Action"]] = relationship(back_populates="task")
class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id"), index=True)
    agent: Mapped[str] = mapped_column(String(80))
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action_type: Mapped[str] = mapped_column(String(32))
    resource: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(16), index=True)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    executed: Mapped[bool] = mapped_column(default=False)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    task: Mapped[Task] = relationship(back_populates="actions")
    approval: Mapped["Approval | None"] = relationship(back_populates="action", uselist=False)
class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.id"), unique=True)
    status: Mapped[str] = mapped_column(String, default="PENDING", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    action: Mapped[Action] = relationship(back_populates="approval")

class BrokerExecution(Base):
    """One-shot execution attempt associated with exactly one evaluated action."""
    __tablename__ = "broker_executions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("actions.id"), unique=True, index=True)
    approval_id: Mapped[str | None] = mapped_column(ForeignKey("approvals.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(24), index=True)
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    action: Mapped[Action] = relationship()
    approval: Mapped[Approval | None] = relationship()
class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    action_id: Mapped[str | None] = mapped_column(ForeignKey("actions.id"), nullable=True, index=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    category: Mapped[str] = mapped_column(String)
    pattern: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    outcome: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    resource_classification: Mapped[str | None] = mapped_column(String(16), nullable=True)
    name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    action_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reference_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    enabled: Mapped[bool | None] = mapped_column(default=True, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=now, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=now, nullable=True)
Index("ix_actions_task_created", Action.task_id, Action.created_at)
