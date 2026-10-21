"""Lightweight boundary between agent-specific actions and AgentGate actions."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from app.services.policy_engine import NormalizedAction


@dataclass(frozen=True)
class AgentActionRequest:
    """Agent identity and action context alongside the shared normalized action."""

    agent_id: str
    agent_name: str
    action_type: str
    resource: str
    agent_version: str | None = None
    session_id: str | None = None
    integration_source: str | None = None
    task_id: str | None = None
    timestamp: datetime | None = None
    metadata: dict = field(default_factory=dict)

    def to_normalized_action(self) -> NormalizedAction:
        context = dict(self.metadata)
        for reserved in (
            "agent_id", "agent_name", "agent_version", "session_id", "integration_source",
            "task_id", "observed_at", "allowed_scope", "agent_source", "process_name",
            "process_path", "resource_classification", "matched_policies",
            "protected_resource_matches",
        ):
            context.pop(reserved, None)
        # The target comes from the normalized resource field; caller metadata must
        # not spoof a different network host during policy evaluation.
        if self.action_type.upper() == "NETWORK_CONNECT":
            context.pop("host", None)
        context.update({"agent_id": self.agent_id, "agent_name": self.agent_name})
        if self.agent_version:
            context["agent_version"] = self.agent_version
        if self.session_id:
            context["session_id"] = self.session_id
        if self.integration_source:
            context["integration_source"] = self.integration_source
        if self.task_id:
            context["task_id"] = self.task_id
        if self.timestamp:
            context["observed_at"] = self.timestamp.isoformat()
        return NormalizedAction.create(self.action_type, self.resource, context)


class AgentAdapter(ABC):
    """Adapter boundary; vendor adapters translate into AgentActionRequest."""

    def normalize(self, request: AgentActionRequest) -> NormalizedAction:
        return request.to_normalized_action()

    @staticmethod
    def normalize_request(request: AgentActionRequest) -> NormalizedAction:
        """Default vendor-neutral translation used by the generic integration API."""
        return request.to_normalized_action()

    @abstractmethod
    def send_action(self, action: dict) -> dict: ...


class SimulatorAdapter(AgentAdapter):
    """Transport adapter only. The simulator never executes submitted commands."""
    def __init__(self, client): self.client = client
    def send_action(self, action: dict) -> dict:
        action.setdefault("agent_source", "simulator")
        return self.client.post("/api/actions/check", json=action).json()
