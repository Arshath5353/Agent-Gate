from abc import ABC, abstractmethod
class AgentAdapter(ABC):
    @abstractmethod
    def send_action(self, action: dict) -> dict: ...
class SimulatorAdapter(AgentAdapter):
    """Transport adapter only. The simulator never executes submitted commands."""
    def __init__(self, client): self.client = client
    def send_action(self, action: dict) -> dict:
        action.setdefault("agent_source", "simulator")
        return self.client.post("/api/actions/check", json=action).json()
