"""Narrow user-mode executor for AgentGate's controlled enforcement demo.

This module is deliberately not a general-purpose process or filesystem proxy.
Only named fixtures below ``controlled_workspace/enforcement_demo`` are writable
or deletable, and EXECUTE accepts one exact, shell-free command.
"""
from pathlib import Path
import subprocess
import sys

from app.config import WORKSPACE

DEMO_ROOT = (WORKSPACE / "enforcement_demo").resolve()
READABLE_FIXTURES = {"allowed_demo.py", "approval_demo.py", "protected_demo.txt", "delete_me.py"}
WRITABLE_FIXTURES = {"allowed_demo.py", "approval_demo.py"}
DELETABLE_FIXTURES = {"delete_me.py"}
MAX_WRITE_BYTES = 10_000


class BrokerExecutionError(ValueError):
    """The request is outside the broker's explicitly supported safe scope."""


def _fixture_path(resource: str, workspace: Path = WORKSPACE) -> tuple[Path, str]:
    raw = str(resource).strip().replace("\\", "/")
    if not raw or "\x00" in raw or ".." in Path(raw).parts or raw.startswith("~"):
        raise BrokerExecutionError("Invalid broker resource path")
    root = (workspace / "enforcement_demo").resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    try:
        resolved = candidate.resolve(strict=False)
        relative = resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BrokerExecutionError("Broker resources must stay inside enforcement_demo") from exc
    # The demo intentionally supports direct, named fixtures only, not subdirectories.
    if len(relative.parts) != 1:
        raise BrokerExecutionError("Only named enforcement demo fixtures are supported")
    return resolved, relative.name.casefold()


def execute_controlled_action(action_type: str, resource: str, metadata: dict | None = None,
                              workspace: Path = WORKSPACE) -> dict:
    """Execute a single allowlisted operation after the policy decision is ALLOW."""
    kind = str(action_type).upper()
    context = metadata or {}
    if kind in {"READ", "WRITE", "DELETE"}:
        path, name = _fixture_path(resource, workspace)
        if kind == "READ":
            if name not in READABLE_FIXTURES or not path.is_file():
                raise BrokerExecutionError("Resource is not an available readable demo fixture")
            data = path.read_bytes()
            if len(data) > MAX_WRITE_BYTES:
                raise BrokerExecutionError("Demo fixture exceeds the broker read limit")
            return {"operation": kind, "resource": str(path), "bytes": len(data), "content": data.decode("utf-8", errors="replace")}
        if kind == "WRITE":
            if name not in WRITABLE_FIXTURES:
                raise BrokerExecutionError("Writes are limited to the named writable demo fixtures")
            content = context.get("content")
            if not isinstance(content, str):
                raise BrokerExecutionError("WRITE requires string metadata.content")
            data = content.encode("utf-8")
            if len(data) > MAX_WRITE_BYTES:
                raise BrokerExecutionError("Write exceeds the broker limit")
            path.write_bytes(data)
            return {"operation": kind, "resource": str(path), "bytes": len(data)}
        if name not in DELETABLE_FIXTURES or not path.is_file():
            raise BrokerExecutionError("Deletes are limited to the existing delete_me.py fixture")
        path.unlink()
        return {"operation": kind, "resource": str(path), "deleted": True}

    if kind == "EXECUTE":
        if " ".join(str(resource).strip().split()).casefold() != "python --version":
            raise BrokerExecutionError("EXECUTE supports only the exact command 'python --version'")
        completed = subprocess.run(
            [sys.executable, "--version"], cwd=str((workspace / "enforcement_demo").resolve()),
            shell=False, capture_output=True, text=True, timeout=5, check=False,
        )
        if completed.returncode != 0:
            raise BrokerExecutionError("Allowlisted version command failed")
        return {"operation": kind, "resource": "python --version", "output": (completed.stdout or completed.stderr).strip()[:500]}

    if kind == "NETWORK_CONNECT":
        return {"operation": kind, "resource": str(resource), "simulated": True,
                "message": "Network operation simulated; no connection was opened"}

    raise BrokerExecutionError(f"Broker does not execute {kind or 'this'} operations")
