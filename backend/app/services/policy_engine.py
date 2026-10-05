import re
from pathlib import Path
from urllib.parse import urlparse
from app.config import WORKSPACE

PRIVATE_PATTERNS = ("id_rsa", "id_ed25519", "ssh\\", ".ssh/")
PERSONAL = ("passport", "personal", "medical", "tax-return")
SECRET_PATTERNS = (".env", ".key", ".pem", "credential", "password", "secret")
DANGEROUS = [r"\brm\s+-rf\b", r"\bsudo\b", r"chmod\s+777", r"curl\b.*\|\s*(?:bash|sh)\b", r"wget\b.*\|\s*(?:bash|sh)\b", r"\bmkfs(?:\.|\s)", r"\bdd\s+if="]
BLOCKED_HOSTS = {"malware.test", "evil.example", "exfil.example", "example-malware.com"}

def resolve_resource(resource: str, workspace: Path = WORKSPACE) -> tuple[Path | None, bool]:
    """Return normalized path and containment. Resolve symlinks, including existing parents."""
    root = workspace.resolve()
    raw = Path(resource).expanduser()
    # Reject traversal syntax itself, even when it happens to normalize back inside
    # the workspace (or points at a different file than the submitted prefix suggests).
    if ".." in raw.parts:
        return None, False
    candidate = raw if raw.is_absolute() else root / raw
    try:
        normalized = candidate.resolve(strict=False)
        return normalized, normalized == root or root in normalized.parents
    except (OSError, RuntimeError): return None, False

def is_path_allowed(path: str, workspace: Path = WORKSPACE) -> bool:
    return resolve_resource(path, workspace)[1]

def evaluate(action_type: str, resource: str, metadata: dict, workspace: Path = WORKSPACE):
    reasons: list[str] = []; score = 5; force = None
    kind = action_type.upper(); normalized = resource.replace("\\", "/").lower()
    if kind == "EXECUTE":
        if any(re.search(p, resource, re.I) for p in DANGEROUS):
            score = 100; force = "BLOCK"; reasons.append("Destructive or privilege escalation command")
        elif re.search(r"\b(npm|pnpm|yarn)\s+(test|run\s+test|lint|build)\b|\bpytest\b", resource, re.I):
            score = 5; reasons.append("Recognized safe development command")
        else:
            score = 45; reasons.append("Unrecognized command requires monitoring")
    elif kind == "NETWORK_CONNECT":
        supplied = str(metadata.get("host") or resource).lower().strip()
        parsed = urlparse(supplied if "://" in supplied else "//" + supplied)
        host = (parsed.hostname or supplied.split(":")[0]).strip("/ ")
        if host in BLOCKED_HOSTS or any(host.endswith("." + h) for h in BLOCKED_HOSTS):
            score = 100; force = "BLOCK"; reasons.append("Destination is on the blocked test-domain list")
        elif host in {"localhost", "127.0.0.1", "::1"}:
            score = 5; reasons.append("Local development destination")
        else:
            score = 75; reasons.append("External destination is not allowlisted")
    else:
        path, inside = resolve_resource(resource, workspace)
        base = (path.name.lower() if path else normalized.split("/")[-1])
        is_private = any(x in normalized for x in PRIVATE_PATTERNS)
        is_personal = any(x in base or x in normalized for x in PERSONAL) or (base.endswith(".pdf") and not inside)
        is_secret = base == ".env" or base.endswith((".key", ".pem")) or any(x in base for x in ("credential", "password", "secret"))
        if not inside:
            force = "BLOCK"
            reasons.append("Resource resolves outside the task workspace")
            score = max(score, 80)
        if is_private:
            score = 100; force = "BLOCK"; reasons.extend(["Private SSH key or SSH directory", "Credential material is never exposed by the simulator"])
        elif is_personal:
            score = 100; force = "BLOCK"; reasons.append("Personal document access is blocked")
        elif is_secret:
            score = max(score, 75); reasons.append("Sensitive configuration or credential-like file")
        elif inside:
            reasons.append("Resource is inside the controlled workspace")
        else:
            force = "BLOCK"; score = 90; reasons.append("Untrusted path outside the controlled workspace")
        scopes = metadata.get("allowed_scope")
        if inside and scopes and not any(normalized.startswith(str(s).lower()) for s in scopes):
            score = max(score, 70); reasons.append("Resource is outside the task's declared scope")
    if force: decision = force
    elif score >= 70: decision = "APPROVAL"
    elif score >= 35: decision = "MONITOR"
    else: decision = "ALLOW"
    level = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 35 else "LOW"
    return {"decision": decision, "risk_level": level, "risk_score": score, "reasons": list(dict.fromkeys(reasons))}
