"""Agent-independent action normalization and deterministic policy evaluation."""
from dataclasses import dataclass
from fnmatch import fnmatch
import re
from pathlib import Path
from urllib.parse import urlparse

from app.config import WORKSPACE
from app.services.resource_classifier import ClassificationResult, classify_resource, protected_resource_matches

ACTION_TYPES = {"READ", "WRITE", "DELETE", "EXECUTE", "NETWORK_CONNECT", "TOOL_CALL"}
PRIVATE_PATTERNS = ("id_rsa", "id_ed25519", "ssh\\", ".ssh/")
PERSONAL = ("passport", "personal", "medical", "tax-return")
DANGEROUS = [r"\brm\s+-rf\b", r"\bsudo\b", r"chmod\s+777", r"curl\b.*\|\s*(?:bash|sh)\b", r"wget\b.*\|\s*(?:bash|sh)\b", r"\bmkfs(?:\.|\s)", r"\bdd\s+if="]
BLOCKED_HOSTS = {"malware.test", "evil.example", "exfil.example", "example-malware.com"}
_SCORE_BY_SEVERITY = {"LOW": 5, "MEDIUM": 45, "HIGH": 75, "CRITICAL": 100}


@dataclass(frozen=True)
class NormalizedAction:
    """Common action shape shared by integrations, independent of agent identity."""

    action_type: str
    resource: str
    context: dict

    @classmethod
    def create(cls, action_type: str, resource: str, context: dict | None = None):
        kind = action_type.upper()
        if kind not in ACTION_TYPES:
            raise ValueError(f"Unsupported action type: {action_type}")
        return cls(kind, resource, dict(context or {}))


def resolve_resource(resource: str, workspace: Path = WORKSPACE) -> tuple[Path | None, bool]:
    """Return normalized path and containment. Resolve symlinks, including existing parents."""
    root = workspace.resolve()
    raw = Path(resource).expanduser()
    # Reject traversal syntax itself, even when it happens to normalize back inside.
    if ".." in raw.parts:
        return None, False
    candidate = raw if raw.is_absolute() else root / raw
    try:
        normalized = candidate.resolve(strict=False)
        return normalized, normalized == root or root in normalized.parents
    except (OSError, RuntimeError):
        return None, False


def is_path_allowed(path: str, workspace: Path = WORKSPACE) -> bool:
    return resolve_resource(path, workspace)[1]


def _resource_in_scope(resource: str, scopes, workspace: Path, resolved_path: Path | None = None) -> bool:
    """Match declared task scopes as case-insensitive paths or supported globs."""
    if not scopes:
        return True
    target = resource.replace("\\", "/").strip().casefold()
    if resolved_path is not None:
        try:
            target = resolved_path.relative_to(workspace.resolve()).as_posix().casefold()
        except ValueError:
            return False
    while target.startswith("./"):
        target = target[2:]
    target = target.lstrip("/")
    for raw_scope in scopes:
        scope = str(raw_scope).replace("\\", "/").strip().casefold()
        while scope.startswith("./"):
            scope = scope[2:]
        if scope in {"", "."}:
            return True
        scope = scope.lstrip("/")
        if any(char in scope for char in "*?["):
            if fnmatch(target, scope):
                return True
        else:
            scope = scope.rstrip("/")
            if target == scope or target.startswith(scope + "/"):
                return True
    return False


def _policy_value(policy, name, default=None):
    if isinstance(policy, dict):
        return policy.get(name, default)
    return getattr(policy, name, default)


def _policy_matches(policy, action: NormalizedAction, host: str | None, inside: bool | None,
                    workspace: Path = WORKSPACE, resolved_path: Path | None = None) -> bool:
    category = str(_policy_value(policy, "category", "")).lower()
    pattern = str(_policy_value(policy, "pattern", "")).strip().lower()
    if not pattern:
        return False
    kind = action.action_type
    target = action.resource.replace("\\", "/").lower()
    configured_types = str(_policy_value(policy, "action_type", "") or "").upper().replace(" ", "").split(",")
    has_configured_types = bool(configured_types and configured_types != [""])
    if has_configured_types and kind not in configured_types:
        return False

    context = action.context
    marker = pattern[1:] if pattern.startswith("@") else None
    if marker:
        flags = {str(value).lower() for value in context.get("security_indicators", [])}
        flags.update(str(key).lower() for key, value in context.items() if value is True)
        if marker == "ssh_private_key":
            return any(token in target for token in PRIVATE_PATTERNS)
        if marker == "credential_resource":
            return any(token in target for token in ("credential", "password", "secret", ".env"))
        if marker == "outside_workspace":
            return inside is False
        if marker == "path_traversal":
            return ".." in Path(action.resource.replace("\\", "/")).parts
        if marker == "system_path":
            normalized_path = target.lower()
            return normalized_path.startswith(("/etc/", "/root/", "/usr/", "/var/", "c:/windows/", "c:/program files/"))
        if marker == "unknown_resource":
            classification = context.get("resource_classification") or {}
            classification = classification.get("classification") if isinstance(classification, dict) else classification
            return classification == "UNKNOWN"
        if marker == "protected_resource":
            return bool(context.get("protected_resource_matches"))
        if marker == "out_of_task_scope":
            scopes = context.get("allowed_scope") or []
            return bool(scopes and inside is True and not _resource_in_scope(action.resource, scopes, workspace, resolved_path))
        if marker == "dangerous_command":
            return kind == "EXECUTE" and any(re.search(expr, action.resource, re.I) for expr in DANGEROUS)
        if marker == "download_execute":
            return kind == "EXECUTE" and bool(re.search(r"(?:curl|wget)\b.*\|\s*(?:bash|sh)\b", action.resource, re.I))
        if marker == "obfuscated_command":
            return kind == "EXECUTE" and ("obfuscated_command" in flags or bool(context.get("command_obfuscated")))
        if marker == "unknown_command":
            safe = re.search(r"\b(npm|pnpm|yarn)\s+(test|run\s+test|lint|build)\b|\bpytest\b", action.resource, re.I)
            return kind == "EXECUTE" and not safe and not any(re.search(expr, action.resource, re.I) for expr in DANGEROUS)
        if marker == "blocked_host":
            return bool(host) and (host in BLOCKED_HOSTS or any(host.endswith("." + blocked) for blocked in BLOCKED_HOSTS))
        if marker == "unknown_network":
            return kind == "NETWORK_CONNECT" and bool(host) and host not in {"localhost", "127.0.0.1", "::1"} and not (host in BLOCKED_HOSTS or any(host.endswith("." + blocked) for blocked in BLOCKED_HOSTS))
        data_class = str(context.get("data_classification", "")).upper()
        if marker == "sensitive_egress":
            return kind in {"NETWORK_CONNECT", "TOOL_CALL"} and (data_class in {"SENSITIVE", "PRIVATE", "CRITICAL"} or context.get("contains_sensitive_data") is True)
        if marker == "sensitive_data":
            classification = context.get("resource_classification") or {}
            classification = classification.get("classification") if isinstance(classification, dict) else classification
            return classification in {"SENSITIVE", "PRIVATE", "CRITICAL"} or data_class in {"SENSITIVE", "PRIVATE", "CRITICAL"} or context.get("contains_sensitive_data") is True
        if marker == "personal_data":
            return data_class == "PERSONAL" or context.get("contains_personal_data") is True
        if marker == "unapproved_upload":
            return context.get("upload") is True and context.get("upload_approved") is not True
        if marker == "metadata_endpoint":
            return kind == "NETWORK_CONNECT" and bool(host) and host.lower() in {"169.254.169.254", "metadata.google.internal", "metadata.azure.internal"}
        if marker == "unknown_tool":
            return kind == "TOOL_CALL" and context.get("tool_known") is not True
        if marker == "destructive_tool":
            name = str(context.get("tool") or action.resource).lower()
            return kind == "TOOL_CALL" and ("destructive_tool" in flags or any(term in name for term in ("delete", "drop", "destroy", "purge", "remove")))
        if marker == "privileged_tool":
            return kind == "TOOL_CALL" and ("privileged_tool" in flags or context.get("privileged") is True)
        if marker == "high_impact_tool":
            return kind == "TOOL_CALL" and ("high_impact" in flags or context.get("high_impact") is True)
        if marker == "irreversible_tool":
            return kind == "TOOL_CALL" and ("irreversible" in flags or context.get("irreversible") is True)
        if marker == "excessive_permissions":
            return kind == "TOOL_CALL" and ("excessive_permissions" in flags or context.get("excessive_permissions") is True)
        if marker == "high_impact":
            return "high_impact" in flags or context.get("high_impact") is True
        if marker == "irreversible":
            return "irreversible" in flags or context.get("irreversible") is True
        if marker == "untrusted_content_escalation":
            return context.get("untrusted_content") is True and context.get("requests_sensitive_access") is True
        if marker == "tool_output_escalation":
            return context.get("untrusted_tool_output") is True and context.get("requests_privilege_escalation") is True
        if marker == "untrusted_sensitive_access":
            return context.get("untrusted_content") is True and context.get("requests_sensitive_access") is True
        if marker == "untrusted_privilege_escalation":
            return context.get("untrusted_content") is True and context.get("requests_privilege_escalation") is True
        return marker in flags

    if category == "command" and kind == "EXECUTE":
        return pattern in target
    if category == "sensitive" and kind in {"READ", "WRITE", "DELETE", "TOOL_CALL"}:
        if pattern == "*.key / *.pem":
            return target.endswith((".key", ".pem"))
        if pattern == "id_rsa / id_ed25519":
            return any(key in target for key in ("id_rsa", "id_ed25519"))
        return pattern in target
    if category == "personal" and kind in {"READ", "WRITE", "DELETE", "TOOL_CALL"}:
        return any(part.strip() in target for part in pattern.split("/"))
    if category == "network" and kind == "NETWORK_CONNECT":
        if pattern == "blocked test domains":
            return bool(host) and (host in BLOCKED_HOSTS or any(host.endswith("." + blocked) for blocked in BLOCKED_HOSTS))
        if pattern == "localhost":
            return host in {"localhost", "127.0.0.1", "::1"}
        if pattern == "unknown external":
            return bool(host) and host not in {"localhost", "127.0.0.1", "::1"} and not (
                host in BLOCKED_HOSTS or any(host.endswith("." + blocked) for blocked in BLOCKED_HOSTS)
            )
        return pattern in (host or target)

    # Custom persisted policies can match resource globs in their category, or in "any".
    if category not in {"", "any", kind.lower()} and not has_configured_types:
        return False
    return fnmatch(target, pattern) if any(char in pattern for char in "*?[") else pattern in target


def evaluate(action_type: str | NormalizedAction, resource: str | None = None, metadata: dict | None = None,
             workspace: Path = WORKSPACE, policies=None):
    """Evaluate normalized actions with immutable safeguards plus persisted policy rules.

    Returns a dictionary to preserve the existing API/service contract. ``policies`` may
    contain SQLAlchemy Policy rows or plain mappings; direct callers may omit it.
    """
    if isinstance(action_type, NormalizedAction):
        action = action_type
    else:
        action = NormalizedAction.create(action_type, resource or "", metadata)
    context = action.context
    kind, resource = action.action_type, action.resource
    reasons: list[str] = []
    score = 5
    force = None
    matched = []
    normalized = resource.replace("\\", "/").lower()
    host = None
    inside = None
    policy_rows = list(policies or ())
    file_resource_action = kind in {"READ", "WRITE", "DELETE"}
    protected_matches = protected_resource_matches(resource, policy_rows, workspace) if file_resource_action else []
    classification = (
        classify_resource(resource, workspace=workspace, policies=policy_rows)
        if file_resource_action
        else ClassificationResult("UNKNOWN", "LOW", ("Resource classification is not applicable to this action type",), ({"type": "non_file_action", "value": kind},))
    )
    classification_data = classification.to_dict()
    context["resource_classification"] = classification_data

    if kind == "EXECUTE":
        if any(re.search(pattern, resource, re.I) for pattern in DANGEROUS):
            score = 100; force = "BLOCK"; reasons.append("Destructive or privilege escalation command")
        elif re.search(r"\b(npm|pnpm|yarn)\s+(test|run\s+test|lint|build)\b|\bpytest\b", resource, re.I):
            score = 5; reasons.append("Recognized safe development command")
        else:
            score = 45; reasons.append("Unrecognized command requires monitoring")
    elif kind == "NETWORK_CONNECT":
        supplied = str(context.get("host") or resource).lower().strip()
        parsed = urlparse(supplied if "://" in supplied else "//" + supplied)
        host = (parsed.hostname or supplied.split(":")[0]).strip("/ ")
        if host in BLOCKED_HOSTS or any(host.endswith("." + blocked) for blocked in BLOCKED_HOSTS):
            score = 100; force = "BLOCK"; reasons.append("Destination is on the blocked test-domain list")
        elif host in {"localhost", "127.0.0.1", "::1"}:
            score = 5; reasons.append("Local development destination")
        else:
            score = 75; reasons.append("External destination is not allowlisted")
    elif kind in {"READ", "WRITE", "DELETE"}:
        path, inside = resolve_resource(resource, workspace)
        base = (path.name.lower() if path else normalized.split("/")[-1])
        is_private = any(token in normalized for token in PRIVATE_PATTERNS)
        is_personal = any(token in base or token in normalized for token in PERSONAL) or (base.endswith(".pdf") and not inside)
        is_secret = base == ".env" or base.endswith((".key", ".pem")) or any(token in base for token in ("credential", "password", "secret"))
        if not inside:
            force = "BLOCK"; reasons.append("Resource resolves outside the task workspace"); score = max(score, 80)
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
        scopes = context.get("allowed_scope")
        if inside and scopes and not _resource_in_scope(resource, scopes, workspace, path):
            score = max(score, 70); reasons.append("Resource is outside the task's declared scope")
    else:  # TOOL_CALL: generic tool request is observable and can be governed by policies.
        score = 45; reasons.append("Tool call requires monitoring")

    hard_safeguard_force = force

    if kind in {"READ", "WRITE", "DELETE", "TOOL_CALL"}:
        if classification.classification in {"SENSITIVE", "PRIVATE", "CRITICAL"}:
            score = max(score, 75)
            reasons.append(f"Resource classified {classification.classification}")
            reasons.extend(classification.reasons)
        elif classification.classification == "UNKNOWN":
            # Unknown is neither trusted nor categorically blocked: require review.
            score = max(score, 35)
            reasons.append("Unknown resource requires monitoring")
            reasons.extend(classification.reasons)

    context["protected_resource_matches"] = protected_matches
    for policy in policy_rows:
        if _policy_value(policy, "enabled", True) is False:
            continue
        if not _policy_matches(policy, action, host, inside, workspace, path if file_resource_action else None):
            continue
        outcome = str(_policy_value(policy, "outcome", "MONITOR")).upper()
        severity = str(_policy_value(policy, "severity", "MEDIUM")).upper()
        rule_score = _SCORE_BY_SEVERITY.get(severity, 45)
        info = {
            "id": _policy_value(policy, "id"),
            "policy_id": _policy_value(policy, "id"),
            "name": _policy_value(policy, "name"),
            "category": _policy_value(policy, "category"),
            "action_type": _policy_value(policy, "action_type"),
            "pattern": _policy_value(policy, "pattern"),
            "resource_pattern": _policy_value(policy, "pattern"),
            "classification": _policy_value(policy, "resource_classification"),
            "severity": severity,
            "risk_level": _policy_value(policy, "risk_level") or severity,
            "outcome": outcome,
            "decision": outcome,
            "description": _policy_value(policy, "description", ""),
            "rationale": _policy_value(policy, "rationale"),
            "reference_name": _policy_value(policy, "reference_name"),
            "reference_url": _policy_value(policy, "reference_url"),
            "version": _policy_value(policy, "version"),
        }
        matched.append(info)
        if info["description"]:
            reasons.append(info["description"])
        if outcome == "BLOCK":
            force = "BLOCK"; score = max(score, rule_score)
        elif outcome == "APPROVAL":
            score = max(score, 70, rule_score)
        elif outcome == "MONITOR":
            score = max(score, 35, rule_score)
        elif outcome == "ALLOW" and score < 35:
            score = max(score, rule_score)

    if hard_safeguard_force:
        decision = hard_safeguard_force
    elif protected_matches:
        selected = protected_matches[0]
        decision = selected["decision"]
        reasons.append(selected["reason"])
        if selected["description"]:
            reasons.append(selected["description"])
        if decision == "BLOCK":
            score = max(score, 100)
        elif decision == "APPROVAL":
            score = max(score, 75)
        elif decision == "MONITOR":
            score = max(score, 45)
    elif force:
        decision = force
    elif score >= 70:
        decision = "APPROVAL"
    elif score >= 35:
        decision = "MONITOR"
    else:
        decision = "ALLOW"
    level = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 35 else "LOW"
    return {"decision": decision, "risk_level": level, "risk_score": score,
            "reasons": list(dict.fromkeys(reasons)), "matched_policies": matched,
            "resource_classification": classification_data,
            "protected_resource_matches": protected_matches}
