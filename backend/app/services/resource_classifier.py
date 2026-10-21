"""Deterministic resource classification for normalized agent actions."""
from dataclasses import asdict, dataclass
from fnmatch import fnmatch
import ntpath
from pathlib import Path

from app.config import WORKSPACE

CLASSIFICATIONS = {"WORKING", "SENSITIVE", "PRIVATE", "CRITICAL", "UNKNOWN"}
_CLASS_RANK = {"UNKNOWN": 0, "WORKING": 1, "SENSITIVE": 2, "PRIVATE": 3, "CRITICAL": 4}
_SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css", ".scss", ".java",
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb",
    ".swift", ".kt", ".sql", ".sh", ".ps1",
}
_CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config", ".xml", ".properties"}
_PRIVATE_KEY_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "private.key", "server.key"}


@dataclass(frozen=True)
class ClassificationResult:
    classification: str
    confidence: str
    reasons: tuple[str, ...]
    matched_indicators: tuple[dict, ...]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        result["matched_indicators"] = list(self.matched_indicators)
        return result


def _policy_field(policy, name, default=None):
    return policy.get(name, default) if isinstance(policy, dict) else getattr(policy, name, default)


def _policy_match(policy, target: str) -> bool:
    if _policy_field(policy, "enabled", True) is False:
        return False
    if str(_policy_field(policy, "category", "")).casefold() == "protected_resource":
        return False
    pattern = str(_policy_field(policy, "pattern", "")).strip().replace("\\", "/").lower()
    if not pattern:
        return False
    return fnmatch(target, pattern) if any(char in pattern for char in "*?[") else pattern in target


def normalize_protected_pattern(value: str, workspace: Path = WORKSPACE) -> str:
    """Normalize a relative pattern or an absolute path anchored inside workspace."""
    raw = str(value).strip().replace("\\", "/")
    if not raw or "\x00" in raw:
        raise ValueError("Resource path is required and cannot contain NUL characters")
    if raw.startswith("~"):
        raise ValueError("Home-directory aliases are not valid protected-resource paths")
    root = str(workspace.resolve()).replace("\\", "/").rstrip("/")
    folded = raw.casefold()
    root_folded = root.casefold()
    if folded == root_folded:
        relative = ""
    elif folded.startswith(root_folded + "/"):
        relative = raw[len(root) + 1:]
    elif raw.startswith("/") or ntpath.splitdrive(raw)[0]:
        raise ValueError("Absolute resource paths must be inside the controlled workspace")
    else:
        relative = raw

    parts = []
    for part in relative.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            raise ValueError("Parent traversal is not allowed in protected-resource paths")
        if any(char in part for char in '<>:"|'):
            raise ValueError("Protected-resource path contains an invalid character")
        if any(char in part for char in "[]"):
            raise ValueError("Only * and ? wildcards are supported")
        parts.append(part.casefold())
    if not parts:
        raise ValueError("Protect a resource below the controlled workspace, not the workspace root")
    root_path = workspace.resolve()
    try:
        resolved = root_path.joinpath(*parts).resolve(strict=False)
        return resolved.relative_to(root_path).as_posix().casefold()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("Protected-resource path must resolve inside the controlled workspace") from exc


def normalize_resource_for_match(resource: str, workspace: Path = WORKSPACE) -> str | None:
    """Normalize a concrete in-workspace action path; reject traversal/outside paths."""
    raw = str(resource).strip().replace("\\", "/")
    if not raw or "\x00" in raw or raw.startswith("~"):
        return None
    root = str(workspace.resolve()).replace("\\", "/").rstrip("/")
    folded, root_folded = raw.casefold(), root.casefold()
    if folded == root_folded:
        return ""
    if folded.startswith(root_folded + "/"):
        relative = raw[len(root) + 1:]
    elif raw.startswith("/") or ntpath.splitdrive(raw)[0]:
        return None
    else:
        relative = raw
    parts = []
    for part in relative.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            return None
        parts.append(part.casefold())
    if not parts:
        return ""
    root_path = workspace.resolve()
    try:
        resolved = root_path.joinpath(*parts).resolve(strict=False)
        return resolved.relative_to(root_path).as_posix().casefold()
    except (OSError, RuntimeError, ValueError):
        return None


def protected_resource_matches(resource: str, policies, workspace: Path = WORKSPACE) -> list[dict]:
    """Return enabled protected-resource rows matching a normalized concrete path."""
    normalized = normalize_resource_for_match(resource, workspace)
    if not normalized:
        return []
    matches = []
    for policy in policies or ():
        if str(_policy_field(policy, "category", "")).casefold() != "protected_resource":
            continue
        enabled = _policy_field(policy, "enabled", True)
        if enabled is not None and not bool(enabled):
            continue
        pattern = str(_policy_field(policy, "pattern", "")).casefold()
        if not pattern or not fnmatch(normalized, pattern):
            continue
        matches.append({
            "id": _policy_field(policy, "id"),
            "pattern": pattern,
            "classification": str(_policy_field(policy, "resource_classification", "UNKNOWN") or "UNKNOWN").upper(),
            "decision": str(_policy_field(policy, "outcome", "MONITOR") or "MONITOR").upper(),
            "description": _policy_field(policy, "description", ""),
            "reason": "Explicit protected-resource policy",
        })
    return sorted(matches, key=lambda item: (
        {"MONITOR": 1, "APPROVAL": 2, "BLOCK": 3}.get(item["decision"], 0),
        sum(char not in "*?" for char in item["pattern"]),
    ), reverse=True)


def _policy_class(policy) -> str | None:
    """Interpret a matching resource rule as an explicit classification override."""
    category = str(_policy_field(policy, "category", "")).strip().lower()
    outcome = str(_policy_field(policy, "outcome", "")).strip().upper()
    aliases = {
        "working": "WORKING", "classification:working": "WORKING",
        "sensitive": "SENSITIVE", "classification:sensitive": "SENSITIVE",
        "private": "PRIVATE", "personal": "PRIVATE", "classification:private": "PRIVATE",
        "critical": "CRITICAL", "classification:critical": "CRITICAL",
    }
    if category in aliases:
        return aliases[category]
    if category in {"resource", "protected", "classification"}:
        if outcome == "BLOCK":
            return "CRITICAL"
        if outcome == "APPROVAL":
            return "SENSITIVE"
        if outcome == "ALLOW":
            return "WORKING"
    return None


def _inside_workspace(resource: str, workspace: Path) -> bool:
    raw = Path(resource).expanduser()
    if ".." in raw.parts:
        return False
    root = workspace.resolve()
    candidate = raw if raw.is_absolute() else root / raw
    try:
        resolved = candidate.resolve(strict=False)
        return resolved == root or root in resolved.parents
    except (OSError, RuntimeError):
        return False


def classify_resource(resource: str, workspace: Path = WORKSPACE, policies=None) -> ClassificationResult:
    """Classify a file-like resource; unknown documents and file types stay UNKNOWN.

    Explicit matching resource policies override automatic indicators. When multiple
    policies match, the most restrictive explicit classification wins.
    """
    target = str(resource).replace("\\", "/").strip().lower()
    normalized = target.rstrip("/")
    name = normalized.rsplit("/", 1)[-1] if normalized else ""
    suffix = Path(name).suffix.lower()
    inside = _inside_workspace(resource, workspace)
    automatic = "UNKNOWN"
    reasons: list[str] = []
    indicators: list[dict] = []

    def mark(classification: str, reason: str, indicator: str):
        nonlocal automatic
        if _CLASS_RANK[classification] > _CLASS_RANK[automatic]:
            automatic = classification
        reasons.append(reason)
        indicators.append({"type": indicator, "value": name or target})

    private_key = (
        name in _PRIVATE_KEY_NAMES
        or name.endswith((".pem", ".key"))
        or (name.startswith("id_") and not suffix)
        or "/.ssh/" in f"/{normalized}/"
        or normalized.startswith(".ssh/")
    )
    if private_key:
        mark("CRITICAL", "private-key filename or extension", "private_key")
    elif name == ".env" or name.startswith(".env.") or name.startswith(("credential", "credentials", "secret", "password")) or "/secrets/" in f"/{normalized}/" or normalized.startswith("secrets/"):
        mark("SENSITIVE", "sensitive filename", "sensitive_name")
    elif any(token in normalized for token in ("passport", "personal", "medical", "tax-return", "/private/")) or normalized.startswith("private/"):
        mark("PRIVATE", "personal or private resource path", "private_path")

    # Type evidence is secondary to security indicators.
    if suffix in _CONFIG_EXTENSIONS and automatic not in {"CRITICAL", "PRIVATE"}:
        mark("SENSITIVE", "configuration file type", "configuration_extension")
    elif suffix in _SOURCE_EXTENSIONS and automatic in {"UNKNOWN", "WORKING"}:
        mark("WORKING", "source-code file type", "source_extension")
    if inside:
        reasons.append("inside controlled workspace")
        indicators.append({"type": "workspace_location", "value": str(workspace)})

    if automatic == "UNKNOWN":
        reasons.append("unknown resource")
        indicators.append({"type": "unknown_resource", "value": suffix or name or target})

    matched = []
    explicit = []
    protected = protected_resource_matches(resource, policies, workspace)
    for item in protected:
        protected_item = {
            "id": item["id"],
            "category": "protected_resource",
            "pattern": item["pattern"],
            "outcome": item["decision"],
            "classification": item["classification"],
            "description": item["description"],
            "reason": item["reason"],
        }
        matched.append(protected_item)
        explicit.append((item["classification"], protected_item))
    for policy in policies or ():
        if not _policy_match(policy, target):
            continue
        classification = _policy_class(policy)
        if classification is None:
            continue
        item = {
            "id": _policy_field(policy, "id"),
            "category": _policy_field(policy, "category"),
            "pattern": _policy_field(policy, "pattern"),
            "outcome": _policy_field(policy, "outcome"),
            "classification": classification,
            "description": _policy_field(policy, "description", ""),
        }
        matched.append(item)
        explicit.append((classification, item))

    if explicit:
        classification = protected[0]["classification"] if protected else max(
            (item[0] for item in explicit), key=lambda value: _CLASS_RANK[value]
        )
        reasons.append("Explicit protected-resource policy" if protected else "explicit user policy")
        indicators.append({"type": "user_policy", "value": classification})
        reasons.extend(item[1]["description"] for item in explicit if item[1]["description"])
        confidence = "HIGH"
    else:
        classification = automatic
        confidence = "HIGH" if automatic in {"CRITICAL", "PRIVATE", "SENSITIVE"} else "MEDIUM" if automatic == "WORKING" else "LOW"

    return ClassificationResult(
        classification=classification,
        confidence=confidence,
        reasons=tuple(dict.fromkeys(reasons)),
        matched_indicators=tuple(indicators + ([{"type": "matched_policy", **item} for item in matched] if explicit else [])),
    )
