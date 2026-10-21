from app.config import WORKSPACE
from app.services.resource_classifier import classify_resource


def test_source_code_is_working():
    result = classify_resource("src/login.js")
    assert result.classification == "WORKING"
    assert "source-code file type" in result.reasons


def test_env_is_sensitive():
    assert classify_resource(".env").classification == "SENSITIVE"


def test_credentials_json_is_sensitive():
    result = classify_resource("config/credentials.json")
    assert result.classification == "SENSITIVE"
    assert "sensitive filename" in result.reasons


def test_private_key_is_critical():
    result = classify_resource(".ssh/id_rsa")
    assert result.classification == "CRITICAL"
    assert "private-key filename or extension" in result.reasons


def test_matching_explicit_protection_policy_overrides_automatic_classification():
    policy = {
        "id": "POL-PROTECTED-REPORT",
        "category": "protected",
        "pattern": "docs/report.pdf",
        "severity": "CRITICAL",
        "outcome": "BLOCK",
        "description": "Protected report",
    }
    result = classify_resource("docs/report.pdf", policies=[policy])
    assert result.classification == "CRITICAL"
    assert "explicit user policy" in result.reasons
    assert result.matched_indicators[-1]["id"] == policy["id"]


def test_explicit_working_policy_can_override_an_automatic_label():
    policy = {
        "id": "POL-EXPLICIT-WORKING",
        "category": "classification:working",
        "pattern": ".env",
        "severity": "LOW",
        "outcome": "ALLOW",
        "description": "Explicit classification test",
    }
    result = classify_resource(".env", policies=[policy])
    assert result.classification == "WORKING"
    assert "explicit user policy" in result.reasons


def test_unknown_file_type_stays_unknown():
    assert classify_resource("runtime_test/payload.zzz").classification == "UNKNOWN"


def test_documents_and_images_stay_unknown_without_explicit_rule():
    assert classify_resource("runtime_test/report.pdf").classification == "UNKNOWN"
    assert classify_resource("runtime_test/photo.png").classification == "UNKNOWN"


def test_workspace_source_file_is_working_when_no_stronger_indicator_exists():
    result = classify_resource("runtime_test/example.py", workspace=WORKSPACE)
    assert result.classification == "WORKING"
    assert "inside controlled workspace" in result.reasons


def test_sensitive_indicator_overrides_workspace_location():
    result = classify_resource("runtime_test/.env.local", workspace=WORKSPACE)
    assert result.classification == "SENSITIVE"
    assert "inside controlled workspace" in result.reasons
