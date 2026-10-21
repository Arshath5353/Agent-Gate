"""Optional ACL verification; never requires elevated privileges in pytest."""
import os
from pathlib import Path
import subprocess

import pytest

from app.config import WORKSPACE


@pytest.mark.skipif(
    os.name != "nt" or not os.getenv("AGENTGATE_ACL_TEST_IDENTITY"),
    reason="optional ACL demo is Windows-only and requires configured fixture/identity",
)
def test_restricted_identity_has_deny_ace_on_demo_fixture():
    fixture = WORKSPACE / "enforcement_demo" / "protected_demo.txt"
    if not fixture.is_file():
        pytest.skip("ACL demo fixture setup is unavailable")
    identity = os.environ["AGENTGATE_ACL_TEST_IDENTITY"]
    script = Path(__file__).resolve().parents[2] / "scripts" / "enforcement_demo" / "verify_acl.ps1"
    result = subprocess.run(
        ["powershell", "-NoProfile", "-File", str(script), "-AgentIdentity", identity],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode and "Access is denied" in (result.stderr + result.stdout):
        pytest.skip("fixture ACL cannot be inspected with current permissions")
    assert result.returncode == 0 and "ACL DEMO: PASS" in result.stdout, result.stdout + result.stderr
