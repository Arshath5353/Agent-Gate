import pytest
from pathlib import Path
from app.services.policy_engine import evaluate, is_path_allowed
from app.config import WORKSPACE

def test_normal_file_allowed(): assert evaluate("READ","src/login.js",{})["decision"]=="ALLOW"
def test_env_requires_approval(): assert evaluate("READ",".env",{})["decision"]=="APPROVAL"
def test_ssh_key_blocked(): assert evaluate("READ","~/.ssh/id_rsa",{})["decision"]=="BLOCK"
def test_passport_blocked(): assert evaluate("READ","passport.pdf",{})["decision"]=="BLOCK"
def test_npm_test_allowed(): assert evaluate("EXECUTE","npm test",{})["decision"]=="ALLOW"
def test_destructive_command_blocked(): assert evaluate("EXECUTE","rm -rf /",{})["decision"]=="BLOCK"
def test_path_traversal_blocked(): assert not is_path_allowed("../.env",WORKSPACE)
def test_named_workspace_traversal_blocked(): assert evaluate("READ","controlled_workspace/../.env",{})["decision"]=="BLOCK"
def test_absolute_external_path_blocked(): assert evaluate("READ","/home/user/.ssh/id_rsa",{})["decision"]=="BLOCK"
def test_unknown_network_requires_approval(): assert evaluate("NETWORK_CONNECT","https://unknown.invalid/path",{})["decision"]=="APPROVAL"
def test_malicious_test_domain_blocked(): assert evaluate("NETWORK_CONNECT","https://evil.example/path",{})["decision"]=="BLOCK"
def test_symlink_escape_blocked(tmp_path):
    root=tmp_path/"workspace"; root.mkdir(); outside=tmp_path/"outside"; outside.mkdir()
    try: (root/"escape").symlink_to(outside,target_is_directory=True)
    except OSError as exc: pytest.skip(f"symlink creation is unavailable: {exc}")
    assert not is_path_allowed("escape/secret",root)
