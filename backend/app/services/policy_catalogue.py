"""Versioned, reference-backed default policy catalogue."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Policy

CATALOGUE_VERSION = "1.0"

# Catalogue rules are deterministic and evaluate only action fields and explicitly
# supplied integration context. They do not inspect file contents or classify prompts.
CATALOGUE = [
    ("AG-CRED-001", "Private key material", "CREDENTIAL_SECURITY", "READ,WRITE,DELETE", "*.pem", "CRITICAL", "BLOCK", "CRITICAL", "Private keys must not be read, replaced, or deleted through an agent request.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-CRED-002", "Private key material", "CREDENTIAL_SECURITY", "READ,WRITE,DELETE", "*.key", "CRITICAL", "BLOCK", "CRITICAL", "Private key files are blocked.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-CRED-003", "SSH private keys", "CREDENTIAL_SECURITY", "READ,WRITE,DELETE", "@ssh_private_key", "CRITICAL", "BLOCK", "CRITICAL", "SSH private key paths are blocked.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-CRED-004", "Environment secrets", "CREDENTIAL_SECURITY", "READ,WRITE,DELETE", ".env", "HIGH", "APPROVAL", "HIGH", "Environment files can contain credentials and require review.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-CRED-005", "Credential file access", "CREDENTIAL_SECURITY", "READ,WRITE,DELETE", "*credential*", "HIGH", "APPROVAL", "HIGH", "Credential-named resources require review.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-CRED-006", "Secret file access", "CREDENTIAL_SECURITY", "READ,WRITE,DELETE", "*secret*", "HIGH", "APPROVAL", "HIGH", "Secret-named resources require review.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-CRED-007", "Credential modifications", "CREDENTIAL_SECURITY", "WRITE,DELETE", "@credential_resource", "CRITICAL", "APPROVAL", "HIGH", "Credential-resource modifications require human review.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-FS-001", "Workspace escape", "FILESYSTEM_SECURITY", "READ,WRITE,DELETE", "@outside_workspace", "CRITICAL", "BLOCK", "CRITICAL", "File actions must remain inside the controlled workspace.", "NIST AI RMF: Manage", "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"),
    ("AG-FS-002", "Path traversal", "FILESYSTEM_SECURITY", "READ,WRITE,DELETE", "@path_traversal", "CRITICAL", "BLOCK", "CRITICAL", "Traversal syntax is denied even if normalization would return inside the workspace.", "NIST AI RMF: Manage", "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"),
    ("AG-FS-003", "System directory access", "FILESYSTEM_SECURITY", "READ,WRITE,DELETE", "@system_path", "CRITICAL", "BLOCK", "CRITICAL", "System directory access is denied.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-FS-004", "Unknown resource review", "FILESYSTEM_SECURITY", "READ,WRITE,DELETE", "@unknown_resource", "MEDIUM", "MONITOR", "MEDIUM", "Unclassified resources remain observable and are not assumed safe.", "NIST AI RMF: Measure", "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"),
    ("AG-FS-005", "Protected resource enforcement", "FILESYSTEM_SECURITY", "READ,WRITE,DELETE", "@protected_resource", "HIGH", "APPROVAL", "HIGH", "Explicit protected-resource decisions take precedence through the protected-resource policy path.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-FS-006", "Task scope enforcement", "TASK_SCOPE", "READ,WRITE,DELETE", "@out_of_task_scope", "HIGH", "APPROVAL", "HIGH", "Actions outside the task declared scope require review.", "NIST AI RMF: Manage", "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"),
    ("AG-CMD-001", "Destructive shell command", "COMMAND_EXECUTION", "EXECUTE", "@dangerous_command", "CRITICAL", "BLOCK", "CRITICAL", "Destructive or privilege-escalating commands are blocked.", "MITRE ATLAS", "https://atlas.mitre.org/"),
    ("AG-CMD-002", "Privilege escalation command", "COMMAND_EXECUTION", "EXECUTE", "sudo", "HIGH", "BLOCK", "HIGH", "Privilege escalation commands are blocked.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
    ("AG-CMD-003", "Unknown command review", "COMMAND_EXECUTION", "EXECUTE", "@unknown_command", "HIGH", "APPROVAL", "HIGH", "Commands outside the recognized development command set require review.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-CMD-004", "Download and execute", "COMMAND_EXECUTION", "EXECUTE", "@download_execute", "CRITICAL", "BLOCK", "CRITICAL", "Piping a remote download directly to a shell is blocked.", "MITRE ATLAS", "https://atlas.mitre.org/"),
    ("AG-CMD-005", "Obfuscated command", "COMMAND_EXECUTION", "EXECUTE", "@obfuscated_command", "HIGH", "APPROVAL", "HIGH", "Commands flagged by the integration as obfuscated require review.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-NET-001", "Blocked network destination", "NETWORK_SECURITY", "NETWORK_CONNECT", "@blocked_host", "CRITICAL", "BLOCK", "CRITICAL", "Known blocked test destinations are denied.", "MITRE ATLAS", "https://atlas.mitre.org/"),
    ("AG-NET-002", "Unknown external destination", "NETWORK_SECURITY", "NETWORK_CONNECT", "@unknown_network", "HIGH", "APPROVAL", "HIGH", "External destinations without an allowlist entry require review.", "Microsoft Agentic AI Shared Responsibility", "https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility-ai-agent"),
    ("AG-NET-003", "Sensitive data egress", "DATA_PROTECTION", "NETWORK_CONNECT,TOOL_CALL", "@sensitive_egress", "CRITICAL", "BLOCK", "CRITICAL", "Blocks egress when the integration declares sensitive data in the action context.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-NET-004", "Unapproved upload", "DATA_PROTECTION", "NETWORK_CONNECT,TOOL_CALL", "@unapproved_upload", "HIGH", "APPROVAL", "HIGH", "Uploads not marked as approved by the integration require review.", "Microsoft Agentic AI Shared Responsibility", "https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility-ai-agent"),
    ("AG-NET-005", "Cloud metadata endpoint", "NETWORK_SECURITY", "NETWORK_CONNECT", "@metadata_endpoint", "CRITICAL", "BLOCK", "CRITICAL", "Cloud metadata endpoints are blocked.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-DATA-001", "Sensitive data handling", "DATA_PROTECTION", "READ,WRITE,DELETE,TOOL_CALL", "@sensitive_data", "HIGH", "APPROVAL", "HIGH", "Resources or payloads declared sensitive by the integration require review.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-DATA-002", "Personal data handling", "DATA_PROTECTION", "READ,WRITE,DELETE,TOOL_CALL", "@personal_data", "HIGH", "APPROVAL", "HIGH", "Personal-data indicators declared by the integration require review.", "OWASP LLM02: Sensitive Information Disclosure", "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"),
    ("AG-TOOL-001", "Unregistered tool invocation", "AGENT_TOOL_SECURITY", "TOOL_CALL", "@unknown_tool", "HIGH", "APPROVAL", "HIGH", "Tool calls require review until a trusted-tool registry is available.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
    ("AG-TOOL-002", "Destructive tool invocation", "AGENT_TOOL_SECURITY", "TOOL_CALL", "@destructive_tool", "CRITICAL", "APPROVAL", "HIGH", "Destructive tool names or integration labels require human review.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
    ("AG-TOOL-003", "Privileged tool invocation", "AGENT_TOOL_SECURITY", "TOOL_CALL", "@privileged_tool", "HIGH", "APPROVAL", "HIGH", "Privileged tool calls require human review.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
    ("AG-TOOL-004", "High impact tool invocation", "AGENT_TOOL_SECURITY", "TOOL_CALL", "@high_impact_tool", "HIGH", "APPROVAL", "HIGH", "High-impact tool calls require review when identified by the integration.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-TOOL-005", "Irreversible tool invocation", "AGENT_TOOL_SECURITY", "TOOL_CALL", "@irreversible_tool", "HIGH", "APPROVAL", "HIGH", "Irreversible tool calls require human review.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-TOOL-006", "Excessive tool permissions", "AGENT_TOOL_SECURITY", "TOOL_CALL", "@excessive_permissions", "HIGH", "APPROVAL", "HIGH", "Excessive permissions declared by an integration require review.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
    ("AG-SCOPE-001", "Declared task scope", "TASK_SCOPE", "READ,WRITE,DELETE,EXECUTE,TOOL_CALL", "@out_of_task_scope", "HIGH", "APPROVAL", "HIGH", "Actions outside declared task scope require review.", "NIST AI RMF: Manage", "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/"),
    ("AG-HUM-001", "High impact approval", "HUMAN_APPROVAL", "WRITE,DELETE,EXECUTE,TOOL_CALL", "@high_impact", "HIGH", "APPROVAL", "HIGH", "High-impact actions identified by the integration require human approval.", "Microsoft Responsible AI", "https://learn.microsoft.com/en-us/agents/center-of-excellence/responsible-ai"),
    ("AG-HUM-002", "Irreversible action approval", "HUMAN_APPROVAL", "DELETE,TOOL_CALL", "@irreversible", "HIGH", "APPROVAL", "HIGH", "Irreversible actions require human approval when identified by the integration.", "Microsoft Responsible AI", "https://learn.microsoft.com/en-us/agents/center-of-excellence/responsible-ai"),
    ("AG-UNTRUST-001", "Untrusted content escalation", "UNTRUSTED_CONTENT", "TOOL_CALL,EXECUTE,WRITE", "@untrusted_content_escalation", "HIGH", "APPROVAL", "HIGH", "Requires review when integration labels untrusted content as requesting sensitive access.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-UNTRUST-002", "Untrusted tool output escalation", "UNTRUSTED_CONTENT", "TOOL_CALL,EXECUTE,WRITE", "@tool_output_escalation", "HIGH", "APPROVAL", "HIGH", "Requires review when untrusted tool output is labelled as requesting privilege escalation.", "Microsoft Agent Safety", "https://learn.microsoft.com/en-us/agent-framework/concepts/agents/safety"),
    ("AG-UNTRUST-003", "Prompt-derived sensitive access", "UNTRUSTED_CONTENT", "TOOL_CALL,READ,WRITE", "@untrusted_sensitive_access", "HIGH", "APPROVAL", "HIGH", "Requires review when an upstream integration flags untrusted content seeking sensitive access.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
    ("AG-UNTRUST-004", "Prompt-derived privilege escalation", "UNTRUSTED_CONTENT", "TOOL_CALL,EXECUTE", "@untrusted_privilege_escalation", "HIGH", "APPROVAL", "HIGH", "Requires review when an upstream integration flags untrusted content seeking privilege escalation.", "OWASP Agentic Top 10", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"),
]


def ensure_policy_catalog(db: Session) -> int:
    """Add missing built-ins without replacing user-edited or protected-resource rules."""
    existing = set(db.scalars(select(Policy.id)).all())
    added = 0
    for (policy_id, name, category, action_type, pattern, severity, outcome,
         risk_level, description, reference_name, reference_url) in CATALOGUE:
        if policy_id in existing:
            continue
        db.add(Policy(
            id=policy_id, name=name, category=category, action_type=action_type,
            pattern=pattern, severity=severity, outcome=outcome,
            risk_level=risk_level, description=description,
            rationale=description, reference_name=reference_name,
            reference_url=reference_url, version=CATALOGUE_VERSION,
            enabled=True,
        ))
        added += 1
    if added:
        db.commit()
    return added
