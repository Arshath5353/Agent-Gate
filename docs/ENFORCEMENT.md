# AgentGate user-mode enforcement demo

## Enforcement boundary

AgentGate now has a narrow user-mode broker at `POST /api/broker/execute`. It evaluates each submitted `ActionIn` through the existing normalized action, resource classifier, persisted policy catalogue, protected-resource rules, and policy engine. The broker performs an operation only for an explicit `ALLOW` or after the matching pending approval is approved once. An approval is tied to one action and one execution record; a later submission is evaluated as a new request.

This is enforcement only for operations routed through the broker. An unrestricted agent can still access resources directly outside this API. AgentGate does not transparently intercept arbitrary processes.

## Precise terms

- **OBSERVATION** — the existing `ReadDirectoryChangesW` monitor reports filesystem changes after they occur. It remains observational; it does not prevent operations.
- **DECISION** — the existing policy engine returns `ALLOW`, `APPROVAL`, `BLOCK`, or `MONITOR` with risk and explanation data.
- **PRE-ACTION GATING** — the broker submits the normalized action to the policy engine before it calls its controlled executor. `BLOCK` and `MONITOR` do not execute. `APPROVAL` waits for the specific approval.
- **OS-LEVEL ENFORCEMENT** — Windows ACLs control access to the one protected fixture based on the Windows identity of the process. The broker does not elevate privileges or bypass ACLs.

The existing Live Monitor continues to receive the existing action and runtime events. Broker lifecycle changes use additive audit entries and an additive `ACTION_EXECUTION_UPDATED` WebSocket event.

## Supported broker operations

The executor is intentionally limited to the files in `controlled_workspace/enforcement_demo/`:

- `READ`: reads named demo fixtures only, with a 10 KB limit.
- `WRITE`: writes `allowed_demo.py` or `approval_demo.py` only, from string `metadata.content`, with a 10 KB limit.
- `DELETE`: deletes the exact disposable `delete_me.py` fixture only.
- `EXECUTE`: accepts exactly `python --version`, launches Python with an argument vector and `shell=False`, and has a five second timeout. Any other command is rejected; dangerous commands continue to be blocked by the existing policy engine.
- `NETWORK_CONNECT`: records a simulated result and opens no connection.
- Other action types are not executed by the broker.

Only paths resolving directly to an allowlisted fixture under `controlled_workspace/enforcement_demo/` are accepted. Parent traversal, symlink escape, and other directories are rejected. Filesystem errors are recorded as `FAILED`. `MONITOR` is not authorization and does not execute.

For normal allowed examples, create a task whose allowed scope includes `enforcement_demo/`, then POST a `READ` action for `enforcement_demo/allowed_demo.py`. A `WRITE` request includes, for example, `"metadata":{"content":"DEMO_VALUE = 'updated'\\n"}`. Submit the same shape to `POST /api/broker/execute`. The response includes the action plus `execution` with `action_id`, `approval_id`, `execution_id`, decision, status, resource, and result. `GET /api/executions/{execution_id}` returns the current status.

To demonstrate an approval, first create a protected-resource rule for `enforcement_demo/approval_demo.py` with classification `SENSITIVE` and decision `APPROVAL`, then submit a broker action for that resource. The broker request remains pending while the approval appears in the existing Approvals page/API. **Allow once** releases only that request; deny, cancellation, or expiry never executes it. Timeout defaults to 120 seconds and can be configured using `AGENTGATE_BROKER_APPROVAL_TIMEOUT_SECONDS`.

## Execution and audit lifecycle

Each broker submission creates a new action and a unique `BrokerExecution` row. The action metadata records `broker_managed`, `execution_id`, and `execution_status`. Execution rows have one unique `action_id` and optional matching `approval_id`, preventing an old approval from being reused by a new request.

Audit entries correlate the original `action_id`, `approval_id`, and `execution_id`: `BROKER_ACTION_REQUESTED`, `EXECUTION_STARTED`, `EXECUTION_COMPLETED`, `EXECUTION_DENIED`, or `EXECUTION_FAILED`, plus the existing approval requested/resolved events. Approval expiry/cancellation is recorded separately. Lifecycle result data is also available from the execution endpoint.

## Restricted Windows identity ACL demonstration

The repository includes three PowerShell scripts under `scripts/enforcement_demo/`. They affect only `controlled_workspace/enforcement_demo/protected_demo.txt`:

1. Create or select two existing local identities: a **standard, non-administrator agent identity** and the identity that runs the broker. Do not use an administrator account as the agent identity. The broker identity receives Modify access to this one fixture; the designated agent identity receives an explicit deny ACE.
2. From an elevated PowerShell only if Windows requires it to edit that fixture's DACL, run:

   ```powershell
   .\scripts\enforcement_demo\setup_acl.ps1 -AgentIdentity '.\AgentGateDemoAgent' -BrokerIdentity '.\AgentGateDemoBroker'
   .\scripts\enforcement_demo\verify_acl.ps1 -AgentIdentity '.\AgentGateDemoAgent'
   ```

   The setup resolves the fixture path and refuses to operate outside the demo directory. It does not change ACLs on the workspace or parent folders.
3. Run an actual read/write probe as the agent identity (for example with a separate logon session) and confirm Windows denies access. Run the broker under the explicitly configured broker identity for the broker-controlled operation. The scripts do not create accounts, change group membership, or grant administrator privileges.
4. Restore inherited permissions on the fixture with:

   ```powershell
   .\scripts\enforcement_demo\cleanup_acl.ps1
   ```

This ACL demonstration is optional and is not applied automatically. The verify script checks for the expected deny ACE; an actual access-denial probe must be performed in a session running as the restricted identity. ACL setup may require local administrator rights depending on file ownership and system configuration.

## What remains outside this implementation

- Direct filesystem, process, or network operations by an agent that bypasses the broker are not intercepted.
- The broker is not a general command proxy and does not support arbitrary shell commands or arbitrary files.
- Windows ACL enforcement depends on the process identity and ACL configuration. Running both agent and broker under the denied identity will also deny the broker; the broker is not a privilege-escalation boundary.
- The broker does not implement kernel drivers, filesystem minifilters, WFP callouts, SIEM export, MCP mediation, or dashboard redesign.
- ReadDirectoryChangesW remains post-operation observation, not evidence that an operation was prevented.
