# Security testing

## Threat model

AgentGate accepts normalized agent action requests and evaluates them against deterministic policies, resource classifications, protected-resource rules, task scope, and hard safeguards. The adversarial suite submits simulated requests to the local test API; it does not run commands, make network connections, read credentials, or change real files. Its scope is bypass resistance at the decision and API layers, not a claim that every agent or attack is covered.

## Tested attack and bypass classes

The suite exercises path traversal (including Windows separators), case and separator normalization, protected-resource wildcard matching, policy conflicts and disabled rules, classification indicators, workspace/task-scope boundaries, dangerous and unrecognized commands, network and metadata destinations, tool-call risk, integration-supplied untrusted-content indicators, approval replay, bulk approval, and malformed API input.

The tests record these invariants:

1. Traversal and workspace escape cannot override an ordinary allow policy.
2. Hard safeguards remain stronger than ordinary persisted policies.
3. Disabled policies do not change a decision or its classification.
4. Protected-resource decisions outrank ordinary allow rules.
5. An approval authorizes one action and does not change future policy decisions.
6. Unknown tools require review; unknown resources remain monitored under the current risk policy.

## What AgentGate evaluates and its limits

AgentGate evaluates and controls actions submitted through its decision API and applies policy decisions to observed runtime activity. Current Windows ReadDirectoryChangesW monitoring is observational and cannot retroactively prevent a filesystem operation. The Windows monitor sees configured filename/last-write notifications in the controlled workspace; it does not intercept an operation before it occurs. AgentGate does not currently enforce decisions at the operating-system boundary.

Policy checks for file content, prompt meaning, tool registration, or upload approval rely on explicit context labels supplied by the integration. The current test suite cannot prove an integration labels those signals accurately. Unknown tool calls require approval because there is not yet a trusted-tool registry. Network actions in these tests are policy requests only and never create a socket connection.

## Running the suite

From `backend`, run the full backend suite (including the adversarial cases):

```powershell
..\.venv\Scripts\python.exe -m pytest -q
```

Run only the adversarial suite with:

```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_adversarial_security.py -q
```
