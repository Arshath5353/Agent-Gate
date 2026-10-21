"""Safe decision-only client for the generic AgentGate integration API."""
import argparse
import json
import urllib.request


SCENARIOS = [
    ("READ", "src/login.js", {}, "normal source file"),
    ("READ", ".env", {}, "sensitive configuration"),
    ("READ", "passport.pdf", {}, "protected personal-document policy"),
    ("DELETE", "passport.pdf", {}, "protected resource delete request"),
    ("EXECUTE", "npm test", {}, "recognized development command"),
    ("EXECUTE", "rm -rf /", {}, "dangerous command string"),
]


def post(url: str, body: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentGate Integration API Demo")
    parser.add_argument("--api", default="http://127.0.0.1:8000/api")
    parser.add_argument("--agent-id", default="generic-demo-agent")
    parser.add_argument("--agent-name", default="Generic Demo Agent")
    parser.add_argument("--session-id", default="integration-demo-session")
    parser.add_argument("--task-id", help="Optional existing AgentGate task ID")
    args = parser.parse_args()

    print("AgentGate Integration API Demo")
    print("Decision requests only: this client does not perform the described file, command, or network operations.")
    for action_type, resource, metadata, label in SCENARIOS:
        body = {
            "agent": {"id": args.agent_id, "name": args.agent_name, "version": "demo"},
            "session_id": args.session_id,
            "action": {"type": action_type, "resource": resource, "metadata": metadata},
        }
        if args.task_id:
            body["task_id"] = args.task_id
        result = post(args.api.rstrip("/") + "/agent/actions/check", body)
        print(
            f"{action_type:15} {resource:28} {result['decision']:9} "
            f"{result['risk']['level']:8} {label}"
        )


if __name__ == "__main__":
    main()
