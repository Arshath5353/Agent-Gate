"""Generate harmless, real filesystem notifications inside the demo workspace."""
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1] / "real_agent_demo"


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    files = {
        "login.html": "<!doctype html>\n<title>Safe AgentGate demo</title>\n<h1>Login</h1>\n",
        "style.css": "body { font-family: sans-serif; }\n",
        "script.js": "document.documentElement.dataset.demo = 'ready';\n",
    }
    for name, content in files.items():
        (ROOT / name).write_text(content, encoding="utf-8")
        time.sleep(0.25)
    # Modify one file so the monitor also exercises a last-write notification.
    with (ROOT / "login.html").open("a", encoding="utf-8") as page:
        page.write("<!-- harmless local test modification -->\n")
    time.sleep(1.0)


if __name__ == "__main__":
    main()
