"""Safe V3 test process: reads only dummy fixtures and writes one test output file."""
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent

def main():
    # Read the harmless fixture and existing dummy source; never read secret fixtures.
    (HERE / "dummy.txt").read_text(encoding="utf-8")
    (WORKSPACE / "src" / "login.js").read_text(encoding="utf-8")
    (HERE / "test_output.txt").write_text(f"Safe AgentGate monitor test output {time.time_ns()}.\n", encoding="utf-8")
    # Give the directory notification observer time to deliver its change event.
    time.sleep(1.0)

if __name__ == "__main__":
    main()
