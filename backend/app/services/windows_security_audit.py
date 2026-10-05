"""Read narrowly scoped Windows Security 4663 events for safe workspace fixtures.

This is an optional evidence source. It never changes Windows auditing settings,
reads file contents, or infers READ from directory notifications/process ancestry.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from typing import Any, Mapping

from app.services.windows_monitor import API_BASE, SAFE_TEST_DIR, WORKSPACE, WindowsMonitorAdapter

SOURCE_UNAVAILABLE = "Windows Security audit source unavailable"
SAFE_AUDIT_FILES = (
    "runtime_test/dummy.txt",
    "runtime_test/test_output.txt",
    "src/login.js",
)
READ_DATA = 0x00000001
ACCESS_RIGHTS = (
    (0x00000001, "ReadData"),
    (0x00000002, "WriteData"),
    (0x00000004, "AppendData"),
    (0x00000008, "ReadEA"),
    (0x00000010, "WriteEA"),
    (0x00000020, "Execute/Traverse"),
    (0x00000040, "DeleteChild"),
    (0x00000080, "ReadAttributes"),
    (0x00000100, "WriteAttributes"),
    (0x00010000, "DELETE"),
)


def _field(record: Mapping[str, Any], *names: str) -> Any:
    lowered = {str(key).casefold(): value for key, value in record.items()}
    for name in names:
        if name.casefold() in lowered:
            return lowered[name.casefold()]
    return None


def _number(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _safe_relative_path(path: Any, workspace: str | Path = WORKSPACE) -> str | None:
    if not isinstance(path, str) or not path.strip():
        return None
    root = ntpath.normcase(ntpath.normpath(ntpath.abspath(str(workspace))))
    candidate = ntpath.normcase(ntpath.normpath(ntpath.abspath(path)))
    try:
        if ntpath.commonpath((root, candidate)) != root or candidate == root:
            return None
        relative = ntpath.relpath(candidate, root)
    except (ValueError, OSError):
        return None
    if relative == ".." or relative.startswith("..\\"):
        return None
    return relative.replace("\\", "/")


def _decode_access(mask: int | None, raw_rights: Any) -> list[str]:
    rights: list[str] = []
    if mask is not None:
        rights.extend(name for bit, name in ACCESS_RIGHTS if mask & bit)
    if isinstance(raw_rights, str):
        raw = [part.strip() for part in re.split(r"[,;|]", raw_rights) if part.strip()]
    elif isinstance(raw_rights, (tuple, list, set)):
        raw = [str(part).strip() for part in raw_rights if str(part).strip()]
    else:
        raw = []
    for right in raw:
        if right.casefold() in {"readdata", "read data"} and "ReadData" not in rights:
            rights.append("ReadData")
        elif right not in rights:
            rights.append(right)
    return rights


def normalize_4663_record(record: Mapping[str, Any], workspace: str | Path = WORKSPACE) -> dict[str, Any] | None:
    """Normalize only 4663 evidence with an explicit file ReadData access right."""
    event_id = _number(_field(record, "event_id", "EventID"))
    path = _field(record, "object_name", "ObjectName", "object_path", "file_path")
    relative = _safe_relative_path(path, workspace)
    if event_id != 4663 or relative is None:
        return None

    access_mask_raw = _field(record, "access_mask", "AccessMask")
    access_mask = _number(access_mask_raw)
    raw_rights = _field(record, "access_rights", "Accesses", "AccessList")
    rights = _decode_access(access_mask, raw_rights)
    if "ReadData" not in rights:
        return None

    pid = _number(_field(record, "process_id", "ProcessId", "pid"))
    if pid is not None and pid < 0:
        pid = None
    process_path = _field(record, "process_name", "ProcessName", "process_path")
    process_name = ntpath.basename(process_path) if isinstance(process_path, str) and process_path else None
    timestamp = _field(record, "timestamp", "TimeCreated") or datetime.now(timezone.utc).isoformat()
    if isinstance(timestamp, datetime):
        timestamp = timestamp.astimezone(timezone.utc).isoformat()
    subject = {
        key: _field(record, *aliases)
        for key, aliases in {
            "user_sid": ("SubjectUserSid", "subject_user_sid"),
            "user_name": ("SubjectUserName", "subject_user_name"),
            "domain_name": ("SubjectDomainName", "subject_domain_name"),
            "logon_id": ("SubjectLogonId", "subject_logon_id"),
        }.items()
        if _field(record, *aliases) is not None
    }
    return {
        "agent": "WINDOWS_SECURITY_AUDIT",
        "agent_source": "windows_security_audit",
        "pid": pid,
        "process_name": process_name,
        "process_path": process_path if isinstance(process_path, str) else None,
        "action_type": "READ",
        "resource": relative,
        "timestamp": str(timestamp),
        "metadata": {
            "source": "windows_security_audit",
            "agent_source": "windows_security_audit",
            "event_id": event_id,
            "record_id": _number(_field(record, "record_id", "EventRecordID")),
            "access_mask": access_mask_raw,
            "access_rights": rights,
            "access_rights_raw": raw_rights,
            "evidence": "ReadData",
            "subject": subject,
            "process_attribution": "event_pid" if pid is not None else "unavailable_in_event",
            "observed_path": path,
        },
    }


def parse_4663_xml(xml_text: str) -> list[dict[str, Any]]:
    """Extract 4663 fields from one or more wevtutil XML Event elements."""
    records: list[dict[str, Any]] = []
    for fragment in re.findall(r"(?s)<Event(?:\s[^>]*)?>.*?</Event>", xml_text):
        try:
            root = ET.fromstring(fragment)
        except ET.ParseError:
            continue
        values: dict[str, Any] = {}
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag == "EventID":
                values["event_id"] = node.text
            elif tag == "EventRecordID":
                values["record_id"] = node.text
            elif tag == "TimeCreated":
                values["timestamp"] = node.attrib.get("SystemTime")
            elif tag == "Data":
                name = node.attrib.get("Name")
                if name:
                    values[name] = node.text
        if _number(values.get("event_id")) == 4663:
            records.append(values)
    return records


def safe_query_paths(workspace: str | Path = WORKSPACE) -> tuple[str, ...]:
    root = Path(workspace)
    paths = []
    for relative in SAFE_AUDIT_FILES:
        candidate = root.joinpath(*relative.split("/"))
        if _safe_relative_path(str(candidate), workspace) is None:
            raise ValueError("Audit query path escaped controlled_workspace")
        paths.append(ntpath.normpath(str(candidate)))
    return tuple(paths)


def build_event_xpath(paths: tuple[str, ...], after_record_id: int | None = None) -> str:
    """Build an Event Log query restricted to exact safe fixture file paths."""
    if not paths:
        raise ValueError("At least one controlled-workspace path is required")
    predicates = []
    for path in paths:
        if "'" in path:
            raise ValueError("Unsupported quote in controlled-workspace path")
        predicates.append(f"Data[@Name='ObjectName']='{path}'")
    system = "EventID=4663"
    if after_record_id is not None:
        system += f" and EventRecordID>{int(after_record_id)}"
    return f"*[System[{system}] and EventData[({' or '.join(predicates)})]]"


class WindowsSecurityAuditReader:
    """Poll only 4663 events for exact safe fixture paths using wevtutil."""
    def __init__(self, workspace: str | Path = WORKSPACE, command_runner=subprocess.run):
        self.paths = safe_query_paths(workspace)
        self.command_runner = command_runner

    def query(self, after_record_id: int | None = None, newest: int = 1000) -> list[dict[str, Any]]:
        xpath = build_event_xpath(self.paths, after_record_id)
        args = ["wevtutil.exe", "qe", "Security", f"/q:{xpath}", "/f:xml", "/rd:true", f"/c:{newest}"]
        try:
            result = self.command_runner(args, capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(SOURCE_UNAVAILABLE) from exc
        if result.returncode != 0:
            raise RuntimeError(SOURCE_UNAVAILABLE)
        return parse_4663_xml(result.stdout or "")


def _create_fixture_process() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(SAFE_TEST_DIR / "safe_file_activity.py")],
        cwd=str(WORKSPACE), shell=False,
    )


def run(args: argparse.Namespace) -> int:
    if os.name != "nt":
        print(SOURCE_UNAVAILABLE)
        return 2
    reader = WindowsSecurityAuditReader()
    adapter = WindowsMonitorAdapter(args.api)
    fixture: subprocess.Popen | None = None
    try:
        # Baseline first, so historical audit records never become new actions.
        baseline = reader.query(newest=1)
        last_record_id = max((_number(row.get("record_id")) or 0 for row in baseline), default=0)
    except RuntimeError:
        print(SOURCE_UNAVAILABLE, flush=True)
        return 2

    try:
        task_id = args.task_id or adapter.create_task()
        if args.safe_test:
            fixture = _create_fixture_process()
            selected_pid = fixture.pid
        else:
            selected_pid = args.pid
        adapter.set_mode("WINDOWS_SECURITY_AUDIT", {"pid": selected_pid, "source": "windows_security_audit", "task_id": task_id})
        print(f"Windows Security audit source active for PID {selected_pid}; task {task_id}.", flush=True)
        print("Query scope: Event 4663 for controlled_workspace/runtime_test/{dummy.txt,test_output.txt} and controlled_workspace/src/login.js only.", flush=True)
        observed = 0
        process_exit_at: float | None = None
        while True:
            try:
                rows = reader.query(after_record_id=last_record_id)
            except RuntimeError:
                print(SOURCE_UNAVAILABLE, flush=True)
                return 2
            rows.sort(key=lambda row: _number(row.get("record_id")) or 0)
            for row in rows:
                record_id = _number(row.get("record_id"))
                if record_id is not None:
                    last_record_id = max(last_record_id, record_id)
                action = normalize_4663_record(row)
                # The Event 4663's own PID must match the selected process.
                if action is None or action["pid"] is None or action["pid"] != selected_pid:
                    continue
                payload = {"task_id": task_id, **action}
                response = adapter.send_action(payload)
                observed += 1
                print(f"Observed audited READ {action['resource']} PID={action['pid']} record={action['metadata']['record_id']} => {response['decision']}", flush=True)
            if fixture is not None:
                if fixture.poll() is None:
                    time.sleep(max(0.2, args.interval))
                    continue
                if process_exit_at is None:
                    process_exit_at = time.monotonic()
                if observed or time.monotonic() - process_exit_at >= 10:
                    break
            else:
                time.sleep(max(0.2, args.interval))
    except KeyboardInterrupt:
        print("Stopping Windows Security audit monitor.", flush=True)
    finally:
        if fixture is not None and fixture.poll() is None:
            fixture.wait(timeout=5)
        adapter.set_mode("WINDOWS_MONITOR", {"source": "fastapi_lifespan_monitor"})
        print("Runtime mode restored to the FastAPI workspace monitor.", flush=True)
    if observed == 0:
        print("No qualifying Event 4663 was observed; no READ action was submitted.", flush=True)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Optional observation-only Windows Security 4663 audit source")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--pid", type=int, help="Observe Event 4663 records for this exact selected PID")
    choice.add_argument("--safe-test", action="store_true", help="Run the harmless controlled_workspace file activity fixture")
    parser.add_argument("--task-id", help="Existing AgentGate task ID; creates a restricted observation task if omitted")
    parser.add_argument("--api", default=API_BASE, help="AgentGate API base URL")
    parser.add_argument("--interval", type=float, default=0.5, help="Polling interval in seconds")
    args = parser.parse_args()
    if args.pid is not None and args.pid <= 0:
        parser.error("--pid must be a positive process ID")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
