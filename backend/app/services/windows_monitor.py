"""User-space Windows process identification and workspace change observation.

ReadDirectoryChangesW reports directory/file-name and last-write notifications, not
read operations and not the PID responsible for a notification. File events are
therefore submitted with pid/process identity unset and explicit attribution metadata.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Callable
from urllib.request import Request, urlopen

import psutil
from app.services.agent_adapter import AgentAdapter

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = (ROOT / "controlled_workspace").resolve()
SAFE_TEST_DIR = WORKSPACE / "runtime_test"
API_BASE = "http://127.0.0.1:8001/api"
ALLOWED_WATCH_DIRS = (WORKSPACE,)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    process_name: str | None
    process_path: str | None
    start_time: str | None
    parent_pid: int | None
    children: tuple[int, ...]

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "start_time": self.start_time,
            "parent_pid": self.parent_pid,
            "children": list(self.children),
        }


def identify_process(pid: int) -> ProcessIdentity:
    """Return process metadata without opening its files or inspecting memory."""
    process = psutil.Process(pid)
    with process.oneshot():
        name = _safe_call(process.name)
        exe = _safe_call(process.exe)
        started = _safe_call(process.create_time)
        parent = _safe_call(process.ppid)
        children = _safe_call(lambda: [child.pid for child in process.children(recursive=True)]) or []
    started_iso = datetime.fromtimestamp(started, timezone.utc).isoformat() if isinstance(started, (float, int)) else None
    return ProcessIdentity(pid, name, exe, started_iso, parent if isinstance(parent, int) else None, tuple(children))


def _safe_call(fn):
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return None


def normalize_file_notification(path: Path, notification: str, observed_at: str | None = None) -> dict | None:
    """Map real notifications for any file inside the controlled workspace."""
    try:
        resolved = path.resolve(strict=False)
        relative = resolved.relative_to(WORKSPACE).as_posix()
    except (OSError, ValueError, RuntimeError):
        return None
    if not relative or relative == ".":
        return None
    try:
        if resolved.is_dir():
            return None
    except OSError:
        pass
    mapping = {
        "added": ("WRITE", "created", "file-name-added notification; content write is not established"),
        "modified": ("WRITE", "modified", "last-write notification; writer PID is unavailable"),
        "removed": ("DELETE", "deleted", "file-name-removed notification; actor PID is unavailable"),
        "renamed_old": ("DELETE", "renamed_from", "rename-old-name notification; actor PID is unavailable"),
        "renamed_new": ("WRITE", "renamed_to", "rename-new-name notification; writer PID is unavailable"),
    }
    mapped = mapping.get(notification)
    if mapped is None:
        return None
    action_type, filesystem_event, evidence = mapped
    return {
        "action_type": action_type,
        "resource": relative,
        "timestamp": observed_at or datetime.now(timezone.utc).isoformat(),
        "pid": None,
        "process_name": None,
        "process_path": None,
        "metadata": {
            "source": "windows_monitor",
            "observation_api": "ReadDirectoryChangesW",
            "filesystem_event": filesystem_event,
            "evidence": evidence,
            "process_attribution": "unavailable_from_directory_notification",
            "observed_path": str(resolved),
        },
    }


def normalize_child_process(process: ProcessIdentity, parent: ProcessIdentity) -> dict:
    """Describe a child currently linked to the selected process, without command-line inspection."""
    return {
        "action_type": "EXECUTE",
        "resource": process.process_path or process.process_name or f"PID {process.pid}",
        "timestamp": process.start_time or datetime.now(timezone.utc).isoformat(),
        "pid": process.pid,
        "process_name": process.process_name,
        "process_path": process.process_path,
        "metadata": {
            "source": "windows_monitor",
            "observation_api": "psutil process-tree snapshot",
            "evidence": "new child PID observed under selected process during polling; this is not command-line or syscall telemetry",
            "parent_pid": parent.pid,
            "process_attribution": "parent_relationship_observed",
        },
    }


class WindowsMonitorAdapter(AgentAdapter):
    """Small HTTP adapter for existing AgentGate action and runtime-mode APIs."""
    def __init__(self, api_base: str = API_BASE):
        self.api_base = api_base.rstrip("/")

    def _post(self, path: str, payload: dict) -> dict:
        request = Request(
            self.api_base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST" if path != "/runtime/mode" else "PUT",
        )
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def set_mode(self, mode: str, details: dict | None = None) -> dict:
        return self._post("/runtime/mode", {"mode": mode, "details": details or {}})

    def create_task(self) -> str:
        response = self._post("/tasks", {
            "name": "Windows Runtime Observation",
            "description": "Observation-only controlled workspace runtime session",
            "allowed_scope": ["real_agent_demo/", "src/", "runtime_test/", "tests/", "package.json"],
        })
        return response["task_id"]

    def send_action(self, action: dict) -> dict:
        request = Request(
            self.api_base + "/actions/check",
            data=json.dumps(action).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


# FILE_NOTIFY_INFORMATION structure returned by ReadDirectoryChangesW.
class _FileNotifyInformation(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wintypes.DWORD),
        ("Action", wintypes.DWORD),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class _OffsetPair(ctypes.Structure):
    _fields_ = [("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD)]


class _OffsetUnion(ctypes.Union):
    _fields_ = [("offsets", _OffsetPair), ("pointer", ctypes.c_void_p)]


class _Overlapped(ctypes.Structure):
    _anonymous_ = ("position",)
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t), ("position", _OffsetUnion), ("hEvent", wintypes.HANDLE)]


def parse_file_notify_buffer(buffer: ctypes.Array, byte_count: int) -> list[tuple[str, str]]:
    """Parse Win32 FILE_NOTIFY_INFORMATION records, returning (action, relative name)."""
    actions = {1: "added", 2: "removed", 3: "modified", 4: "renamed_old", 5: "renamed_new"}
    entries = []
    offset = 0
    while offset + _FileNotifyInformation.FileName.offset <= byte_count:
        record = _FileNotifyInformation.from_buffer(buffer, offset)
        name_length = int(record.FileNameLength)
        name_start = offset + _FileNotifyInformation.FileName.offset
        if name_start + name_length > byte_count or name_length % 2:
            break
        name = ctypes.string_at(ctypes.addressof(buffer) + name_start, name_length).decode("utf-16-le", errors="strict")
        action = actions.get(int(record.Action))
        if action and name:
            entries.append((action, name))
        next_offset = int(record.NextEntryOffset)
        if not next_offset:
            break
        offset += next_offset
    return entries


class ReadDirectoryChangesWatcher:
    """Overlapped ReadDirectoryChangesW watcher for names + last-write only.

    LAST_ACCESS is intentionally excluded, so file reads cannot be mistaken for writes.
    """
    FILE_LIST_DIRECTORY = 0x0001
    SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
    OPEN_EXISTING = 3
    BACKUP_SEMANTICS = 0x02000000
    OVERLAPPED = 0x40000000
    CHANGE_FILE_NAME = 0x00000001
    CHANGE_DIR_NAME = 0x00000002
    CHANGE_LAST_WRITE = 0x00000010
    ACTION_FILTER = CHANGE_FILE_NAME | CHANGE_DIR_NAME | CHANGE_LAST_WRITE
    ERROR_IO_PENDING = 997
    WAIT_OBJECT_0 = 0
    INFINITE = 0xFFFFFFFF
    BUFFER_SIZE = 64 * 1024

    def __init__(self, directory: Path, callback: Callable[[str, str], None], watch_subtree: bool = True):
        self.directory = Path(directory)
        self.callback = callback
        self.watch_subtree = watch_subtree
        self.thread: threading.Thread | None = None
        self._stop_event = None
        self.ready = threading.Event()
        self.startup_error: Exception | None = None
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_api()

    def _configure_api(self):
        kernel = self._kernel
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateEventW.restype = wintypes.HANDLE
        kernel.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.ReadDirectoryChangesW.restype = wintypes.BOOL
        kernel.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID, wintypes.LPVOID]
        kernel.WaitForMultipleObjects.restype = wintypes.DWORD
        kernel.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.GetOverlappedResult.restype = wintypes.BOOL
        kernel.GetOverlappedResult.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
        kernel.CancelIoEx.restype = wintypes.BOOL
        kernel.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        kernel.CloseHandle.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.SetEvent.restype = wintypes.BOOL
        kernel.SetEvent.argtypes = [wintypes.HANDLE]

    def start(self):
        if os.name != "nt":
            raise OSError("ReadDirectoryChangesW is available only on Windows")
        if self.thread and self.thread.is_alive():
            return
        self._stop_event = self._kernel.CreateEventW(None, True, False, None)
        if not self._stop_event:
            raise ctypes.WinError(ctypes.get_last_error())
        self.thread = threading.Thread(target=self._run, name=f"ag-watch-{self.directory.name}", daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=5):
            self.stop()
            raise TimeoutError(f"Timed out opening ReadDirectoryChangesW for {self.directory}")
        if self.startup_error:
            self.stop()
            raise self.startup_error
        if not self.thread.is_alive():
            raise OSError(f"ReadDirectoryChangesW stopped while starting for {self.directory}")

    def stop(self):
        if self._stop_event:
            self._kernel.SetEvent(self._stop_event)
        if self.thread:
            self.thread.join(timeout=5)

    def _run(self):
        invalid = ctypes.c_void_p(-1).value
        directory_handle = self._kernel.CreateFileW(
            str(self.directory), self.FILE_LIST_DIRECTORY, self.SHARE_ALL, None,
            self.OPEN_EXISTING, self.BACKUP_SEMANTICS | self.OVERLAPPED, None,
        )
        if directory_handle == invalid:
            self.startup_error = ctypes.WinError(ctypes.get_last_error())
            print(f"Could not watch {self.directory}: {self.startup_error}", flush=True)
            self.ready.set()
            self._kernel.CloseHandle(self._stop_event)
            self._stop_event = None
            return
        self.ready.set()
        try:
            while True:
                buffer = ctypes.create_string_buffer(self.BUFFER_SIZE)
                completion = self._kernel.CreateEventW(None, True, False, None)
                if not completion:
                    raise ctypes.WinError(ctypes.get_last_error())
                overlapped = _Overlapped(hEvent=completion)
                ok = self._kernel.ReadDirectoryChangesW(
                    directory_handle, buffer, self.BUFFER_SIZE, self.watch_subtree, self.ACTION_FILTER,
                    None, ctypes.byref(overlapped), None,
                )
                error = ctypes.get_last_error()
                if not ok and error != self.ERROR_IO_PENDING:
                    self._kernel.CloseHandle(completion)
                    raise ctypes.WinError(error)
                handles = (wintypes.HANDLE * 2)(self._stop_event, completion)
                wait_result = self._kernel.WaitForMultipleObjects(2, handles, False, self.INFINITE)
                if wait_result == self.WAIT_OBJECT_0:
                    self._kernel.CancelIoEx(directory_handle, ctypes.byref(overlapped))
                    self._kernel.WaitForSingleObject(completion, self.INFINITE)
                    transferred = wintypes.DWORD(0)
                    self._kernel.GetOverlappedResult(directory_handle, ctypes.byref(overlapped), ctypes.byref(transferred), False)
                    self._kernel.CloseHandle(completion)
                    break
                if wait_result != self.WAIT_OBJECT_0 + 1:
                    self._kernel.CancelIoEx(directory_handle, ctypes.byref(overlapped))
                    self._kernel.CloseHandle(completion)
                    raise ctypes.WinError(ctypes.get_last_error())
                transferred = wintypes.DWORD(0)
                if self._kernel.GetOverlappedResult(directory_handle, ctypes.byref(overlapped), ctypes.byref(transferred), False):
                    for action, relative_name in parse_file_notify_buffer(buffer, transferred.value):
                        self.callback(action, relative_name)
                self._kernel.CloseHandle(completion)
        except Exception as exc:
            print(f"Directory watcher error for {self.directory}: {exc}", flush=True)
        finally:
            self._kernel.CloseHandle(directory_handle)
            if self._stop_event:
                self._kernel.CloseHandle(self._stop_event)
                self._stop_event = None


class WorkspaceRuntimeMonitor:
    """Watch only the controlled workspace and forward file evidence to AgentGate."""

    def __init__(self, task_id: str, submit_action: Callable[[dict], None], workspace: Path = WORKSPACE, watcher_factory=None):
        self.task_id = task_id
        self.submit_action = submit_action
        self.workspace = Path(workspace).resolve()
        self.watcher_factory = watcher_factory
        self.watcher: ReadDirectoryChangesWatcher | None = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self.watcher is not None and self.watcher.thread is not None and self.watcher.thread.is_alive()

    def start(self) -> bool:
        if os.name != "nt":
            return False
        with self._lock:
            if self.is_running:
                return True
            if not self.workspace.is_dir():
                raise FileNotFoundError(f"Controlled workspace does not exist: {self.workspace}")
            factory = self.watcher_factory or ReadDirectoryChangesWatcher
            watcher = factory(self.workspace, self._on_notification, watch_subtree=True)
            watcher.start()
            self.watcher = watcher
            return True

    def stop(self) -> None:
        with self._lock:
            watcher = self.watcher
            self.watcher = None
        if watcher is not None:
            watcher.stop()

    def _on_notification(self, notification: str, relative_name: str) -> None:
        event = normalize_file_notification(self.workspace / relative_name, notification)
        if event is None:
            return
        payload = {
            "task_id": self.task_id,
            "agent": "WINDOWS_MONITOR",
            "agent_source": "windows_monitor",
            "pid": None,
            "process_name": None,
            "process_path": None,
            "timestamp": event["timestamp"],
            "action_type": event["action_type"],
            "resource": event["resource"],
            "metadata": {
                **event["metadata"],
                "agent_source": "windows_monitor",
                "process_attribution": "unavailable_from_directory_notification",
            },
        }
        try:
            self.submit_action(payload)
        except Exception as exc:
            print(f"Could not forward filesystem event for {event['resource']}: {exc}", flush=True)


def run(args):
    if os.name != "nt":
        raise SystemExit("This monitor requires Windows (ReadDirectoryChangesW).")
    adapter = WindowsMonitorAdapter(args.api)
    safe_process = None
    if args.safe_test or args.safe_real_test:
        pid = None
    elif args.pid:
        pid = args.pid
    else:
        raise SystemExit("Provide --pid <selected process> or --safe-test.")

    task_id = args.task_id or adapter.create_task()
    selected_process: list[ProcessIdentity | None] = [identify_process(pid) if pid else None]

    def make_handler(directory: Path):
        def on_notification(notification: str, relative_name: str):
            process = selected_process[0]
            if process is None:
                return
            event = normalize_file_notification(directory / relative_name, notification)
            if event is None:
                return
            payload = {
                "task_id": task_id,
                "agent": "WINDOWS_MONITOR",
                "agent_source": "windows_monitor",
                # Do not attribute ReadDirectoryChangesW notifications to the selected PID.
                "pid": None,
                "process_name": None,
                "process_path": None,
                "timestamp": event["timestamp"],
                "action_type": event["action_type"],
                "resource": event["resource"],
                "metadata": {
                    **event["metadata"],
                    "agent_source": "windows_monitor",
                    "selected_process": process.as_dict(),
                    "process_attribution": "unavailable_from_directory_notification",
                },
            }
            response = adapter.send_action(payload)
            print(f"Observed {event['action_type']} {event['resource']} => {response['decision']} (PID attribution unavailable)", flush=True)
        return on_notification

    watchers = [ReadDirectoryChangesWatcher(directory, make_handler(directory), watch_subtree=True) for directory in ALLOWED_WATCH_DIRS if directory.is_dir()]
    for watcher in watchers:
        watcher.start()

    if args.safe_test or args.safe_real_test:
        fixture = "safe_real_agent_activity.py" if args.safe_real_test else "safe_file_activity.py"
        safe_process = subprocess.Popen([sys.executable, str(SAFE_TEST_DIR / fixture)], cwd=str(WORKSPACE), shell=False)
        pid = safe_process.pid
        selected_process[0] = identify_process(pid)
    process = selected_process[0]
    assert process is not None
    print("Selected process:")
    print(json.dumps(process.as_dict(), indent=2))
    adapter.set_mode("WINDOWS_MONITOR", {"pid": process.pid, "process_name": process.process_name, "process_path": process.process_path, "start_time": process.start_time, "task_id": task_id})
    print(f"Runtime mode WINDOWS_MONITOR; task {task_id}", flush=True)
    print("ReadDirectoryChangesW observes file-name and last-write changes only; READ events are not emitted.", flush=True)
    print("Watching controlled_workspace recursively; file-event PID attribution is unavailable from ReadDirectoryChangesW.", flush=True)
    try:
        known_children = set(process.children)
        while True:
            time.sleep(1)
            try:
                current = identify_process(pid)
            except psutil.NoSuchProcess:
                if safe_process:
                    time.sleep(0.5)
                    break
                print("Selected process exited; stopping monitor.", flush=True)
                break
            new_children = set(current.children) - known_children
            for child_pid in sorted(new_children):
                try:
                    child = identify_process(child_pid)
                    print("Observed child process:")
                    print(json.dumps(child.as_dict(), indent=2))
                    event = normalize_child_process(child, current)
                    payload = {
                        "task_id": task_id,
                        "agent": "WINDOWS_MONITOR",
                        "agent_source": "windows_monitor",
                        "pid": child.pid,
                        "process_name": child.process_name,
                        "process_path": child.process_path,
                        "timestamp": event["timestamp"],
                        "action_type": event["action_type"],
                        "resource": event["resource"],
                        "metadata": {**event["metadata"], "agent_source": "windows_monitor", "selected_process": current.as_dict()},
                    }
                    response = adapter.send_action(payload)
                    print(f"Observed child EXECUTE {event['resource']} => {response['decision']}", flush=True)
                except psutil.Error:
                    print(f"Child PID {child_pid} appeared but exited or became inaccessible before inspection.")
            known_children.update(current.children)
            if safe_process and safe_process.poll() is not None:
                time.sleep(0.5)
                break
    except KeyboardInterrupt:
        print("Stopping Windows monitor.", flush=True)
    finally:
        for watcher in watchers:
            watcher.stop()
        adapter.set_mode("WINDOWS_MONITOR", {"source": "fastapi_lifespan_monitor"})
        print("Runtime mode restored to the FastAPI workspace monitor.", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Observation-only Windows process and file-change monitor")
    parser.add_argument("--pid", type=int, help="PID of a process selected by the user")
    parser.add_argument("--task-id", help="Existing AgentGate task ID; creates an observation task if omitted")
    parser.add_argument("--api", default=API_BASE, help="AgentGate API base URL")
    test_mode = parser.add_mutually_exclusive_group()
    test_mode.add_argument("--safe-test", action="store_true", help="Launch the harmless Phase 1 controlled_workspace test process")
    test_mode.add_argument("--safe-real-test", action="store_true", help="Create and modify safe demo files under controlled_workspace/real_agent_demo")
    args = parser.parse_args()
    if (args.safe_test or args.safe_real_test) and args.pid:
        parser.error("Use a safe test mode or --pid, not both")
    run(args)


if __name__ == "__main__":
    main()
