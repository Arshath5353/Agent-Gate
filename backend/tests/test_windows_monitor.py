import ctypes
from pathlib import Path
import struct

from app.services.windows_monitor import ProcessIdentity, normalize_child_process, normalize_file_notification, parse_file_notify_buffer, WORKSPACE


def test_nested_controlled_workspace_changes_are_normalized_without_pid_attribution():
    event=normalize_file_notification(WORKSPACE/"runtime_test"/"test_output.txt","modified")
    assert event is not None
    assert event["action_type"]=="WRITE"
    assert event["pid"] is None
    assert event["metadata"]["observation_api"]=="ReadDirectoryChangesW"
    assert event["metadata"]["process_attribution"]=="unavailable_from_directory_notification"
    nested=normalize_file_notification(WORKSPACE/"real_agent_demo"/"nested"/"login.html","added")
    assert nested is not None
    assert nested["action_type"]=="WRITE"
    assert nested["resource"]=="real_agent_demo/nested/login.html"
    assert nested["metadata"]["filesystem_event"]=="created"
    assert nested["pid"] is None and nested["process_name"] is None
    assert normalize_file_notification(WORKSPACE/"real_agent_demo","added") is None
    assert normalize_file_notification(WORKSPACE.parent/"outside.txt","modified") is None
    assert normalize_file_notification(WORKSPACE/"runtime_test"/"dummy.txt","accessed") is None


def test_rename_notifications_are_distinguished_as_delete_and_write_evidence():
    old=normalize_file_notification(WORKSPACE/"real_agent_demo"/"old.html","renamed_old")
    new=normalize_file_notification(WORKSPACE/"real_agent_demo"/"new.html","renamed_new")
    assert old["action_type"]=="DELETE" and old["metadata"]["filesystem_event"]=="renamed_from"
    assert new["action_type"]=="WRITE" and new["metadata"]["filesystem_event"]=="renamed_to"


def test_windows_file_notification_buffer_parser():
    name="test_output.txt"
    encoded=name.encode("utf-16-le")
    raw=struct.pack("<III",0,3,len(encoded))+encoded
    buffer=ctypes.create_string_buffer(raw)
    assert parse_file_notify_buffer(buffer,len(raw))==[("modified",name)]


def test_child_process_event_contains_observed_pid_and_parent_evidence():
    parent=ProcessIdentity(100,"agent.exe","C:/agent.exe","2026-01-01T00:00:00+00:00",1,(101,))
    child=ProcessIdentity(101,"tool.exe","C:/tool.exe","2026-01-01T00:00:01+00:00",100,())
    event=normalize_child_process(child,parent)
    assert event["action_type"]=="EXECUTE" and event["pid"]==101
    assert event["process_name"]=="tool.exe"
    assert event["metadata"]["parent_pid"]==100
