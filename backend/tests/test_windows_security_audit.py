from app.services.windows_security_audit import (
    SOURCE_UNAVAILABLE,
    WindowsSecurityAuditReader,
    build_event_xpath,
    normalize_4663_record,
    parse_4663_xml,
)
from app.services.windows_monitor import WORKSPACE


def read_record(**overrides):
    record = {
        "event_id": 4663,
        "record_id": 8123,
        "timestamp": "2026-09-26T10:20:30.000Z",
        "process_id": "0x3039",
        "process_name": r"D:\Agent-Gate\.venv\Scripts\python.exe",
        "object_name": str(WORKSPACE / "runtime_test" / "dummy.txt"),
        "access_mask": "0x1",
        "access_rights": "ReadData",
        "subject_user_sid": "S-1-5-21-123",
        "subject_user_name": "student",
        "subject_domain_name": "LAPTOP",
        "subject_logon_id": "0x12345",
    }
    record.update(overrides)
    return record


def test_event_4663_readdata_becomes_attributed_read():
    action = normalize_4663_record(read_record())
    assert action is not None
    assert action["action_type"] == "READ"
    assert action["pid"] == 12345
    assert action["process_name"] == "python.exe"
    assert action["process_path"].endswith("python.exe")
    assert action["agent_source"] == "windows_security_audit"
    assert action["resource"] == "runtime_test/dummy.txt"
    assert action["metadata"]["source"] == "windows_security_audit"
    assert action["metadata"]["event_id"] == 4663
    assert action["metadata"]["record_id"] == 8123
    assert action["metadata"]["access_mask"] == "0x1"
    assert action["metadata"]["access_rights"] == ["ReadData"]
    assert action["metadata"]["access_rights_raw"] == "ReadData"
    assert action["metadata"]["evidence"] == "ReadData"
    assert action["metadata"]["subject"]["user_name"] == "student"


def test_write_data_does_not_become_read():
    assert normalize_4663_record(read_record(access_mask="0x2", access_rights="WriteData")) is None


def test_unrelated_and_path_prefix_lookalike_are_rejected():
    assert normalize_4663_record(read_record(object_name=r"D:\Agent-Gate\controlled_workspace\..\outside\secret.txt")) is None
    assert normalize_4663_record(read_record(object_name=r"D:\Agent-Gate\controlled_workspace_backup\secret.txt")) is None


def test_missing_process_fields_remain_unavailable():
    record = read_record(process_id=None, process_name=None)
    action = normalize_4663_record(record)
    assert action is not None
    assert action["pid"] is None
    assert action["process_name"] is None
    assert action["process_path"] is None
    assert action["metadata"]["process_attribution"] == "unavailable_in_event"


def test_non_4663_and_read_attributes_are_not_read_actions():
    assert normalize_4663_record(read_record(event_id=4656)) is None
    assert normalize_4663_record(read_record(access_mask="0x80", access_rights="ReadAttributes")) is None
    assert normalize_4663_record(read_record(access_mask=None, access_rights="Read")) is None


def test_reader_reports_unavailable_without_synthesizing_events():
    class Failed:
        returncode = 5
        stdout = ""
        stderr = "Access is denied"

    reader = WindowsSecurityAuditReader(command_runner=lambda *args, **kwargs: Failed())
    try:
        reader.query()
    except RuntimeError as exc:
        assert str(exc) == SOURCE_UNAVAILABLE
    else:
        raise AssertionError("unavailable Security log must not yield events")


def test_event_xml_parser_preserves_fields():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4663</EventID><EventRecordID>91</EventRecordID><TimeCreated SystemTime="2026-09-26T10:20:30Z"/></System><EventData><Data Name="ProcessId">0x3039</Data><Data Name="ProcessName">D:\\python.exe</Data><Data Name="ObjectName">D:\\Agent-Gate\\controlled_workspace\\runtime_test\\dummy.txt</Data><Data Name="AccessMask">0x1</Data><Data Name="SubjectUserName">student</Data></EventData></Event>'''
    rows = parse_4663_xml(xml)
    assert len(rows) == 1
    action = normalize_4663_record(rows[0])
    assert action is not None and action["metadata"]["record_id"] == 91
    assert action["metadata"]["subject"]["user_name"] == "student"


def test_xpath_is_limited_to_exact_controlled_fixture_paths():
    query = build_event_xpath((str(WORKSPACE / "runtime_test" / "dummy.txt"),))
    assert "EventID=4663" in query
    assert str(WORKSPACE / "runtime_test" / "dummy.txt") in query
    assert "controlled_workspace_backup" not in query
