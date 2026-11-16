import json
from pathlib import Path
import pytest
import sqlite3

from correlator.case_manager import CaseManager


def test_create_and_list_cases(tmp_path: Path):
    cm = CaseManager(tmp_path)
    case_id = cm.create_case(
        case_name="Operation CyberShield",
        case_number="FSL/2026/089",
        examiner="Dr. Forensic Officer",
        description="Seized iPhone investigation",
    )

    assert isinstance(case_id, str)
    cases = cm.list_cases()
    assert len(cases) == 1
    assert cases[0]["case_name"] == "Operation CyberShield"
    assert cases[0]["case_number"] == "FSL/2026/089"

    case_data = cm.get_case(case_id)
    assert case_data["examiner"] == "Dr. Forensic Officer"
    assert case_data["status"] == "active"


def test_add_device_and_results(tmp_path: Path):
    cm = CaseManager(tmp_path)
    case_id = cm.create_case("Case 1", "001", "Officer A")

    dev_id = cm.add_device(
        case_id=case_id,
        device_name="Suspect iPhone 14",
        device_model="iPhone14,7",
        os_version="16.5",
        serial_number="DNPZ1234ABCD",
        source_type="cellebrite",
    )

    devices = cm.list_devices(case_id)
    assert len(devices) == 1
    assert devices[0]["device_name"] == "Suspect iPhone 14"

    # Add mock analysis result
    res_id = cm.add_analysis_result(
        case_id=case_id,
        device_id=dev_id,
        result_data={
            "total_databases": 5,
            "decrypted_count": 3,
            "plain_count": 1,
            "locked_count": 1,
        },
    )
    assert isinstance(res_id, str)

    results = cm.get_analysis_results(case_id, device_id=dev_id)
    assert len(results) == 1
    assert results[0]["data"]["decrypted_count"] == 3


def test_generate_case_report_and_export(tmp_path: Path):
    cm = CaseManager(tmp_path)
    case_id = cm.create_case("Case Report Test", "REP/2026", "Officer B")
    dev_id = cm.add_device(case_id, "iPhone", "iPhone13", "15.4", "SER1", "itunes")
    cm.add_analysis_result(case_id, dev_id, {
        "total_databases": 10,
        "decrypted_count": 7,
        "plain_count": 2,
        "locked_count": 1,
    })

    rep = cm.generate_case_report(case_id)
    assert rep["summary"]["total_devices"] == 1
    assert rep["summary"]["total_decrypted"] == 7
    assert rep["summary"]["total_databases"] == 10

    # Test export
    export_zip = tmp_path / "case_export.zip"
    exported_path = cm.export_case(case_id, export_zip)
    assert exported_path.is_file()
    assert exported_path.suffix == ".zip"


def test_cross_device_search(tmp_path: Path):
    cm = CaseManager(tmp_path)
    case_id = cm.create_case("Search Case", "SRC/01", "Examiner")
    dev_id = cm.add_device(case_id, "DevA", "ModA", "16.0", "S1", "live_usb")

    # Put a mock SQLite DB inside the device directory
    dev_dir = tmp_path / "cases" / case_id / "devices" / dev_id
    db_file = dev_dir / "contacts.sqlite"
    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("CREATE TABLE contacts (name TEXT, phone TEXT);")
    cur.execute("INSERT INTO contacts VALUES ('Target Suspect', '+91-9876543210');")
    con.commit()
    con.close()

    hits = cm.cross_device_search(case_id, "Target Suspect")
    assert len(hits) == 1
    assert hits[0]["device_id"] == dev_id
    assert hits[0]["column"] == "name"
    assert "Target Suspect" in hits[0]["matched_value"]
