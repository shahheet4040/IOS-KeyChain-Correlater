from pathlib import Path
import pytest
from correlator.web.app import (
    create_case,
    detect_dump,
    get_pairing_records,
    get_system_overview,
    list_cases,
    serve_dashboard,
)
from correlator.web.schemas import CaseCreateRequest


def test_get_system_overview():
    res = get_system_overview()
    assert res["status"] == "operational"
    assert "total_cases" in res
    assert "pairing_records_found" in res


def test_case_lifecycle():
    req = CaseCreateRequest(
        case_name="Web Test Case",
        case_number="WEB/2026/01",
        examiner="Web Officer",
        description="Testing web API",
    )
    res = create_case(req)
    assert "case_id" in res
    assert res["message"] == "Case created successfully"

    cases = list_cases()
    assert any(c["case_number"] == "WEB/2026/01" for c in cases)


def test_pairing_records_endpoint():
    res = get_pairing_records()
    assert isinstance(res, list)


def test_detect_dump_endpoint(tmp_path: Path):
    test_dir = tmp_path / "mock_cellebrite"
    test_dir.mkdir()
    (test_dir / "report.xml").write_text("<xml/>", encoding="utf-8")
    (test_dir / "UFEDReaderReport").mkdir()

    res = detect_dump({"path": str(test_dir)})
    assert res["detected_format"] == "cellebrite"


def test_serve_dashboard():
    res = serve_dashboard()
    assert res is not None
