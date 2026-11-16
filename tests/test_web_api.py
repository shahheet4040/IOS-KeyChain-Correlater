from pathlib import Path
import plistlib
import hashlib
import pytest
from correlator.web.app import (
    crack_backup_password,
    create_case,
    detect_dump,
    download_case_pdf,
    get_pairing_records,
    get_system_overview,
    list_cases,
    serve_dashboard,
    triage_device,
)
from correlator.web.schemas import (
    CaseCreateRequest,
    CrackBackupRequest,
    DeviceTriageRequest,
)


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


def test_case_pdf_download():
    req = CaseCreateRequest(
        case_name="PDF Case Test",
        case_number="FSL-PDF-001",
        examiner="Analyst Lead",
        description="Testing PDF Report Generation",
    )
    res = create_case(req)
    case_id = res["case_id"]

    pdf_resp = download_case_pdf(case_id)
    assert pdf_resp.status_code == 200
    assert pdf_resp.media_type == "application/pdf"
    assert Path(pdf_resp.path).is_file()
    assert Path(pdf_resp.path).stat().st_size > 1000


def test_triage_device_endpoint():
    res = triage_device(DeviceTriageRequest(udid="test-unpaired-device"))
    assert res["udid"] == "test-unpaired-device"
    assert res["access_tier"] == "unpaired"
    assert "recommendation" in res


def test_crack_backup_endpoint(tmp_path):
    salt = b"test_salt_16bytes"
    pwd = "apple"
    exp = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 52, 32)
    manifest = tmp_path / "Manifest.plist"
    with open(manifest, "wb") as f:
        plistlib.dump({"Lockdown": {"PasswordSalt": salt, "PasswordHash": exp, "Iterations": 52}}, f)

    res = crack_backup_password(CrackBackupRequest(manifest_path=str(manifest), candidate_passwords=["apple"]))
    assert res["cracked"] is True
    assert res["password"] == "apple"


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

