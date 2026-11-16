from pathlib import Path
import plistlib
import hashlib
import pytest
from correlator.web.app import (
    compare_cases_endpoint,
    crack_backup_password,
    create_case,
    detect_dump,
    download_case_pdf,
    export_case_geojson,
    export_case_jsonl,
    export_case_xlsx,
    get_case_provenance,
    get_geospatial,
    get_pairing_records,
    get_system_overview,
    get_timeline,
    get_watchlist_alerts,
    list_cases,
    serve_dashboard,
    triage_device,
    trigger_watchlist_scan,
)
from correlator.web.schemas import (
    CaseCreateRequest,
    CrackBackupRequest,
    DeviceTriageRequest,
    WatchlistScanRequest,
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


def test_case_provenance_endpoint():
    req = CaseCreateRequest(
        case_name="Provenance Case",
        case_number="FSL-PROV-99",
        examiner="Chief Officer",
        description="Testing step-by-step mapping",
    )
    case_res = create_case(req)
    cid = case_res["case_id"]

    prov = get_case_provenance(cid)
    assert prov["case_id"] == cid
    assert "provenance_map" in prov
    assert isinstance(prov["provenance_map"], list)


def test_timeline_endpoint():
    res = get_timeline(max_records=100)
    assert "total_events" in res
    assert "app_breakdown" in res
    assert "events" in res
    assert isinstance(res["events"], list)


def test_geospatial_endpoint():
    res = get_geospatial()
    assert "total_points" in res
    assert "center" in res
    assert "points" in res
    assert isinstance(res["points"], list)


def test_watchlist_endpoints():
    alerts_res = get_watchlist_alerts()
    assert "total_alerts" in alerts_res
    assert "severity_summary" in alerts_res
    assert "category_summary" in alerts_res
    assert isinstance(alerts_res["alerts"], list)

    scan_req = WatchlistScanRequest(custom_keywords=["test_target", "operation_alpha"])
    scan_res = trigger_watchlist_scan(scan_req)
    assert "total_alerts" in scan_res
    assert "severity_summary" in scan_res
    assert "category_summary" in scan_res
    assert isinstance(scan_res["alerts"], list)


def test_export_formats_endpoints():
    req = CaseCreateRequest(
        case_name="Export Web Case",
        case_number="WEB-EXP-01",
        examiner="Chief Officer",
        description="Testing export endpoints",
    )
    res = create_case(req)
    cid = res["case_id"]

    # XLSX / CSV-ZIP
    x_resp = export_case_xlsx(cid)
    assert x_resp.status_code == 200
    assert Path(x_resp.path).is_file()

    # JSONL
    j_resp = export_case_jsonl(cid)
    assert j_resp.status_code == 200
    assert Path(j_resp.path).is_file()

    # GeoJSON
    g_resp = export_case_geojson(cid)
    assert g_resp.status_code == 200
    assert Path(g_resp.path).is_file()


def test_case_compare_endpoint():
    req1 = CaseCreateRequest(case_name="Alpha", case_number="CMP-01", examiner="Officer A")
    c1 = create_case(req1)["case_id"]

    req2 = CaseCreateRequest(case_name="Beta", case_number="CMP-02", examiner="Officer B")
    c2 = create_case(req2)["case_id"]

    res = compare_cases_endpoint({"case_id_a": c1, "case_id_b": c2})
    assert "metadata" in res
    assert "messages" in res
    assert "locations" in res
    assert "alerts" in res
    assert "timeline" in res




