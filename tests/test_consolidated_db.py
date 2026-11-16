"""
Unit Tests for Consolidated Forensic Master Database Generator
==============================================================
Verifies creation, schema initialization, multi-source ingestion,
and endpoint downloads for `consolidated_case_evidence.sqlite`.
"""

from pathlib import Path
import sqlite3
import pytest

from correlator.consolidated_db import generate_consolidated_database, init_consolidated_schema
from correlator.web.app import create_case, download_case_consolidated_db, export_general_consolidated_db
from correlator.web.schemas import CaseCreateRequest


def test_init_consolidated_schema(tmp_path):
    db_file = tmp_path / "test_schema.sqlite"
    con = sqlite3.connect(str(db_file))
    init_consolidated_schema(con)

    cur = con.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    con.close()

    expected = [
        "case_info",
        "messages",
        "timeline_events",
        "locations",
        "keyword_alerts",
        "audit_trail",
        "decrypted_databases",
    ]
    for exp in expected:
        assert exp in tables


def test_generate_consolidated_database(tmp_path):
    # Setup mock decrypted database
    decrypted_dir = tmp_path / "decrypted"
    decrypted_dir.mkdir()
    signal_db = decrypted_dir / "signal.sqlite"
    s_con = sqlite3.connect(str(signal_db))
    s_con.execute("CREATE TABLE messages (id INT, body TEXT, date INT, sender TEXT);")
    s_con.execute("INSERT INTO messages VALUES (1, 'Secret meeting at midnight', 1700000000000, '+15550001');")
    s_con.commit()
    s_con.close()

    # Setup mock case data
    case_data = {
        "case_id": "CASE-TEST-123",
        "case_name": "Operation Falcon",
        "case_number": "FALCON/2026",
        "examiner": "Detective Miller",
        "description": "Consolidated export test",
        "devices": [{"device_id": "DEV-01"}],
    }

    # Setup mock provenance
    prov_steps = [
        {
            "step_number": 1,
            "phase": "Baseline Cryptographic Hashing",
            "action": "SHA256 Computed",
            "target": "signal.sqlite",
            "status": "success",
            "details": {"sha256": "abc123456789"},
        }
    ]

    out_file = tmp_path / "consolidated_case_evidence.sqlite"
    summary = generate_consolidated_database(
        output_path=out_file,
        case_data=case_data,
        decrypted_dirs=[decrypted_dir],
        provenance_steps=prov_steps,
    )

    assert out_file.is_file()
    assert summary["total_messages"] >= 1
    assert summary["total_audit_steps"] == 1
    assert summary["file_size_bytes"] > 1000

    # Query tables in generated SQLite database
    con = sqlite3.connect(f"file:{out_file.as_posix()}?mode=ro", uri=True)
    cur = con.cursor()

    c_row = cur.execute("SELECT case_name, case_number, examiner FROM case_info").fetchone()
    assert c_row == ("Operation Falcon", "FALCON/2026", "Detective Miller")

    m_row = cur.execute("SELECT app, content, sender FROM messages WHERE app='Signal'").fetchone()
    assert m_row[0] == "Signal"
    assert "Secret meeting" in m_row[1]
    assert m_row[2] == "+15550001"

    a_row = cur.execute("SELECT step_number, action FROM audit_trail").fetchone()
    assert a_row == (1, "SHA256 Computed")

    con.close()


def test_consolidated_db_api_endpoints():
    # 1. Create a case
    req = CaseCreateRequest(
        case_name="Consolidated Web Case",
        case_number="WEB-CONS-01",
        examiner="Cyber Specialist",
        description="Testing API consolidated database download",
    )
    res = create_case(req)
    case_id = res["case_id"]

    # 2. Call download_case_consolidated_db
    file_resp = download_case_consolidated_db(case_id)
    assert file_resp.status_code == 200
    assert file_resp.media_type == "application/vnd.sqlite3"
    assert Path(file_resp.path).is_file()
    assert Path(file_resp.path).stat().st_size > 1000

    # 3. Call export_general_consolidated_db
    gen_resp = export_general_consolidated_db()
    assert gen_resp.status_code == 200
    assert gen_resp.media_type == "application/vnd.sqlite3"
    assert Path(gen_resp.path).is_file()


def test_new_tables_exist(tmp_path):
    from correlator.consolidated_db import generate_consolidated_database, init_consolidated_schema
    import sqlite3
    db = tmp_path / "test.sqlite"
    con = sqlite3.connect(str(db))
    init_consolidated_schema(con)
    cur = con.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    assert "contacts" in tables
    assert "app_artifacts" in tables
    assert "file_registry" in tables
    con.close()


def test_file_registry_populated(tmp_path):
    # Setup a decrypted dir with a sqlite file
    decrypted_dir = tmp_path / "decrypted"
    decrypted_dir.mkdir()
    sample_db = decrypted_dir / "sample_evidence.sqlite"
    s_con = sqlite3.connect(str(sample_db))
    s_con.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, value TEXT);")
    s_con.execute("INSERT INTO data VALUES (1, 'test');")
    s_con.commit()
    s_con.close()

    out_file = tmp_path / "consolidated.sqlite"
    summary = generate_consolidated_database(
        output_path=out_file,
        decrypted_dirs=[decrypted_dir],
    )

    # Open result db, query file_registry
    import sqlite3 as _sqlite3
    con = _sqlite3.connect(str(out_file))
    cur = con.cursor()
    rows = cur.execute("SELECT file_name, mime_type, extracted_via FROM file_registry").fetchall()
    con.close()

    assert len(rows) >= 1
    file_names = [r[0] for r in rows]
    assert "sample_evidence.sqlite" in file_names
    # Check mime_type and extracted_via for that row
    for row in rows:
        if row[0] == "sample_evidence.sqlite":
            assert row[1] == "application/vnd.sqlite3"
            assert row[2] == "decryption"
