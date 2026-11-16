"""
Unit Tests for Court-Ready Pure-Python Forensic PDF Report Generation
====================================================================
Verifies that ForensicPDFBuilder and generate_case_pdf produce valid,
structurally sound PDF 1.4 documents without any third-party dependencies.
"""

from pathlib import Path
from correlator.pdf_report import ForensicPDFBuilder, generate_case_pdf


def test_pdf_builder_structure():
    builder = ForensicPDFBuilder(title="Test Verification Document")
    builder.draw_rect(36, 700, 540, 40, fill_rgb=(0.1, 0.2, 0.4))
    builder.draw_text("TEST HEADER", 48, 720, size=12, bold=True, color_rgb=(1.0, 1.0, 1.0))
    builder.add_section_header("1. Executive Details")
    builder.add_key_value("Case Identifier", "FSL-TEST-2026")
    builder.add_key_value("Lead Examiner", "Forensic Officer Test")

    headers = ["Item", "Description", "Status"]
    rows = [
        ["Device #1", "iPhone 14 Pro (AFU)", "FULL_BACKUP"],
        ["Database A", "Signal SQLCipher v4", "DECRYPTED"],
        ["Database B", "WeChat WCDB 64k", "DECRYPTED"],
    ]
    builder.add_table(headers, rows)

    pdf_bytes = builder.build_pdf_bytes()
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"/Type /Catalog" in pdf_bytes
    assert b"/Type /Pages" in pdf_bytes
    assert len(pdf_bytes) > 1000


def test_generate_case_pdf_end_to_end(tmp_path):
    case_data = {
        "case_id": "test-uuid-9999",
        "case_name": "Operation Sovereign Shield",
        "case_number": "FSL-2026-9041",
        "examiner": "Scientific Officer A",
        "status": "COMPLETED",
        "summary": {
            "total_devices": 1,
            "total_databases": 3,
            "total_decrypted": 2,
            "total_plain": 1,
            "total_locked": 0,
        },
        "devices": [{
            "device_name": "Suspect iPhone 13 Pro",
            "device_model": "iPhone14,2",
            "os_version": "iOS 16.5",
            "serial_number": "00008110-001234567890001E",
            "access_tier": "FULL_BACKUP (AFU)",
            "total_databases": 3,
        }],
        "databases": [
            {
                "name": "signal.sqlite",
                "bundle_id": "org.whispersystems.signal",
                "profile": "SQLCipher v4 (HMAC-SHA512)",
                "key_fingerprint": "a1b2c3d4",
                "status": "DECRYPTED",
            },
            {
                "name": "wechat.sqlite",
                "bundle_id": "com.tencent.xin",
                "profile": "WCDB (HMAC-SHA1 64k)",
                "key_fingerprint": "e5f6g7h8",
                "status": "DECRYPTED",
            },
        ],
        "evidence_samples": [
            {
                "database": "signal.sqlite",
                "table": "messages",
                "column": "body",
                "snippet": "Transfer the funds to escrow account immediately.",
            }
        ],
    }

    out_file = tmp_path / "case_report.pdf"
    res_path = generate_case_pdf(case_data, out_file)

    assert res_path.is_file()
    assert res_path.stat().st_size > 2000

    content = res_path.read_bytes()
    assert content.startswith(b"%PDF-1.4")
    assert b"OFFICIAL FORENSIC EXAMINATION REPORT" in content
    assert b"FSL-2026-9041" in content
    assert b"Operation Sovereign Shield" in content
    assert b"Scientific Officer A" in content
    assert b"%%EOF" in content
