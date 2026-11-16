import json
from pathlib import Path
import pytest

from correlator.engine import CorrelationResult
from correlator.report import generate_json_report, generate_html_report, evaluate_report


def test_generate_json_report(tmp_path):
    results = [
        CorrelationResult(
            relpath="a/b.db",
            name="b.db",
            status="decrypted",
            sha256="12345678" * 8,
            key_fingerprint="12345678",
            profile="default",
        )
    ]
    report_file = tmp_path / "report.json"
    rep = generate_json_report(results, extraction_path=tmp_path, keychain_path=tmp_path / "kc.json", out_file=report_file)

    assert report_file.is_file()
    assert rep["metadata"]["total_databases"] == 1
    assert rep["metadata"]["decrypted_count"] == 1
    assert len(rep["databases"]) == 1
    assert rep["databases"][0]["name"] == "b.db"
    assert rep["databases"][0]["status"] == "decrypted"


def test_generate_html_report(tmp_path):
    results = [
        CorrelationResult(
            relpath="a/b.db",
            name="b.db",
            status="decrypted",
            bundle_id="com.app",
            sha256="abcdef" * 10,
            key_fingerprint="12345678",
            profile="default",
            has_wal=True,
        ),
        CorrelationResult(
            relpath="c/d.db",
            name="d.db",
            status="plain",
            bundle_id="com.plain",
            sha256="fedcba" * 10,
            has_wal=False,
        ),
    ]
    html_file = tmp_path / "report.html"
    content = generate_html_report(results, extraction_path=tmp_path, keychain_path=tmp_path / "kc.json", out_file=html_file)

    assert html_file.is_file()
    assert "<!DOCTYPE html>" in content
    assert "iOS Keychain Correlator Forensic Report" in content
    assert "b.db" in content
    assert "d.db" in content
    assert "badge-decrypted" in content
    assert "badge-plain" in content


def test_evaluate_report(tmp_path):
    report_data = {
        "metadata": {"total_databases": 2},
        "databases": [
            {
                "relpath": "path/a.db",
                "status": "decrypted",
                "key_fingerprint": "11111111",
                "profile": "default",
            },
            {
                "relpath": "path/b.db",
                "status": "plain",
                "key_fingerprint": None,
                "profile": None,
            },
        ],
    }
    report_file = tmp_path / "report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f)

    ground_truth = [
        {
            "relpath": "path/a.db",
            "expected_status": "decrypted",
            "expected_key_fingerprint": "11111111",
            "expected_profile": "default",
        },
        {
            "relpath": "path/b.db",
            "expected_status": "plain",
            "expected_key_fingerprint": None,
            "expected_profile": None,
        },
    ]
    gt_file = tmp_path / "gt.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f)

    eval_res = evaluate_report(report_file, gt_file)
    assert eval_res["total_expected"] == 2
    assert eval_res["matched"] == 2
    assert eval_res["accuracy"] == 1.0


def test_evaluate_report_mismatch(tmp_path):
    report_data = [
        {
            "relpath": "path/a.db",
            "status": "decrypted",
            "key_fingerprint": "WRONG_FP",
            "profile": "default",
        }
    ]
    report_file = tmp_path / "report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f)

    ground_truth = [
        {
            "relpath": "path/a.db",
            "expected_status": "decrypted",
            "expected_key_fingerprint": "11111111",
            "expected_profile": "default",
        }
    ]
    gt_file = tmp_path / "gt.json"
    with open(gt_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f)

    eval_res = evaluate_report(report_file, gt_file)
    assert eval_res["total_expected"] == 1
    assert eval_res["matched"] == 0
    assert eval_res["accuracy"] == 0.0
