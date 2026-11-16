import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
_venv_site = _root / ".venv" / "Lib" / "site-packages"
_src = _root / "src"
if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))
if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import json
import pytest
from correlator.evaluate import evaluate_report, run_evaluation

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "out" / "fake"
REPORT_PATH = FIXTURES_DIR / "report.json"
GROUND_TRUTH_PATH = FIXTURES_DIR / "ground_truth.json"


def test_evaluate_perfect_match():
    """Verify evaluation against actual ground truth yields 100% match."""
    res = evaluate_report(REPORT_PATH, GROUND_TRUTH_PATH)
    assert res["total_expected"] == 4
    assert res["total_found"] == 4
    assert res["matched"] == 4
    assert res["accuracy"] == 1.0
    assert res["precision"] == 1.0
    assert res["recall"] == 1.0

    for d in res["details"]:
        assert d["passed"] is True


def test_evaluate_missing_database():
    """Verify evaluation detects when a required database is missing from report."""
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        rep_data = json.load(f)

    # Filter out one database
    removed_relpath = rep_data["databases"][0]["relpath"]
    rep_data["databases"] = rep_data["databases"][1:]

    res = evaluate_report(rep_data, GROUND_TRUTH_PATH)
    assert res["total_expected"] == 4
    assert res["total_found"] == 3
    assert res["matched"] == 3
    assert res["accuracy"] == 0.75

    missing = [d for d in res["details"] if not d["passed"]]
    assert len(missing) == 1
    assert missing[0]["relpath"] == removed_relpath
    assert "Missing" in missing[0]["reason"]


def test_evaluate_wrong_fingerprint():
    """Verify evaluation detects mismatched key fingerprint."""
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        rep_data = json.load(f)

    decrypted_entry = next(d for d in rep_data["databases"] if d["status"] == "decrypted")
    orig_fp = decrypted_entry["key_fingerprint"]
    decrypted_entry["key_fingerprint"] = "deadbeef"

    res = evaluate_report(rep_data, GROUND_TRUTH_PATH)
    assert res["matched"] == 3
    assert res["accuracy"] == 0.75

    failed = [d for d in res["details"] if not d["passed"]]
    assert len(failed) == 1
    assert failed[0]["actual"]["key_fingerprint"] == "deadbeef"
    assert failed[0]["expected"]["key_fingerprint"] == orig_fp


def test_evaluate_wrong_status():
    """Verify evaluation detects incorrect triage status."""
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        rep_data = json.load(f)

    for d in rep_data["databases"]:
        if "ChatStorage.sqlite" in d["relpath"]:
            d["status"] = "decrypted"

    res = evaluate_report(rep_data, GROUND_TRUTH_PATH)
    assert res["matched"] == 3
    failed = [d for d in res["details"] if not d["passed"]]
    assert len(failed) == 1
    assert failed[0]["actual"]["status"] == "decrypted"
    assert failed[0]["expected"]["status"] == "plain"


def test_run_evaluation_cli_runner(capsys):
    """Verify run_evaluation CLI runner returns 0 for valid report and prints results."""
    code = run_evaluation(REPORT_PATH, GROUND_TRUTH_PATH)
    assert code == 0
    captured = capsys.readouterr()
    assert "100.0%" in captured.out
    assert "Precision:      1.00" in captured.out
    assert "Recall:         1.00" in captured.out
    assert "All ground truth assertions satisfied" in captured.out


def test_evaluate_spec_assertions():
    """
    Spec: Precision and recall are both 1.0 on the harness data.
    """
    metrics = evaluate_report(REPORT_PATH, GROUND_TRUTH_PATH)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0


if __name__ == "__main__":
    pytest.main([__file__])


