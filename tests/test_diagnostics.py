import json
from pathlib import Path
import pytest

from correlator.diagnostics import diagnose_exception, format_diagnostic_box, run_system_doctor
from correlator.pipeline import IntegrityError


def test_diagnose_missing_root():
    err = ValueError("Root path does not exist: /nonexistent/path")
    diag = diagnose_exception(err, {"root": "/nonexistent/path"})
    assert diag["category"] == "input_path"
    assert "Extraction Folder Not Found" in diag["title"]
    assert len(diag["steps"]) >= 2
    assert diag["quick_command"] is not None

    box = format_diagnostic_box(diag)
    assert "EXTRACTION FOLDER NOT FOUND" in box
    assert "Recommended Fixes:" in box


def test_diagnose_invalid_ios_structure():
    err = ValueError("Given path does not look like an iOS filesystem")
    diag = diagnose_exception(err)
    assert diag["category"] == "filesystem_structure"
    assert "Invalid iOS Directory Structure" in diag["title"]


def test_diagnose_missing_keychain():
    err = ValueError("Keychain path is not a file: /missing.json")
    diag = diagnose_exception(err, {"keychain": "/missing.json"})
    assert diag["category"] == "keychain_path"
    assert "Keychain File Missing" in diag["title"]


def test_diagnose_corrupt_json():
    try:
        json.loads("{bad_json")
    except Exception as e:
        diag = diagnose_exception(e)
        assert diag["category"] == "keychain_syntax"
        assert "Invalid JSON" in diag["title"]


def test_diagnose_integrity_violation():
    err = IntegrityError("Evidence file was modified: ChatStorage.sqlite")
    diag = diagnose_exception(err)
    assert diag["category"] == "integrity"
    assert "Forensic Integrity Violation" in diag["title"]


def test_run_system_doctor():
    res = run_system_doctor(auto_fix=False)
    assert "healthy" in res
    assert "checks" in res
    assert len(res["checks"]) >= 3
    # Check that SQLCipher is PASS
    sqlc_check = next((c for c in res["checks"] if c["name"] == "SQLCipher Library"), None)
    assert sqlc_check is not None
    assert sqlc_check["status"] == "PASS"
