"""
Self-diagnosing and error-handling module for iOS Keychain Correlator.
Analyzes exceptions, explains them in plain English, and provides actionable,
automated remediation steps so non-technical users can resolve issues instantly.
"""

import json
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple


def diagnose_exception(err: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Analyzes an exception and returns a structured diagnosis with actionable remediation steps.
    """
    err_str = str(err).strip()
    err_type = type(err).__name__
    ctx = context or {}

    root = ctx.get("root")
    keychain = ctx.get("keychain")
    out = ctx.get("out")

    # 1. Missing Extraction Root
    if "Root path does not exist" in err_str or (root and not Path(root).exists()):
        return {
            "title": "Extraction Folder Not Found",
            "category": "input_path",
            "severity": "error",
            "details": f"The extraction root '{root or 'provided path'}' could not be located.",
            "cause": "The directory path is misspelled, moved, or has not been generated yet.",
            "steps": [
                "Verify the directory path exists on your hard drive.",
                "To generate sample test data, run: python harness/make_fake_extraction.py --out out/fake",
                "Or in the GUI, click the '⚡ Load Demo Data' button to automatically fill valid paths."
            ],
            "quick_command": "python harness/make_fake_extraction.py --out out/fake",
        }

    # 2. Invalid iOS Structure
    if "does not look like an iOS filesystem" in err_str:
        return {
            "title": "Invalid iOS Directory Structure",
            "category": "filesystem_structure",
            "severity": "error",
            "details": "The directory does not contain standard iOS container directories.",
            "cause": "Expected 'private/var/mobile/Containers' inside the root folder, but it was not found.",
            "steps": [
                "Ensure you selected the root of the extracted filesystem.",
                "If inspecting an unzipped backup, ensure the path points to the parent of 'private/'.",
                "To test with realistic iOS containers, run: python harness/make_fake_extraction.py --out out/fake"
            ],
            "quick_command": "python harness/make_fake_extraction.py --out out/fake",
        }

    # 3. Missing or Corrupt Keychain File
    if "Keychain path is not a file" in err_str or (keychain and not Path(keychain).is_file()):
        return {
            "title": "Keychain File Missing",
            "category": "keychain_path",
            "severity": "error",
            "details": f"Keychain JSON file '{keychain or 'path'}' was not found.",
            "cause": "The keychain file path is invalid or has not been created yet.",
            "steps": [
                "Verify that the keychain JSON file exists at the specified path.",
                "Generate the sample keychain: python harness/make_fake_extraction.py --out out/fake",
                "Ensure the file contains valid JSON with Base64 encoded keys."
            ],
            "quick_command": "python harness/make_fake_extraction.py --out out/fake",
        }

    if isinstance(err, json.JSONDecodeError):
        return {
            "title": "Keychain File Corrupted (Invalid JSON)",
            "category": "keychain_syntax",
            "severity": "error",
            "details": f"JSON syntax error in keychain file: {err_str}",
            "cause": "The keychain file contains invalid formatting, unclosed quotes, or truncated text.",
            "steps": [
                "Open the keychain JSON in VS Code to check for red syntax errors.",
                "Ensure the file begins with '[' and ends with ']'.",
                "Regenerate a clean sample keychain: python harness/make_fake_extraction.py --out out/fake"
            ],
            "quick_command": "python harness/make_fake_extraction.py --out out/fake",
        }

    # 4. Forensic Evidence Integrity Error (File Hash Mismatch)
    if "IntegrityError" in err_type or "Evidence file was modified" in err_str:
        return {
            "title": "Forensic Integrity Violation Detected",
            "category": "integrity",
            "severity": "critical",
            "details": f"Evidence modification detected: {err_str}",
            "cause": "A database or WAL file was modified during processing, altering its SHA-256 hash.",
            "steps": [
                "Digital forensics strictly prohibits modifying original evidence files.",
                "Check if another program (like DB Browser for SQLite) has the file open and checkpointed the WAL.",
                "Close any database viewers and restore the original files from your backup or run: python harness/make_fake_extraction.py --out out/fake"
            ],
            "quick_command": "python harness/make_fake_extraction.py --out out/fake",
        }

    # 5. Missing sqlcipher3 Library
    if "No module named 'sqlcipher3'" in err_str or "sqlcipher3" in err_str.lower():
        return {
            "title": "SQLCipher Library Missing",
            "category": "dependency",
            "severity": "error",
            "details": "The required 'sqlcipher3-binary' package is not accessible in this Python session.",
            "cause": "You may be running system global Python rather than the project's virtual environment (.venv).",
            "steps": [
                "Run using the project virtual environment: .\\.venv\\Scripts\\python.exe",
                "Or activate the environment first: .\\.venv\\Scripts\\Activate.ps1",
                "Or run tests via the automated runner: .\\run_tests.bat"
            ],
            "quick_command": ".\\.venv\\Scripts\\python.exe -m correlator.cli --help",
        }

    # 6. Permission / Locked File Error
    if isinstance(err, PermissionError) or "Permission denied" in err_str or "locked" in err_str.lower():
        return {
            "title": "File Access or Permission Error",
            "category": "permissions",
            "severity": "error",
            "details": f"Access denied: {err_str}",
            "cause": "The file or directory is locked by another running program or lacks write permissions.",
            "steps": [
                "Close any open SQLite viewers, editors, or background processes holding file locks.",
                "Ensure the output directory ('--out') is in a folder you have write permissions to.",
                "If on Windows, ensure the folder is not marked Read-Only."
            ],
            "quick_command": None,
        }

    # Generic Fallback Diagnosis
    return {
        "title": f"Execution Error ({err_type})",
        "category": "general",
        "severity": "error",
        "details": err_str or "An unexpected exception occurred.",
        "cause": "An unhandled condition was encountered during processing.",
        "steps": [
            "Check that all input flags (--root, --keychain, --out) are correctly specified.",
            "Run diagnostics with: python -m correlator.cli doctor",
            "Review task logs in the output folder for deeper error traces."
        ],
        "quick_command": "python -m correlator.cli doctor",
    }


def format_diagnostic_box(diagnosis: Dict[str, Any]) -> str:
    """Renders a diagnostic report into an easy-to-read ASCII card."""
    lines = [
        "═" * 70,
        f" ❌ {diagnosis['title'].upper()}",
        "═" * 70,
        f" 📋 Details : {diagnosis['details']}",
        f" 🔍 Cause   : {diagnosis['cause']}",
        "─" * 70,
        " 💡 Recommended Fixes:"
    ]
    for i, step in enumerate(diagnosis.get("steps", []), 1):
        lines.append(f"    {i}. {step}")

    if diagnosis.get("quick_command"):
        lines.append("─" * 70)
        lines.append(f" 🛠️  Quick Command to Fix: {diagnosis['quick_command']}")
    lines.append("═" * 70)
    return "\n".join(lines)


def run_system_doctor(auto_fix: bool = False) -> Dict[str, Any]:
    """
    Performs comprehensive diagnostic health checks across the entire system.
    Returns status for each check and optionally applies automated fixes.
    """
    checks = []
    has_error = False

    # Check 1: Python Virtual Environment & SQLCipher
    try:
        from sqlcipher3 import dbapi2 as sqlcipher
        con = sqlcipher.connect(":memory:")
        con.execute("PRAGMA key = \"x'00'\";")
        con.close()
        checks.append({"name": "SQLCipher Library", "status": "PASS", "msg": "sqlcipher3 is operational"})
    except Exception as e:
        has_error = True
        checks.append({
            "name": "SQLCipher Library",
            "status": "FAIL",
            "msg": f"sqlcipher3 issue: {e}. Use .venv\\Scripts\\python.exe"
        })

    # Check 2: Demo Extraction and Data
    fake_dir = Path("out/fake").resolve()
    extraction_dir = fake_dir / "extraction"
    keychain_file = fake_dir / "keychain.json"

    data_ok = extraction_dir.is_dir() and keychain_file.is_file()
    if data_ok:
        checks.append({"name": "Demo Test Extraction", "status": "PASS", "msg": f"Found at {fake_dir}"})
    else:
        if auto_fix:
            try:
                from harness.make_fake_extraction import generate_fake_extraction
                generate_fake_extraction(fake_dir)
                checks.append({"name": "Demo Test Extraction", "status": "FIXED", "msg": f"Auto-generated at {fake_dir}"})
            except Exception as e:
                has_error = True
                checks.append({"name": "Demo Test Extraction", "status": "FAIL", "msg": f"Failed to generate: {e}"})
        else:
            has_error = True
            checks.append({
                "name": "Demo Test Extraction",
                "status": "WARN",
                "msg": f"Missing at {fake_dir}. Run: python -m correlator.cli doctor --fix"
            })

    # Check 3: Output write permissions
    test_out = Path("out/.write_test").resolve()
    try:
        test_out.parent.mkdir(parents=True, exist_ok=True)
        test_out.write_text("ok", encoding="utf-8")
        test_out.unlink()
        checks.append({"name": "Disk Write Permissions", "status": "PASS", "msg": "Writable out/ directory"})
    except Exception as e:
        has_error = True
        checks.append({"name": "Disk Write Permissions", "status": "FAIL", "msg": f"Cannot write to out/: {e}"})

    return {
        "healthy": not has_error,
        "checks": checks,
    }
