import json
import sqlite3
from pathlib import Path
from correlator.cli import main, format_table
from correlator.engine import CorrelationResult


def test_format_table():
    sample_results = [
        CorrelationResult(
            relpath="a/b/c.db",
            name="c.db",
            status="decrypted",
            bundle_id="com.example.app",
            key_fingerprint="12345678",
            profile="default",
            has_wal=True,
        ),
        CorrelationResult(
            relpath="x/y/z.db",
            name="z.db",
            status="plain",
            container_uuid="UUID-9999",
            has_wal=False,
        ),
    ]
    table = format_table(sample_results)
    assert "[DECRYPTED]" in table
    assert "[PLAIN]" in table
    assert "com.example.app" in table
    assert "UUID-9999" in table
    assert "12345678" in table
    assert "default" in table
    assert "Yes" in table
    assert "No" in table


def test_cli_missing_paths(tmp_path):
    missing_dir = tmp_path / "missing_dir"
    missing_file = tmp_path / "missing_kc.json"

    # Extraction missing
    ret = main(["--extraction", str(missing_dir), "--keychain", str(missing_file)])
    assert ret == 1

    # Extraction exists, keychain missing
    missing_dir.mkdir()
    ret = main(["--extraction", str(missing_dir), "--keychain", str(missing_file)])
    assert ret == 1


def test_cli_end_to_end(tmp_path):
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"
    keychain_file = base / "keychain.json"

    report_file = tmp_path / "report.json"
    export_dir = tmp_path / "exported"

    ret = main([
        "--extraction", str(extraction_root),
        "--keychain", str(keychain_file),
        "--report", str(report_file),
        "--export-dir", str(export_dir),
    ])
    assert ret == 0

    # Verify report JSON
    assert report_file.is_file()
    with open(report_file, "r", encoding="utf-8") as f:
        report_data = json.load(f)
    
    databases = report_data["databases"] if isinstance(report_data, dict) and "databases" in report_data else report_data
    assert len(databases) == 4

    decrypted_items = [item for item in databases if item["status"] == "decrypted"]
    assert len(decrypted_items) == 2

    # Verify decrypted export directory
    assert export_dir.is_dir()
    for item in decrypted_items:
        exported_path = export_dir / item["relpath"]
        assert exported_path.is_file()

        # Check that the exported file is plain SQLite readable by standard sqlite3
        con = sqlite3.connect(str(exported_path))
        rows = con.execute("SELECT count(*) FROM messages;").fetchone()
        con.close()
        assert rows[0] >= 10


def test_cli_subcommand_run(tmp_path):
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"
    keychain_file = base / "keychain.json"

    out_dir = tmp_path / "out_run"
    ret = main([
        "run",
        "--extraction", str(extraction_root),
        "--keychain", str(keychain_file),
        "--out-dir", str(out_dir),
    ])
    assert ret == 0
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "report.html").is_file()


def test_cli_subcommand_evaluate():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    report_file = base / "report.json"
    gt_file = base / "ground_truth.json"

    ret = main([
        "evaluate",
        "--report", str(report_file),
        "--ground-truth", str(gt_file),
    ])
    assert ret == 0
