import json
from pathlib import Path
import pytest

from correlator.correlate import correlate as correlate_db
from correlator.inventory import scan_containers
from correlator.keychain import candidates, load_keychain
from correlator.pipeline import IntegrityError, run
from correlator.report import write_html, write_json
from correlator.sqlcipher_util import PROFILES
from correlator.triage import classify, find_databases

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "out" / "fake"
EXTRACTION_ROOT = FIXTURES_DIR / "extraction"
KEYCHAIN_FILE = FIXTURES_DIR / "keychain.json"


def test_inventory_scan_containers():
    assert EXTRACTION_ROOT.exists()
    containers = scan_containers(EXTRACTION_ROOT)
    assert isinstance(containers, dict)
    assert len(containers) >= 4

    # Check AppGroup AAAA-1111
    assert "AAAA-1111" in containers
    assert containers["AAAA-1111"]["kind"] == "app_group"
    assert containers["AAAA-1111"]["bundle_id"] in ("org.example.app_a", "org.whispersystems.signal")

    # Check Application BBBB-2222
    assert "BBBB-2222" in containers
    assert containers["BBBB-2222"]["kind"] == "app_data"
    assert containers["BBBB-2222"]["bundle_id"] == "org.example.app_b"


def test_inventory_invalid_root(tmp_path):
    # Non-iOS directory structure
    empty_dir = tmp_path / "not_ios"
    empty_dir.mkdir()
    with pytest.raises(ValueError, match="does not look like an iOS filesystem"):
        scan_containers(empty_dir)


def test_triage_find_databases():
    dbs = find_databases(EXTRACTION_ROOT)
    assert isinstance(dbs, list)
    assert len(dbs) == 4

    # No companions
    for p in dbs:
        assert not p.endswith("-wal")
        assert not p.endswith("-shm")
        assert not p.endswith("-journal")
        assert "/" in p or "\\" in p

    # Sorted
    assert dbs == sorted(dbs)


def test_triage_classify():
    chat_storage = EXTRACTION_ROOT / "private/var/mobile/Containers/Shared/AppGroup/CCCC-3333/ChatStorage.sqlite"
    app_a = next(p for p in EXTRACTION_ROOT.rglob("*.sqlite") if p.name in ("app_a.sqlite", "signal.sqlite"))

    assert classify(chat_storage) == "plain"
    assert classify(app_a) == "not_plain"


def test_correlate_single_db():
    app_a = next(p for p in EXTRACTION_ROOT.rglob("*.sqlite") if p.name in ("app_a.sqlite", "signal.sqlite"))
    records, _ = load_keychain(KEYCHAIN_FILE)
    cands = candidates(records)

    status, matches = correlate_db(app_a, cands)
    assert status == "decrypted"
    assert len(matches) == 1
    assert matches[0]["key_fingerprint"] in ("95fb9d6f", "e53fcee6")
    assert matches[0]["profile"] in ("default", "signal_like")


def test_report_write_json_and_html(tmp_path):
    test_data = {
        "databases": [
            {
                "status": "decrypted",
                "relpath": "path/to/test.sqlite",
                "bundle_id": "com.example.test",
                "key_fingerprint": "12345678",
                "profile": "default",
            }
        ]
    }
    json_out = tmp_path / "test_report.json"
    html_out = tmp_path / "test_report.html"

    write_json(test_data, json_out)
    assert json_out.is_file()
    raw_json = json_out.read_text(encoding="utf-8")
    assert '"status": "decrypted"' in raw_json

    write_html(test_data, html_out)
    assert html_out.is_file()
    html_content = html_out.read_text(encoding="utf-8")
    assert "com.example.test" in html_content
    assert "http://" not in html_content
    assert "https://" not in html_content


def test_pipeline_run(tmp_path):
    out_dir = tmp_path / "pipeline_run_out"
    rep = run(EXTRACTION_ROOT, KEYCHAIN_FILE, out_dir=out_dir)
    assert isinstance(rep, dict)
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "report.html").is_file()
    assert "result_digest" in rep["metadata"]
    assert len(rep["metadata"]["result_digest"]) == 64
    assert not (out_dir / "work").exists()


def test_pipeline_run_keep_work(tmp_path):
    out_dir = tmp_path / "pipeline_keep_work_out"
    rep = run(EXTRACTION_ROOT, KEYCHAIN_FILE, out_dir=out_dir, keep_work=True)
    assert isinstance(rep, dict)
    work_dir = out_dir / "work"
    assert work_dir.is_dir()

    # Check that work/<index>/pristine and scratch exist
    indices = [p.name for p in work_dir.iterdir() if p.is_dir()]
    assert len(indices) == 4
    for idx in indices:
        pristine = work_dir / idx / "pristine"
        scratch = work_dir / idx / "scratch"
        assert pristine.is_dir()
        assert scratch.is_dir()

        # Both pristine and scratch contain the main database
        pristine_files = [f.name for f in pristine.iterdir()]
        scratch_files = [f.name for f in scratch.iterdir()]
        assert any(f.endswith(".sqlite") or f.endswith(".db") for f in pristine_files)
        assert any(f.endswith(".sqlite") or f.endswith(".db") for f in scratch_files)


def test_pipeline_run_step1_validation(tmp_path):
    # Nonexistent root
    with pytest.raises(ValueError, match="Root path does not exist"):
        run(tmp_path / "nonexistent", KEYCHAIN_FILE, out_dir=tmp_path / "out")

    # Nonexistent keychain
    with pytest.raises(ValueError, match="Keychain path is not a file"):
        run(EXTRACTION_ROOT, tmp_path / "missing_kc.json", out_dir=tmp_path / "out")

