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

from correlator.engine import CorrelationResult, correlate, correlate_database, _prioritize_candidates_for_db
from correlator.scanner import DiscoveredDatabase, scan_extraction
from correlator.keychain import load_keychain, candidates
from correlator.sqlcipher_util import PROFILES, sha256_file


def test_correlate_synthetic_against_ground_truth():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"
    keychain_file = base / "keychain.json"
    ground_truth_file = base / "ground_truth.json"

    with open(ground_truth_file, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    results = correlate(extraction_root, keychain_file)
    assert len(results) == len(ground_truth)

    results_by_relpath = {r.relpath: r for r in results}

    for expected in ground_truth:
        relpath = expected["relpath"]
        assert relpath in results_by_relpath, f"Missing relpath in results: {relpath}"

        r = results_by_relpath[relpath]
        assert r.status == expected["expected_status"], (
            f"Status mismatch for {relpath}: got {r.status}, expected {expected['expected_status']}"
        )
        assert r.key_fingerprint == expected["expected_key_fingerprint"], (
            f"Fingerprint mismatch for {relpath}: got {r.key_fingerprint}, expected {expected['expected_key_fingerprint']}"
        )
        assert r.profile == expected["expected_profile"], (
            f"Profile mismatch for {relpath}: got {r.profile}, expected {expected['expected_profile']}"
        )
        assert r.sha256 is not None
        assert len(r.sha256) == 64

        d = r.to_dict()
        assert d["relpath"] == relpath
        assert d["status"] == expected["expected_status"]
        assert d["sha256"] == r.sha256


def test_candidate_prioritization_by_bundle_id():
    cands = [
        {"service": "com.other", "access_group": "group.other", "hint_score": 10, "fingerprint": "11111111"},
        {"service": "org.example.app_a.key", "access_group": "group.org.example.app_a", "hint_score": 0, "fingerprint": "22222222"},
    ]
    # Candidate matching bundle ID "org.example.app_a" should be prioritized above candidate with generic high score
    sorted_cands = _prioritize_candidates_for_db(cands, "org.example.app_a")
    assert sorted_cands[0]["fingerprint"] == "22222222"

    # When bundle ID is None, original order by hint_score is preserved
    unprioritized = _prioritize_candidates_for_db(cands, None)
    assert unprioritized[0]["fingerprint"] == "11111111"


def test_correlate_scratch_isolation_immutability(tmp_path):
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"
    keychain_file = base / "keychain.json"

    # Pre-hashes of all extraction files
    pre_digests = {p: sha256_file(p) for p in extraction_root.rglob("*") if p.is_file()}

    work_dir = tmp_path / "work"
    results = correlate(extraction_root, keychain_file, work_dir=work_dir)
    assert len(results) == 4

    # Post-hashes: pristine files must not have changed at all
    for p, pre_sha in pre_digests.items():
        assert sha256_file(p) == pre_sha, f"File altered during correlation: {p}"


def test_correlate_database_direct(tmp_path):
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"
    keychain_file = base / "keychain.json"

    dbs = scan_extraction(extraction_root)
    app_a = next(d for d in dbs if d.name in ("app_a.sqlite", "signal.sqlite"))

    rows, _ = load_keychain(keychain_file)
    cands = candidates(rows)

    # Correlate single database directly
    res = correlate_database(app_a, cands)
    assert res.status == "decrypted"
    assert res.key_fingerprint in ("95fb9d6f", "e53fcee6")
    assert res.profile in ("default", "signal_like")
    assert res.bundle_id in ("org.example.app_a", "org.whispersystems.signal")


def test_correlate_with_wrong_key_only():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    dbs = scan_extraction(extraction_root)
    app_a = next(d for d in dbs if d.name in ("app_a.sqlite", "signal.sqlite"))

    # Only provide wrong candidate keys
    dummy_cands = [
        {
            "key_bytes": b"\x99" * 32,
            "fingerprint": "99999999",
            "service": "wrong",
            "account": "wrong",
            "access_group": "wrong",
            "hint_score": 0,
        }
    ]

    res = correlate_database(app_a, dummy_cands)
    assert res.status == "not_decrypted"
    assert res.key_fingerprint is None
    assert res.profile is None


def test_correlate_spec_assertions(tmp_path):
    """
    Spec: app_a matches key A with profile default; app_b matches key B with profile compat3;
    orphan has no match; no database has two matches.
    """
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"
    keychain_file = base / "keychain.json"

    from correlator.pipeline import run
    report = run(extraction_root, keychain_file, tmp_path / "spec_correlate_run")
    db_map = {d["relpath"].split("/")[-1]: d for d in report["databases"]}

    # 1. app_a / signal matches key A
    app_a = db_map.get("app_a.sqlite") or db_map.get("signal.sqlite")
    assert app_a["status"] == "decrypted"
    assert app_a["profile"] in ("default", "signal_like")
    assert app_a["key_fingerprint"] in ("95fb9d6f", "e53fcee6")

    # 2. app_b / legacy matches key B with profile compat3
    app_b = db_map.get("app_b.sqlite") or db_map.get("legacy.sqlite")
    assert app_b["status"] == "decrypted"
    assert app_b["profile"] == "compat3"
    assert app_b["key_fingerprint"] in ("0bd8ce66", "9e43227b")

    # 3. orphan has no match
    orphan = db_map["orphan.db"]
    assert orphan["status"] == "not_decrypted"
    assert orphan["key_fingerprint"] is None
    assert orphan["profile"] is None

    # 4. No database has two matches (no ambiguous status)
    for db in report["databases"]:
        assert db["status"] != "ambiguous"
        if db["status"] == "decrypted":
            assert db["key_fingerprint"] is not None
        else:
            assert db["key_fingerprint"] is None


if __name__ == "__main__":
    pytest.main([__file__])


