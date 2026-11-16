import json
from pathlib import Path
from correlator.engine import correlate
from correlator.keychain import candidates, load_keychain
from correlator.pipeline import execute_pipeline

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "out" / "fake"
EXTRACTION_DIR = FIXTURES_DIR / "extraction"
KEYCHAIN_PATH = FIXTURES_DIR / "keychain.json"


def test_keychain_candidates_determinism():
    """Verify that keychain parsing and scoring produces identical results across runs."""
    records1, _ = load_keychain(KEYCHAIN_PATH)
    cands1 = candidates(records1)

    records2, _ = load_keychain(KEYCHAIN_PATH)
    cands2 = candidates(records2)

    assert len(cands1) == len(cands2)
    for c1, c2 in zip(cands1, cands2):
        assert c1["key_bytes"] == c2["key_bytes"]
        assert c1["fingerprint"] == c2["fingerprint"]
        assert c1["hint_score"] == c2["hint_score"]
        assert c1["service"] == c2["service"]
        assert c1["account"] == c2["account"]
        assert c1["access_group"] == c2["access_group"]


def test_correlation_repeatability():
    """Verify running correlate() twice returns identical results in identical order."""
    run1 = correlate(EXTRACTION_DIR, KEYCHAIN_PATH)
    run2 = correlate(EXTRACTION_DIR, KEYCHAIN_PATH)

    assert len(run1) == len(run2)
    for r1, r2 in zip(run1, run2):
        assert r1.relpath == r2.relpath
        assert r1.status == r2.status
        assert r1.key_fingerprint == r2.key_fingerprint
        assert r1.profile == r2.profile
        assert r1.bundle_id == r2.bundle_id
        assert r1.has_wal == r2.has_wal


def test_pipeline_report_repeatability(tmp_path):
    """Verify pipeline generates identical JSON report databases across runs."""
    out_dir1 = tmp_path / "run1"
    out_dir2 = tmp_path / "run2"

    res1 = execute_pipeline(
        extraction=EXTRACTION_DIR,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir1,
    )

    res2 = execute_pipeline(
        extraction=EXTRACTION_DIR,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir2,
    )

    with open(res1["report_json_path"], "r", encoding="utf-8") as f:
        data1 = json.load(f)

    with open(res2["report_json_path"], "r", encoding="utf-8") as f:
        data2 = json.load(f)

    # Database entries must be identical in content and order
    assert data1["databases"] == data2["databases"]

    # Counts must match
    assert data1["metadata"]["decrypted_count"] == data2["metadata"]["decrypted_count"]
    assert data1["metadata"]["plain_count"] == data2["metadata"]["plain_count"]
    assert data1["metadata"]["locked_count"] == data2["metadata"]["locked_count"]


def test_repeatability_five_runs_result_digest(tmp_path):
    """
    Spec: Five runs on the same input give the same result_digest.
    """
    from correlator.pipeline import run

    digests = []
    for i in range(5):
        out_dir = tmp_path / f"repeat_run_{i}"
        rep = run(EXTRACTION_DIR, KEYCHAIN_PATH, out_dir)
        d = rep["metadata"]["result_digest"]
        assert isinstance(d, str) and len(d) == 64
        digests.append(d)

    # All five digests must be completely identical
    assert len(set(digests)) == 1, f"Digests varied across 5 runs: {digests}"

