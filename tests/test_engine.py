import json
from pathlib import Path

from correlator.engine import correlate, _prioritize_candidates_for_db


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

        # Check dictionary conversion
        d = r.to_dict()
        assert d["relpath"] == relpath
        assert d["status"] == expected["expected_status"]


def test_candidate_prioritization():
    cands = [
        {"service": "com.other", "access_group": "group.other", "hint_score": 1, "fingerprint": "11111111"},
        {"service": "org.example.app_a.key", "access_group": "group.org.example.app_a", "hint_score": 0, "fingerprint": "22222222"},
    ]
    # For bundle_id "org.example.app_a", the second candidate should be prioritized first
    sorted_cands = _prioritize_candidates_for_db(cands, "org.example.app_a")
    assert sorted_cands[0]["fingerprint"] == "22222222"
