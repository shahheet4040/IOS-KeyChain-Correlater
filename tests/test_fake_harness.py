import json
from pathlib import Path

from correlator.keychain import load_keychain, candidates
from correlator.sqlcipher_util import is_plain_sqlite, try_key, PROFILES


def test_harness_ground_truth():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    keychain_file = base / "keychain.json"
    ground_truth_file = base / "ground_truth.json"
    extraction_root = base / "extraction"

    assert keychain_file.exists()
    assert ground_truth_file.exists()
    assert extraction_root.exists()

    rows, skipped = load_keychain(keychain_file)
    assert skipped in (0, 1)
    cands = candidates(rows)

    with open(ground_truth_file, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    for item in ground_truth:
        db_path = extraction_root / item["relpath"]
        expected_status = item["expected_status"]
        expected_fp = item["expected_key_fingerprint"]
        expected_prof = item["expected_profile"]

        assert db_path.exists(), f"Database does not exist: {db_path}"

        if expected_status == "plain":
            assert is_plain_sqlite(db_path) is True
        else:
            assert is_plain_sqlite(db_path) is False

            # Check trying candidates
            matched_cands = []
            for c in cands:
                for prof in PROFILES:
                    if try_key(db_path, c["key_bytes"], prof):
                        matched_cands.append((c, prof))

            if expected_status == "decrypted":
                assert len(matched_cands) >= 1
                matched_fps = {c["fingerprint"] for c, prof in matched_cands}
                matched_profs = {prof["name"] for c, prof in matched_cands}
                assert expected_fp in matched_fps
                assert expected_prof in matched_profs
            elif expected_status == "not_decrypted":
                assert len(matched_cands) == 0
