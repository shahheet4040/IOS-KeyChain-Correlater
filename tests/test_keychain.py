import base64
import json
import pytest
from pathlib import Path

from correlator.keychain import load_keychain, candidates, HINT_WORDS
from correlator.sqlcipher_util import fingerprint


def test_load_keychain_success(tmp_path):
    key_bytes = b"\x01" * 32
    data = [
        {
            "service": "com.app.service",
            "account": "user1",
            "access_group": "group.com.app",
            "value_b64": base64.b64encode(key_bytes).decode("ascii"),
        }
    ]
    p = tmp_path / "keychain.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    rows, skipped = load_keychain(p)
    assert skipped == 0
    assert len(rows) == 1
    assert rows[0]["service"] == "com.app.service"
    assert rows[0]["account"] == "user1"
    assert rows[0]["access_group"] == "group.com.app"
    assert rows[0]["key_bytes"] == key_bytes
    assert rows[0]["fingerprint"] == fingerprint(key_bytes)


def test_load_keychain_skips_invalid_records(tmp_path):
    data = [
        "not a dict",
        {"service": "no_val"},
        {"service": "bad_b64", "value_b64": "!!!not_base64!!!"},
        {"service": "valid", "value_b64": base64.b64encode(b"ok").decode("ascii")},
    ]
    p = tmp_path / "kc.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    rows, skipped = load_keychain(p)
    assert skipped == 3
    assert len(rows) == 1
    assert rows[0]["key_bytes"] == b"ok"


def test_load_keychain_missing_optional_fields(tmp_path):
    # Record has only value_b64; service, account, access_group omitted or None
    data = [
        {
            "value_b64": base64.b64encode(b"\xaa" * 32).decode("ascii"),
        },
        {
            "service": None,
            "account": None,
            "access_group": None,
            "value_b64": base64.b64encode(b"\xbb" * 32).decode("ascii"),
        },
    ]
    p = tmp_path / "missing_fields.json"
    p.write_text(json.dumps(data), encoding="utf-8")

    rows, skipped = load_keychain(p)
    assert skipped == 0
    assert len(rows) == 2
    for r in rows:
        assert r["service"] == ""
        assert r["account"] == ""
        assert r["access_group"] == ""


def test_load_keychain_errors(tmp_path):
    missing = tmp_path / "nonexistent.json"
    with pytest.raises(ValueError, match="not found"):
        load_keychain(missing)

    not_json = tmp_path / "bad.json"
    not_json.write_text("invalid json {", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON format"):
        load_keychain(not_json)

    not_list = tmp_path / "dict.json"
    not_list.write_text("{\"key\": \"val\"}", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a JSON list"):
        load_keychain(not_list)


def test_candidates_filtering_and_scoring():
    k32_high = b"\x11" * 32
    k32_low = b"\x22" * 32
    k48 = b"\x33" * 48
    k16_ignore = b"\x44" * 16

    rows = [
        # Candidate 1: 32 bytes, hint score = 2 ("database" and "cipher")
        {
            "service": "database_service",
            "account": "cipher_account",
            "access_group": "group.a",
            "key_bytes": k32_high,
        },
        # Duplicate of Candidate 1 with lower hint score = 0
        {
            "service": "random_service",
            "account": "random_account",
            "access_group": "group.a",
            "key_bytes": k32_high,
        },
        # Candidate 2: 32 bytes, hint score = 1 ("key")
        {
            "service": "auth_key",
            "account": "user",
            "access_group": "group.b",
            "key_bytes": k32_low,
        },
        # Candidate 3: 48 bytes, hint score = 0
        {
            "service": "other",
            "account": "token",
            "access_group": "group.c",
            "key_bytes": k48,
        },
        # Candidate 4: 16 bytes, should be excluded
        {
            "service": "iv",
            "account": "salt",
            "access_group": "group.d",
            "key_bytes": k16_ignore,
        },
    ]

    cands = candidates(rows)
    # k16_ignore excluded, duplicate k32_high deduplicated
    assert len(cands) == 3

    # Check order: highest hint score first
    assert cands[0]["key_bytes"] == k32_high
    assert cands[0]["hint_score"] == 2
    assert cands[0]["service"] == "database_service"  # kept the higher scoring one

    assert cands[1]["key_bytes"] == k32_low
    assert cands[1]["hint_score"] == 1

    assert cands[2]["key_bytes"] == k48
    assert cands[2]["hint_score"] == 0


def test_candidates_case_insensitivity():
    k = b"\x55" * 32
    rows = [
        {
            "service": "DATABASE_CIPHER_SQLCIPHER",
            "account": "ENCRYPT_GRDB_KEY",
            "access_group": "group.test",
            "key_bytes": k,
        }
    ]
    cands = candidates(rows)
    assert len(cands) == 1
    # All 6 hint words present regardless of casing
    assert cands[0]["hint_score"] == len(HINT_WORDS)


def test_candidates_tie_breaking_by_fingerprint():
    # Two distinct 32-byte keys with same hint_score (0)
    # Fingerprints should determine ascending order
    k1 = b"\x01" * 32
    k2 = b"\x02" * 32
    fp1 = fingerprint(k1)
    fp2 = fingerprint(k2)

    rows = [
        {"service": "s", "account": "a", "access_group": "g", "key_bytes": k1},
        {"service": "s", "account": "a", "access_group": "g", "key_bytes": k2},
    ]
    cands = candidates(rows)
    assert len(cands) == 2
    if fp1 < fp2:
        assert cands[0]["fingerprint"] == fp1
        assert cands[1]["fingerprint"] == fp2
    else:
        assert cands[0]["fingerprint"] == fp2
        assert cands[1]["fingerprint"] == fp1


def test_candidates_empty():
    assert candidates([]) == []
    # Only invalid byte lengths
    assert candidates([
        {"service": "k", "account": "a", "access_group": "g", "key_bytes": b"\x00" * 10},
        {"service": "k", "account": "a", "access_group": "g", "key_bytes": b"\x00" * 64},
    ]) == []


def test_keychain_spec_assertions(tmp_path):
    """
    Spec: Only 32- and 48-byte values become candidates; the duplicate key appears once;
    the order is identical on two calls; the invalid-base64 row is counted in skipped.
    """
    k32_dup = b"\x11" * 32
    k48 = b"\x22" * 48
    k16_invalid = b"\x33" * 16
    k64_invalid = b"\x44" * 64

    data = [
        {"service": "org.example.dbkey", "account": "key1", "value_b64": base64.b64encode(k32_dup).decode("ascii")},
        {"service": "org.example.other", "account": "key1_dup", "value_b64": base64.b64encode(k32_dup).decode("ascii")},
        {"service": "cipher_svc", "account": "key2", "value_b64": base64.b64encode(k48).decode("ascii")},
        {"service": "short", "account": "key3", "value_b64": base64.b64encode(k16_invalid).decode("ascii")},
        {"service": "long", "account": "key4", "value_b64": base64.b64encode(k64_invalid).decode("ascii")},
        {"service": "corrupt", "account": "bad", "value_b64": "!!!not_base64!!!"},
    ]

    kc_file = tmp_path / "spec_test_keychain.json"
    kc_file.write_text(json.dumps(data), encoding="utf-8")

    rows, skipped = load_keychain(kc_file)
    # The invalid-base64 row is counted in skipped
    assert skipped == 1

    # Only 32- and 48-byte values become candidates; the duplicate key appears once
    cands_call1 = candidates(rows)
    assert len(cands_call1) == 2
    assert {len(c["key_bytes"]) for c in cands_call1} == {32, 48}
    assert sum(1 for c in cands_call1 if c["key_bytes"] == k32_dup) == 1

    # The order is identical on two calls
    cands_call2 = candidates(rows)
    assert cands_call1 == cands_call2

