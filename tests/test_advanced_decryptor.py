import base64
import hashlib
import json
from pathlib import Path
import plistlib
import sqlite3
import pytest
from sqlcipher3 import dbapi2 as sqlcipher

from correlator.advanced_decryptor import (
    OrphanRecoveryResult,
    carve_text_artifacts,
    deep_unlock_database,
    export_orphan_artifacts_csv,
    export_orphan_artifacts_json,
    generate_smart_keys,
    recover_orphan_database,
    scrape_container_secrets,
)
from correlator.engine import correlate_database
from correlator.scanner import DiscoveredDatabase


def test_scrape_container_secrets(tmp_path):
    """Verify secret scraping from plist, json, and text files."""
    container = tmp_path / "AppContainer"
    prefs = container / "Library" / "Preferences"
    prefs.mkdir(parents=True, exist_ok=True)

    # 1. Binary data in plist
    raw_key_32 = b"\xaa" * 32
    plist_path = prefs / "app_config.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump({"cipher_token": raw_key_32, "app_name": "TestApp"}, f)

    # 2. Hex string in json
    raw_key_48 = b"\xbb" * 48
    json_path = container / "settings.json"
    json_path.write_text(json.dumps({"secret_hex": raw_key_48.hex()}))

    # 3. Base64 string in txt
    raw_key_b64 = b"\xcc" * 32
    txt_path = container / "keys.txt"
    txt_path.write_text(f"MASTER_KEY={base64.b64encode(raw_key_b64).decode('utf-8')}")

    secrets = scrape_container_secrets(container)
    assert len(secrets) >= 3
    found_keys = [s["key_bytes"] for s in secrets]
    assert raw_key_32 in found_keys
    assert raw_key_48 in found_keys
    assert raw_key_b64 in found_keys


def test_generate_smart_keys():
    """Verify smart passcode and wordlist key derivations."""
    cands = generate_smart_keys(passwords=["secret99"], device_udid="00008030-001A")
    assert len(cands) > 10

    # Ensure SHA-256 of "secret99" is present
    expected_hash = hashlib.sha256(b"secret99").digest()
    assert any(c["key_bytes"] == expected_hash for c in cands)

    # Ensure common passcode "1234" is present
    hash_1234 = hashlib.sha256(b"1234").digest()
    assert any(c["key_bytes"] == hash_1234 for c in cands)


def test_carve_text_artifacts(tmp_path):
    """Verify carving of text, emails, and phone references from raw files."""
    test_bin = tmp_path / "raw_page.bin"
    # Construct binary payload containing mixed binary and human strings
    payload = (
        b"\x00\x01\x02\x03\x04"
        b"Hello Detective! Please contact suspect at +1-555-019-2834 regarding meeting. "
        b"\xff\xfe\x00\x00"
        b"Email archive sent to suspect@forensics-target.org immediately."
        b"\xaa\xbb\xcc\xdd"
        b'{"txid": "0x71c6187d384414f4", "amount": 25.5}'
        b"\x00\x00\x00"
    )
    test_bin.write_bytes(payload)

    artifacts = carve_text_artifacts(test_bin)
    assert len(artifacts) >= 1
    contents = " ".join([a["content"] for a in artifacts])
    assert "Detective" in contents or "suspect" in contents


def test_deep_unlock_database(tmp_path):
    """Verify end-to-end unlocking of an encrypted SQLCipher DB using smart dictionary."""
    db_file = tmp_path / "secure.db"
    key_bytes = hashlib.sha256(b"1234").digest()

    con = sqlcipher.connect(str(db_file))
    con.execute(f"PRAGMA key = \"x'{key_bytes.hex()}'\";")
    con.execute("CREATE TABLE chats(id INTEGER, msg TEXT);")
    con.execute("INSERT INTO chats VALUES (1, 'Secret meeting at midnight');")
    con.commit()
    con.close()

    # Attempt deep unlock
    res = deep_unlock_database(db_file, extra_passwords=["1234"])
    assert res["status"] == "decrypted"
    assert "chats" in res["tables"]
    assert res["key_bytes"] == key_bytes


def test_correlate_database_with_deep_recover(tmp_path):
    """Verify that correlate_database successfully uses deep_recover to unlock a database without keychain."""
    db_file = tmp_path / "orphan_app.db"
    key_bytes = hashlib.sha256(b"0000").digest()

    con = sqlcipher.connect(str(db_file))
    con.execute(f"PRAGMA key = \"x'{key_bytes.hex()}'\";")
    con.execute("CREATE TABLE records(x INT);")
    con.execute("INSERT INTO records VALUES (42);")
    con.commit()
    con.close()

    discovered = DiscoveredDatabase(
        path=db_file,
        relpath="var/mobile/orphan_app.db",
        name="orphan_app.db",
        size_bytes=db_file.stat().st_size,
    )

    # 1. Normal correlation without deep_recover -> locked
    res_normal = correlate_database(discovered, cands=[], deep_recover=False)
    assert res_normal.status == "not_decrypted"

    # 2. Deep recovery enabled -> decrypted via smart wordlist!
    res_deep = correlate_database(discovered, cands=[], deep_recover=True)
    assert res_deep.status == "decrypted"
    assert res_deep.key_bytes == key_bytes
    assert res_deep.recovery_method == "smart_sha256_derivation"


def test_recover_orphan_database_with_smart_pin(tmp_path):
    """Verify orphan recovery engine cracks locked DB via smart iOS PIN and exports plaintext."""
    db_file = tmp_path / "orphan_pin.db"
    key_bytes = hashlib.sha256(b"2580").digest()

    con = sqlcipher.connect(str(db_file))
    con.execute(f"PRAGMA key = \"x'{key_bytes.hex()}'\";")
    con.execute("CREATE TABLE evidence(id INT, note TEXT);")
    con.execute("INSERT INTO evidence VALUES (1, 'Sensitive evidence unlocked');")
    con.commit()
    con.close()

    out_dir = tmp_path / "orphan_out"
    res = recover_orphan_database(db_file, out_dir=out_dir)
    assert res.status == "decrypted"
    assert "evidence" in res.tables
    assert res.decrypted_export_path is not None
    assert Path(res.decrypted_export_path).is_file()

    # Verify decrypted export is readable as standard SQLite
    con_plain = sqlite3.connect(res.decrypted_export_path)
    cur = con_plain.cursor()
    cur.execute("SELECT note FROM evidence;")
    rows = cur.fetchall()
    con_plain.close()
    assert rows[0][0] == "Sensitive evidence unlocked"


def test_recover_orphan_database_fallback_carve(tmp_path):
    """Verify orphan recovery engine falls back to deep slack/WAL carving when key is missing."""
    db_file = tmp_path / "unknown_orphan.db"
    # Create locked DB with a completely unknown random 32-byte key
    unknown_key = b"\xde\xad" * 16

    con = sqlcipher.connect(str(db_file))
    con.execute(f"PRAGMA key = \"x'{unknown_key.hex()}'\";")
    con.execute("CREATE TABLE t(x);")
    con.commit()
    con.close()

    # Write companion WAL with recoverable text string
    wal_file = db_file.with_name(db_file.name + "-wal")
    wal_file.write_bytes(
        b"\x37\x7f\x06\x83" + b"\x00" * 28 +
        b"Call suspect at +1-555-839-2041 regarding wire transfer to wallet 0x71c6187d3844"
    )

    out_dir = tmp_path / "carve_out"
    res = recover_orphan_database(db_file, out_dir=out_dir, force_carve=True)
    assert res.status == "partially_carved"
    assert res.carved_artifacts_count >= 1
    assert res.evidence_json_path is not None
    assert Path(res.evidence_json_path).is_file()
    assert Path(res.evidence_csv_path).is_file()

    # Verify CSV has recovered content
    csv_text = Path(res.evidence_csv_path).read_text(encoding="utf-8")
    assert "+1-555-839-2041" in csv_text or "suspect" in csv_text
