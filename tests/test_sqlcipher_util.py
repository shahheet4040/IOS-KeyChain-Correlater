import hashlib
import sqlite3
import pytest
from sqlcipher3 import dbapi2 as sqlcipher
from pathlib import Path

from correlator.sqlcipher_util import (
    fingerprint,
    sha256_file,
    is_plain_sqlite,
    try_key,
    PROFILES,
)


def test_fingerprint():
    key = b"\xaa" * 32
    expected = hashlib.sha256(key).hexdigest()[:8]
    assert fingerprint(key) == expected
    assert len(fingerprint(key)) == 8


def test_sha256_file(tmp_path):
    f = tmp_path / "sample.bin"
    content = b"abcdef" * 1000
    f.write_bytes(content)
    assert sha256_file(f) == hashlib.sha256(content).hexdigest()


def test_is_plain_sqlite(tmp_path):
    plain_db = tmp_path / "plain.sqlite"
    con = sqlite3.connect(str(plain_db))
    con.execute("CREATE TABLE t(x);")
    con.execute("INSERT INTO t VALUES (1);")
    con.commit()
    con.close()

    assert is_plain_sqlite(plain_db) is True

    # Encrypted db should return False for is_plain_sqlite
    enc_db = tmp_path / "enc.sqlite"
    k = b"\x01" * 32
    con = sqlcipher.connect(str(enc_db))
    con.execute(f"PRAGMA key = \"x'{k.hex()}'\";")
    con.execute("CREATE TABLE t(x);")
    con.commit()
    con.close()

    assert is_plain_sqlite(enc_db) is False

    # Non-sqlite file should return False
    text_file = tmp_path / "not_a_db.txt"
    text_file.write_text("hello world")
    assert is_plain_sqlite(text_file) is False


def test_try_key(tmp_path):
    k32_a = b"\x11" * 32
    k32_b = b"\x22" * 32
    k48 = b"\x33" * 48

    default_prof = next(p for p in PROFILES if p["name"] == "default")
    compat3_prof = next(p for p in PROFILES if p["name"] == "compat3")

    # Create default sqlcipher database
    db_default = tmp_path / "default.db"
    con = sqlcipher.connect(str(db_default))
    con.execute(f"PRAGMA key = \"x'{k32_a.hex()}'\";")
    con.execute("CREATE TABLE t(x);")
    con.commit()
    con.close()

    # Success with right key and default profile
    assert try_key(db_default, k32_a, default_prof) is True

    # Failure with wrong key
    assert try_key(db_default, k32_b, default_prof) is False

    # Failure with wrong key length (e.g. 48-byte key with default 64-hex profile)
    assert try_key(db_default, k48, default_prof) is False

    # Create compat3 sqlcipher database
    db_compat = tmp_path / "compat3.db"
    con = sqlcipher.connect(str(db_compat))
    con.execute(f"PRAGMA key = \"x'{k32_a.hex()}'\";")
    con.execute("PRAGMA cipher_compatibility = 3;")
    con.execute("CREATE TABLE t(x);")
    con.commit()
    con.close()

    # Success with compat3 profile
    assert try_key(db_compat, k32_a, compat3_prof) is True
    # Should fail if default (v4) profile is attempted on compat3 database
    assert try_key(db_compat, k32_a, default_prof) is False


def test_export_decrypted(tmp_path):
    from correlator.sqlcipher_util import export_decrypted

    k = b"\x55" * 32
    enc_db = tmp_path / "source_enc.sqlite"
    plain_dest = tmp_path / "exported_plain.sqlite"

    # Create an encrypted database
    con = sqlcipher.connect(str(enc_db))
    con.execute(f"PRAGMA key = \"x'{k.hex()}'\";")
    con.execute("CREATE TABLE users (id INT, username TEXT);")
    con.execute("INSERT INTO users VALUES (1, 'alice');")
    con.commit()
    con.close()

    default_prof = next(p for p in PROFILES if p["name"] == "default")

    # Export to plaintext
    export_decrypted(enc_db, plain_dest, k, default_prof)

    assert plain_dest.is_file()
    assert is_plain_sqlite(plain_dest) is True

    # Verify content using standard sqlite3
    con_plain = sqlite3.connect(str(plain_dest))
    row = con_plain.execute("SELECT id, username FROM users;").fetchone()
    con_plain.close()
    assert row == (1, "alice")
