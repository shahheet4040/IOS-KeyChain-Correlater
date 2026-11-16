import sys
from pathlib import Path

# Auto-resolve virtualenv packages and source paths if invoked via global python
_root = Path(__file__).resolve().parent.parent
_venv_site = _root / ".venv" / "Lib" / "site-packages"
_src = _root / "src"
if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))
if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import sqlite3
import pytest
from sqlcipher3 import dbapi2 as sqlcipher

from correlator.triage import classify_database, triage_extraction, classify, find_databases
from correlator.sqlcipher_util import sha256_file


def test_classify_database(tmp_path):
    # 1. Missing file
    missing = tmp_path / "nonexistent.db"
    with pytest.raises(ValueError, match="not found"):
        classify_database(missing)

    # 2. Empty 0-byte file
    empty_file = tmp_path / "empty.db"
    empty_file.touch()
    assert classify_database(empty_file) == "empty"

    # 3. Plain SQLite file
    plain_file = tmp_path / "plain.sqlite"
    con = sqlite3.connect(str(plain_file))
    con.execute("CREATE TABLE test (id INT);")
    con.execute("INSERT INTO test VALUES (1);")
    con.commit()
    con.close()
    assert classify_database(plain_file) == "plain"

    # 4. Encrypted SQLCipher database
    enc_file = tmp_path / "enc.sqlite"
    key = "aa" * 32
    con = sqlcipher.connect(str(enc_file))
    con.execute(f"PRAGMA key = \"x'{key}'\";")
    con.execute("CREATE TABLE secret (val TEXT);")
    con.execute("INSERT INTO secret VALUES ('hidden');")
    con.commit()
    con.close()
    assert classify_database(enc_file) == "encrypted"


def test_triage_synthetic_extraction():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    triaged = triage_extraction(extraction_root)
    assert len(triaged) == 4

    by_name = {t.name: t for t in triaged}
    assert ("app_a.sqlite" in by_name or "signal.sqlite" in by_name)
    assert ("app_b.sqlite" in by_name or "legacy.sqlite" in by_name)
    assert "ChatStorage.sqlite" in by_name
    assert "orphan.db" in by_name

    # Check classifications
    db_a = by_name.get("app_a.sqlite") or by_name.get("signal.sqlite")
    assert db_a.classification == "encrypted"
    assert db_a.bundle_id in ("org.example.app_a", "org.whispersystems.signal")
    assert db_a.container_uuid == "AAAA-1111"
    assert db_a.container_type == "AppGroup"
    assert db_a.has_wal is True
    assert len(db_a.sha256) == 64

    db_b = by_name.get("app_b.sqlite") or by_name.get("legacy.sqlite")
    assert db_b.classification == "encrypted"
    assert db_b.bundle_id == "org.example.app_b"
    assert db_b.container_uuid == "BBBB-2222"
    assert db_b.container_type == "Application"
    assert db_b.has_wal is True

    assert by_name["ChatStorage.sqlite"].classification == "plain"
    assert by_name["ChatStorage.sqlite"].bundle_id == "net.whatsapp.WhatsApp"
    assert by_name["ChatStorage.sqlite"].container_type == "AppGroup"
    assert by_name["ChatStorage.sqlite"].has_wal is True

    assert by_name["orphan.db"].classification == "encrypted"
    assert by_name["orphan.db"].bundle_id == "org.example.orphan"
    assert by_name["orphan.db"].container_type == "Application"

    # Check to_dict()
    d = db_a.to_dict()
    assert d["name"] in ("app_a.sqlite", "signal.sqlite")
    assert d["classification"] == "encrypted"


def test_triage_evidence_immutability():
    """Ensure that running triage does not modify any evidence files on disk."""
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    # Pre-triage digests of all files in extraction
    pre_digests = {}
    for p in extraction_root.rglob("*"):
        if p.is_file():
            pre_digests[p] = sha256_file(p)

    # Perform triage
    triaged = triage_extraction(extraction_root)
    assert len(triaged) == 4

    # Post-triage digests
    for p, pre_sha in pre_digests.items():
        post_sha = sha256_file(p)
        assert post_sha == pre_sha, f"Evidence file was modified: {p}"


def test_triage_spec_assertions():
    """
    Spec: The harness plain database is plain; both encrypted databases are not_plain;
    -wal and -shm files are never listed as databases.
    """
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    # 1. find_databases never lists -wal and -shm files
    dbs = find_databases(extraction_root)
    for db_rel in dbs:
        assert not db_rel.endswith("-wal"), f"WAL file listed as database: {db_rel}"
        assert not db_rel.endswith("-shm"), f"SHM file listed as database: {db_rel}"
        assert not db_rel.endswith("-journal"), f"Journal file listed as database: {db_rel}"

    # Verify actual companion files exist on disk in the harness
    wal_files = list(extraction_root.rglob("*-wal"))
    assert len(wal_files) > 0
    for w in wal_files:
        w_rel = w.relative_to(extraction_root).as_posix()
        assert w_rel not in dbs

    # 2. Plain database is plain
    plain_path = next(extraction_root.rglob("ChatStorage.sqlite"))
    assert classify(plain_path) == "plain"

    # 3. Both encrypted databases are not_plain
    app_a_path = next(p for p in extraction_root.rglob("*.sqlite") if p.name in ("app_a.sqlite", "signal.sqlite"))
    app_b_path = next(p for p in extraction_root.rglob("*.sqlite") if p.name in ("app_b.sqlite", "legacy.sqlite"))
    assert classify(app_a_path) == "not_plain"
    assert classify(app_b_path) == "not_plain"


if __name__ == "__main__":
    pytest.main([__file__])


