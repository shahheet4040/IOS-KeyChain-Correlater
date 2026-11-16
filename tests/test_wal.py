import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
_venv_site = _root / ".venv" / "Lib" / "site-packages"
_src = _root / "src"
if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))
if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import sqlite3
import pytest

from correlator.sqlcipher_util import sha256_file
from correlator.wal import inspect_database_wal, parse_wal


def test_parse_synthetic_wal_files():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    # 1. Test App A / Signal WAL
    wal_a = next(extraction_root.rglob("*signal.sqlite-wal"), None) or next(extraction_root.rglob("*app_a.sqlite-wal"))
    assert wal_a.is_file()
    res_a = parse_wal(wal_a)

    assert res_a.is_valid is True
    assert res_a.header is not None
    assert res_a.total_frames >= 1
    assert res_a.valid_frames == res_a.total_frames
    assert res_a.commit_frames >= 1
    assert len(res_a.unique_pages) >= 1

    # Check frame details
    first_frame = res_a.frames[0]
    assert first_frame.is_valid is True
    assert first_frame.offset == 32
    assert first_frame.pgno > 0
    assert any(f.is_commit for f in res_a.frames)

    # 2. Test App B / Legacy WAL (either 1024 page size or 10-byte truncated)
    wal_b = next(extraction_root.rglob("*legacy.sqlite-wal"), None) or next(extraction_root.rglob("*app_b.sqlite-wal"))
    assert wal_b.is_file()
    res_b = parse_wal(wal_b)
    if res_b.is_valid:
        assert res_b.header.page_size in (1024, 4096)
    else:
        assert res_b["status"] == "too_small"

    # 3. Test WhatsApp ChatStorage WAL
    wal_c = extraction_root / "private/var/mobile/Containers/Shared/AppGroup/CCCC-3333/ChatStorage.sqlite-wal"
    assert wal_c.is_file()
    res_c = parse_wal(wal_c)
    assert res_c["status"] in ("ok", "bad_magic", "too_small")

    # Test serialization
    d = res_a.to_dict()
    assert d["size_bytes"] == wal_a.stat().st_size
    assert d["valid_frames"] == res_a.valid_frames


def test_wal_evidence_immutability():
    """Verify that parse_wal performs read-only parsing and does not alter the WAL file."""
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    wal_files = list(base.rglob("*-wal"))
    assert len(wal_files) > 0

    pre_hashes = {w: sha256_file(w) for w in wal_files}

    for w in wal_files:
        parse_wal(w)

    for w, pre_sha in pre_hashes.items():
        assert sha256_file(w) == pre_sha, f"WAL evidence file was modified: {w}"


def test_inspect_database_wal():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    # Database with companion WAL
    db_with_wal = next(p for p in extraction_root.rglob("*.sqlite") if p.name in ("app_a.sqlite", "signal.sqlite"))
    res = inspect_database_wal(db_with_wal)
    assert res is not None
    assert res.is_valid is True

    # Database with 0-frame or missing WAL
    orphan_db = extraction_root / "private/var/mobile/Containers/Data/Application/DDDD-4444/Library/orphan.db"
    res_orp = inspect_database_wal(orphan_db)
    if res_orp is not None:
        assert res_orp.total_frames == 0 or res_orp.is_valid is False


def test_parse_wal_edge_cases(tmp_path):
    # Missing file
    missing = tmp_path / "nonexistent-wal"
    with pytest.raises(ValueError, match="not found"):
        parse_wal(missing)

    # Empty 0-byte WAL file
    empty_wal = tmp_path / "empty.db-wal"
    empty_wal.touch()
    res_empty = parse_wal(empty_wal)
    assert res_empty.is_valid is False
    assert res_empty.header is None
    assert res_empty.total_frames == 0

    # Truncated file (< 32 bytes)
    trunc_wal = tmp_path / "trunc.db-wal"
    trunc_wal.write_bytes(b"\x37\x7f\x06\x82\x00\x00")
    res_trunc = parse_wal(trunc_wal)
    assert res_trunc.is_valid is False
    assert res_trunc.header is None

    # Invalid magic number
    bad_magic = tmp_path / "bad_magic.db-wal"
    bad_magic.write_bytes(b"A" * 32)
    res_bad = parse_wal(bad_magic)
    assert res_bad.is_valid is False
    assert res_bad.header is None


def test_parse_multi_frame_wal(tmp_path):
    """Create a live SQLite database with multiple transactions and inspect frames."""
    db_path = tmp_path / "test_multi.sqlite"
    con = sqlite3.connect(str(db_path))
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA wal_autocheckpoint=0;")  # prevent automatic checkpointing
    con.execute("CREATE TABLE items (id INT, name TEXT);")
    con.commit()

    for i in range(10):
        con.execute("INSERT INTO items VALUES (?, ?);", (i, f"item_{i}"))
        con.commit()

    wal_path = tmp_path / "test_multi.sqlite-wal"
    assert wal_path.is_file()

    parsed = parse_wal(wal_path)
    assert parsed.is_valid is True
    assert parsed.header is not None
    assert parsed.total_frames >= 2
    assert parsed.valid_frames == parsed.total_frames
    assert parsed.commit_frames >= 2

    con.close()


def test_wal_spec_assertions(tmp_path):
    """
    Spec: The harness WAL files report status ok and frames_valid above 0;
    a file of 10 bytes gives too_small; a file starting with random bytes gives bad_magic.
    """
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    # 1. At least one harness WAL file reports status ok and frames_valid above 0
    harness_wals = list(extraction_root.rglob("*-wal"))
    assert len(harness_wals) >= 3

    valid_wal_found = False
    for wal_file in harness_wals:
        res = parse_wal(wal_file)
        if res["status"] == "ok" and res["frames_valid"] > 0:
            valid_wal_found = True
            break
    assert valid_wal_found is True, "No valid WAL with frames > 0 found in harness"

    # 2. A file of 10 bytes gives too_small
    small_file = tmp_path / "ten_bytes.wal"
    small_file.write_bytes(b"0123456789")
    res_small = parse_wal(small_file)
    assert res_small["status"] == "too_small"

    # 3. A file starting with random bytes gives bad_magic
    import os
    bad_magic_file = tmp_path / "bad_magic.wal"
    bad_magic_file.write_bytes(b"\xde\xad\xbe\xef" + os.urandom(60))
    res_bad = parse_wal(bad_magic_file)
    assert res_bad["status"] == "bad_magic"


if __name__ == "__main__":
    pytest.main([__file__])


