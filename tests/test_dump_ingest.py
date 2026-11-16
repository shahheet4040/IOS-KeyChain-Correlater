import json
from pathlib import Path
import pytest
import sqlite3

from correlator.dump_ingest import (
    detect_dump_format,
    locate_databases_in_dump,
    locate_keychain_in_dump,
    normalize_dump_to_extraction,
)


def test_detect_cellebrite_format(tmp_path: Path):
    cell_dir = tmp_path / "cellebrite_dump"
    cell_dir.mkdir()
    (cell_dir / "report.xml").write_text("<report></report>", encoding="utf-8")
    (cell_dir / "UFEDReaderReport").mkdir()

    fmt = detect_dump_format(cell_dir)
    assert fmt == "cellebrite"


def test_detect_graykey_format(tmp_path: Path):
    gk_dir = tmp_path / "graykey_dump"
    gk_dir.mkdir()
    (gk_dir / "device_info.plist").write_bytes(b"bplist00...")
    (gk_dir / "keychain").mkdir()

    fmt = detect_dump_format(gk_dir)
    assert fmt == "graykey"


def test_detect_itunes_format(tmp_path: Path):
    it_dir = tmp_path / "itunes_dump"
    it_dir.mkdir()
    (it_dir / "Manifest.db").write_text("dummy", encoding="utf-8")
    (it_dir / "Info.plist").write_text("dummy", encoding="utf-8")

    fmt = detect_dump_format(it_dir)
    assert fmt == "itunes"


def test_detect_generic_format(tmp_path: Path):
    gen_dir = tmp_path / "generic_dump"
    gen_dir.mkdir()
    (gen_dir / "some_folder").mkdir()
    (gen_dir / "notes.txt").write_text("hello", encoding="utf-8")

    fmt = detect_dump_format(gen_dir)
    assert fmt == "generic"


def test_locate_keychain_and_databases(tmp_path: Path):
    dump_dir = tmp_path / "test_dump"
    dump_dir.mkdir()
    
    # Create mock keychain file
    kc_dir = dump_dir / "Keychain"
    kc_dir.mkdir()
    mock_kc = kc_dir / "keychain-backup.plist"
    mock_kc.write_bytes(b"bplist00...")

    # Create mock SQLite database
    app_dir = dump_dir / "Applications" / "App1"
    app_dir.mkdir(parents=True)
    db_file = app_dir / "messages.sqlite"
    
    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("CREATE TABLE msgs (id INT, text TEXT);")
    cur.execute("INSERT INTO msgs VALUES (1, 'secret message');")
    con.commit()
    con.close()

    found_kc = locate_keychain_in_dump(dump_dir, "cellebrite")
    assert found_kc is not None
    assert found_kc.name == "keychain-backup.plist"

    found_dbs = locate_databases_in_dump(dump_dir, "cellebrite")
    assert len(found_dbs) >= 1
    assert any("messages.sqlite" in str(d) for d in found_dbs)


def test_normalize_dump_to_extraction(tmp_path: Path):
    dump_dir = tmp_path / "full_dump"
    dump_dir.mkdir()

    # Keychain JSON
    kc_file = dump_dir / "keychain.json"
    kc_data = [
        {"service": "com.test.app", "account": "user1", "access_group": "group1", "value_b64": "QUJD"}
    ]
    kc_file.write_text(json.dumps(kc_data), encoding="utf-8")

    # DB
    app_dir = dump_dir / "AppDomain-com.test.app"
    app_dir.mkdir()
    db_file = app_dir / "store.db"
    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("CREATE TABLE info (k TEXT, v TEXT);")
    cur.execute("INSERT INTO info VALUES ('test', 'val');")
    con.commit()
    con.close()

    out_dir = tmp_path / "normalized"
    res = normalize_dump_to_extraction(dump_dir, out_dir)

    assert res["db_count"] >= 1
    assert (out_dir / "extraction").is_dir()
    assert (out_dir / "dump_info.json").is_file()
