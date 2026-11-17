"""
Unit Tests for SQLite Deleted Data, Freelist & Slack Space Carver
================================================================
Verifies varint decoding, record header parsing, freeblock traversal,
and end-to-end recovery of deleted database records.
"""

import json
from pathlib import Path
import sqlite3
from correlator.carver import (
    DeletedRecord,
    carve_directory_databases,
    carve_regex_artifacts,
    carve_sqlite_database,
    export_carved_csv,
    export_carved_json,
    parse_sqlite_record,
    read_varint,
)


def test_read_varint():
    # 1-byte varints
    assert read_varint(b"\x00")[0] == 0
    assert read_varint(b"\x15")[0] == 21
    assert read_varint(b"\x7F")[0] == 127

    # 2-byte varint: (1 << 7) | 44 = 172
    val, offset = read_varint(b"\x81\x2c")
    assert val == 172
    assert offset == 2


def test_parse_sqlite_record():
    # Construct a SQLite record manually:
    # Header: length varint + serial types
    # Serial types: 13 + 2*5 = 23 (TEXT of length 5), 1 (1-byte int 42)
    # Header size = 3 bytes (len=3, st1=23, st2=1)
    # Payload: b"Hello" + b"\x2a" (42)
    hdr = bytes([3, 23, 1])
    payload = b"Hello\x2a"
    record_bytes = hdr + payload

    res = parse_sqlite_record(record_bytes, 0)
    assert res is not None
    cols, consumed = res
    assert len(cols) == 2
    assert cols[0] == "Hello"
    assert cols[1] == 42
    assert consumed == len(record_bytes)


def test_carve_deleted_sqlite_data(tmp_path):
    db_file = tmp_path / "test_messages.sqlite"
    con = sqlite3.connect(str(db_file))
    # Disable secure_delete so SQLite leaves deleted records in freeblocks / slack space
    # (defaults to ON on Debian/Ubuntu due to -DSQLITE_SECURE_DELETE=1)
    con.execute("PRAGMA secure_delete = OFF;")
    con.execute("CREATE TABLE chats (id INTEGER PRIMARY KEY, sender TEXT, body TEXT);")
    con.execute("INSERT INTO chats VALUES (1, 'Eve', 'Active message that is not deleted');")
    con.execute("INSERT INTO chats VALUES (2, 'Bob', 'TOP_SECRET: Meeting at the dock at midnight');")
    con.execute("INSERT INTO chats VALUES (3, 'Mallory', 'CONFIDENTIAL: Wire transfer $50000 sent');")
    con.commit()

    # Delete rows 2 and 3
    con.execute("DELETE FROM chats WHERE id IN (2, 3);")
    con.commit()
    con.close()

    # Carve deleted records from database image
    carved_records = carve_sqlite_database(db_file)
    assert isinstance(carved_records, list)

    # Check that deleted texts were recovered
    recovered_texts = " ".join(r.raw_text for r in carved_records)
    assert "TOP_SECRET" in recovered_texts or "dock at midnight" in recovered_texts
    assert "CONFIDENTIAL" in recovered_texts or "Wire transfer" in recovered_texts

    # Check that active text is NOT in carved records
    assert "Active message that is not deleted" not in recovered_texts


def test_carve_directory_and_exports(tmp_path):
    db_dir = tmp_path / "cases"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "notes.db"

    con = sqlite3.connect(str(db_path))
    # Disable secure_delete so SQLite leaves deleted records in freeblocks / slack space
    con.execute("PRAGMA secure_delete = OFF;")
    con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, content TEXT);")
    con.execute("INSERT INTO notes VALUES (1, 'Keep', 'Live note text');")
    con.execute("INSERT INTO notes VALUES (2, 'BurnAfterReading', 'Passcode to safe is 482910');")
    con.commit()
    con.execute("DELETE FROM notes WHERE id = 2;")
    con.commit()
    con.close()

    results = carve_directory_databases(db_dir)
    assert len(results) >= 1

    first_db = list(results.keys())[0]
    records = results[first_db]
    assert any("Passcode to safe" in r.raw_text or "482910" in r.raw_text for r in records)

    # Test JSON and CSV export
    json_out = tmp_path / "carved.json"
    csv_out = tmp_path / "carved.csv"

    export_carved_json(records, json_out)
    assert json_out.exists()
    json_data = json.loads(json_out.read_text(encoding="utf-8"))
    assert len(json_data) == len(records)

    export_carved_csv(records, csv_out)
    assert csv_out.exists()
    csv_text = csv_out.read_text(encoding="utf-8")
    assert "Record ID" in csv_text
    assert "Raw Text Preview" in csv_text


def test_carve_regex_artifacts():
    data = b"junk1234\x00user_john@company.gov\x00\x00morejunk\x00+18005550199\x00https://bank.com/transfer\x00"
    arts = carve_regex_artifacts(data)
    assert len(arts) >= 3
    types = [a["type"] for a in arts]
    assert "email" in types
    assert "url" in types
