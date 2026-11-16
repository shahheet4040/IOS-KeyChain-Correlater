from pathlib import Path
import sqlite3
import pytest
from correlator.entity_recognition import (
    extract_entities_from_text,
    scan_entities_in_evidence,
)


def test_extract_entities_from_text():
    sample_text = (
        "Hey Michael, meet me at 14:30 tomorrow. "
        "Send the 5.2 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq "
        "or 0x71C637302432644B238517c6aA4244Ba38048473. "
        "Call me on +1-555-019-2834 or officer at suspect@protonmail.com. "
        "Flight is EK501 on 2026-12-01."
    )

    entities = extract_entities_from_text(sample_text)
    types_found = {t for t, _ in entities}
    values_found = {v for _, v in entities}

    assert "PERSON" in types_found
    assert "Michael" in values_found

    assert "CRYPTO" in types_found
    assert any("bc1qar0" in v for v in values_found)
    assert any("0x71C637" in v for v in values_found)

    assert "PHONE" in types_found
    assert any("555" in v for v in values_found)

    assert "EMAIL" in types_found
    assert "suspect@protonmail.com" in values_found

    assert "FLIGHT_SHIPMENT" in types_found
    assert "EK501" in values_found

    assert "TEMPORAL" in types_found
    assert "2026-12-01" in values_found


def test_scan_entities_in_evidence_from_db(tmp_path: Path):
    db_path = tmp_path / "test_consolidated.sqlite"
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE messages (
            message_id TEXT,
            app TEXT,
            sender TEXT,
            recipient TEXT,
            timestamp_utc TEXT,
            timestamp_epoch INTEGER,
            content TEXT
        )
    """)
    cur.execute(
        "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("m1", "Signal", "UserA", "UserB", "2026-11-10", 1000, "Hi Alexander, transfer funds to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
    )
    cur.execute(
        "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("m2", "WhatsApp", "UserB", "UserA", "2026-11-10", 1005, "Sure Alexander, contacting target@darknet.org"),
    )
    con.commit()
    con.close()

    res = scan_entities_in_evidence(consolidated_db_path=db_path)
    assert res["total_entities"] >= 2
    types = res["summary_by_type"]
    assert "PERSON" in types
    assert "CRYPTO" in types or "EMAIL" in types

    entity_values = [e["value"] for e in res["entities"]]
    assert "Alexander" in entity_values


def test_scan_entities_empty():
    res = scan_entities_in_evidence(search_dirs=[], consolidated_db_path=None)
    assert res["total_entities"] == 0
    assert res["entities"] == []
