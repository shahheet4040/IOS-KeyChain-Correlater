"""
Unit Tests for Unified Chat & Activity Timeline Engine
======================================================
Verifies cross-application parsing of Signal, WhatsApp, WeChat, and Safari history
into a single, chronologically sorted event stream.
"""

from pathlib import Path
import sqlite3
import pytest

from correlator.timeline import (
    TimelineEvent,
    extract_safari_events,
    extract_signal_events,
    extract_unified_timeline,
    extract_whatsapp_events,
)


def test_whatsapp_timeline_extraction(tmp_path):
    db_file = tmp_path / "ChatStorage.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("""
        CREATE TABLE ZWAMESSAGE (
            Z_PK INTEGER PRIMARY KEY,
            ZTEXT TEXT,
            ZMESSAGEDATE REAL,
            ZFROMJID TEXT,
            ZTOJID TEXT,
            ZISFROMME INTEGER
        );
    """)
    # Insert Apple Cocoa timestamp (seconds since 2001-01-01)
    con.execute("""
        INSERT INTO ZWAMESSAGE VALUES
        (1, 'Hey are you ready?', 720000000.0, 'suspect@s.whatsapp.net', 'me@s.whatsapp.net', 0),
        (2, 'Yes, meeting at 10.', 720000060.0, 'me@s.whatsapp.net', 'suspect@s.whatsapp.net', 1);
    """)
    con.commit()
    con.close()

    events = extract_whatsapp_events(db_file)
    assert len(events) == 2
    assert events[0].app == "WhatsApp"
    assert events[0].content == "Hey are you ready?"
    assert events[1].sender == "Target (Device Owner)"


def test_signal_timeline_extraction(tmp_path):
    db_file = tmp_path / "signal.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("""
        CREATE TABLE messages (
            rowid INTEGER PRIMARY KEY,
            body TEXT,
            dateSent INTEGER,
            author_id TEXT,
            conversation_id TEXT
        );
    """)
    con.execute("""
        INSERT INTO messages VALUES
        (10, 'Encrypted drop confirmed', 1690000000000, '+15550199', 'group-77');
    """)
    con.commit()
    con.close()

    events = extract_signal_events(db_file)
    assert len(events) == 1
    assert events[0].app == "Signal"
    assert events[0].content == "Encrypted drop confirmed"
    assert events[0].sender == "+15550199"


def test_safari_timeline_extraction(tmp_path):
    db_file = tmp_path / "History.db"
    con = sqlite3.connect(str(db_file))
    con.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT);")
    con.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);")
    con.execute("INSERT INTO history_items VALUES (1, 'https://secret-drop.onion/portal');")
    con.execute("INSERT INTO history_visits VALUES (1, 1, 720000100.0, 'Dark Portal');")
    con.commit()
    con.close()

    events = extract_safari_events(db_file)
    assert len(events) == 1
    assert events[0].app == "Safari"
    assert "https://secret-drop.onion/portal" in events[0].content


def test_extract_unified_timeline(tmp_path):
    # Test directory containing both WhatsApp and Signal
    wa_db = tmp_path / "ChatStorage.sqlite"
    con1 = sqlite3.connect(str(wa_db))
    con1.execute("CREATE TABLE ZWAMESSAGE (Z_PK INT, ZTEXT TEXT, ZMESSAGEDATE REAL, ZFROMJID TEXT, ZTOJID TEXT, ZISFROMME INT);")
    con1.execute("INSERT INTO ZWAMESSAGE VALUES (1, 'First event', 100.0, 'a', 'b', 0);")
    con1.commit()
    con1.close()

    sig_db = tmp_path / "signal.sqlite"
    con2 = sqlite3.connect(str(sig_db))
    con2.execute("CREATE TABLE messages (rowid INT, body TEXT, dateSent INT, author_id TEXT, conversation_id TEXT);")
    con2.execute("INSERT INTO messages VALUES (1, 'Second event', 150000, 'c', 'd');")
    con2.commit()
    con2.close()

    unified = extract_unified_timeline(tmp_path)
    assert len(unified) == 2
    # Verify sorting
    assert unified[0].timestamp_epoch <= unified[1].timestamp_epoch
