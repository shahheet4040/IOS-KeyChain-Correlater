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


def test_sms_timeline_extraction(tmp_path):
    sms_db = tmp_path / "sms.db"
    con = sqlite3.connect(str(sms_db))
    con.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, service TEXT);")
    con.execute("""
        CREATE TABLE message (
            ROWID INTEGER PRIMARY KEY,
            text TEXT,
            handle_id INTEGER,
            service TEXT,
            date INTEGER,
            is_from_me INTEGER,
            date_read INTEGER,
            date_delivered INTEGER
        );
    """)
    con.execute("INSERT INTO handle VALUES (1, '+15550199234', 'iMessage');")
    # Date in Apple Cocoa nanoseconds (e.g. 720000000 * 1e9)
    con.execute("INSERT INTO message VALUES (1, 'Meet at coordinate Alpha', 1, 'iMessage', 720000000000000000, 0, 0, 0);")
    con.execute("INSERT INTO message VALUES (2, 'Confirmed', 1, 'iMessage', 720000060000000000, 1, 0, 0);")
    con.commit()
    con.close()

    from correlator.timeline import extract_sms_events
    events = extract_sms_events(sms_db)
    assert len(events) == 2
    assert "Messages" in events[0].app
    assert events[0].sender == "+15550199234"
    assert events[1].sender == "Target (Device Owner)"
    assert events[1].recipient == "+15550199234"
    assert events[0].content == "Meet at coordinate Alpha"


def test_call_history_timeline_extraction(tmp_path):
    call_db = tmp_path / "CallHistory.storedata"
    con = sqlite3.connect(str(call_db))
    con.execute("""
        CREATE TABLE ZCALLRECORD (
            Z_PK INTEGER PRIMARY KEY,
            ZADDRESS TEXT,
            ZDATE REAL,
            ZDURATION REAL,
            ZORIGINATED INTEGER,
            ZANSWERED INTEGER,
            ZCALLTYPE INTEGER,
            ZNAME TEXT
        );
    """)
    # Outgoing cellular call
    con.execute("INSERT INTO ZCALLRECORD VALUES (1, '+15550199234', 720000000.0, 142.0, 1, 1, 1, 'John Doe');")
    # Incoming FaceTime video call
    con.execute("INSERT INTO ZCALLRECORD VALUES (2, 'target@icloud.com', 720000500.0, 310.0, 0, 1, 16, 'Mallory');")
    con.commit()
    con.close()

    from correlator.timeline import extract_call_history_events
    events = extract_call_history_events(call_db)
    assert len(events) == 2
    assert events[0].app == "Phone / Calls"
    assert "Outgoing" in events[0].content
    assert events[0].metadata["duration_sec"] == 142
    assert "FaceTime Video" in events[1].content


def test_notes_and_photos_extraction(tmp_path):
    # Notes
    notes_db = tmp_path / "NoteStore.sqlite"
    con = sqlite3.connect(str(notes_db))
    con.execute("CREATE TABLE ZICCLOUDOBJECT (Z_PK INTEGER PRIMARY KEY, ZCREATIONDATE REAL, ZTITLE TEXT, ZSNIPPET TEXT);")
    con.execute("INSERT INTO ZICCLOUDOBJECT VALUES (1, 720000000.0, 'Safehouse Codes', 'Gate passcode: 994820');")
    con.commit()
    con.close()

    # Photos
    photos_db = tmp_path / "Photos.sqlite"
    con2 = sqlite3.connect(str(photos_db))
    con2.execute("""
        CREATE TABLE ZASSET (
            Z_PK INTEGER PRIMARY KEY,
            ZDATECREATED REAL,
            ZFILENAME TEXT,
            ZLATITUDE REAL,
            ZLONGITUDE REAL
        );
    """)
    con2.execute("INSERT INTO ZASSET VALUES (1, 720000120.0, 'IMG_9941.JPG', 37.7749, -122.4194);")
    con2.commit()
    con2.close()

    from correlator.timeline import extract_notes_events, extract_photos_events
    n_events = extract_notes_events(notes_db)
    assert len(n_events) == 1
    assert "Safehouse Codes" in n_events[0].content

    p_events = extract_photos_events(photos_db)
    assert len(p_events) == 1
    assert p_events[0].latitude == 37.7749
    assert p_events[0].longitude == -122.4194
    assert "IMG_9941.JPG" in p_events[0].content


def test_cross_app_bursts_and_identities():
    from correlator.timeline import (
        TimelineEvent,
        correlate_cross_app_identities,
        detect_app_switching,
        detect_cross_app_bursts,
        export_timeline_csv,
        export_timeline_json,
        generate_master_timeline_html,
    )

    t0 = 1700000000.0  # base epoch
    ev1 = TimelineEvent("SMS-1", "2023-11-14 22:13:20 UTC", t0, "Messages (SMS)", "📱", "chat_message", "+15550199234", "Target", "Switch to Signal", "sms.db", "message")
    ev2 = TimelineEvent("SIG-1", "2023-11-14 22:15:00 UTC", t0 + 100, "Signal", "💬", "chat_message", "+15550199234", "group-1", "On encrypted channel now", "signal.sqlite", "messages")
    ev3 = TimelineEvent("PHOTO-1", "2023-11-14 22:17:30 UTC", t0 + 250, "Photos", "📷", "photo_capture", "Camera", "Media", "Drop site photo", "Photos.sqlite", "ZASSET", latitude=37.77, longitude=-122.41)

    events = [ev1, ev2, ev3]

    # Test burst detection
    clusters = detect_cross_app_bursts(events, window_minutes=15, min_apps=2)
    assert len(clusters) == 1
    assert len(clusters[0].apps_involved) >= 2
    assert "+15550199234" in clusters[0].participants

    # Test identity correlation
    identities = correlate_cross_app_identities(events)
    assert "+15550199234" in identities
    assert identities["+15550199234"]["is_cross_app"] is True
    assert "Signal" in identities["+15550199234"]["apps"]

    # Test app switching detection (SMS -> Signal)
    switches = detect_app_switching(events, max_gap_hours=2)
    assert len(switches) == 1
    assert switches[0]["contact"] == "+15550199234"

    # Test HTML and exporters
    html_out = generate_master_timeline_html(events, clusters=clusters)
    assert "iOS Forensic Master Cross-Application Timeline" in html_out
    assert "Switch to Signal" in html_out
