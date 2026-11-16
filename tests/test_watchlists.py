"""
Unit Tests for Automated Forensic Watchlists & Keyword Alert Engine
===================================================================
Verifies pattern matching and detection for crypto wallets, financial IBANs,
narcotics, weapons, credentials, and custom examiner watchlists.
"""

from pathlib import Path
import sqlite3
from correlator.watchlists import (
    WatchlistAlert,
    _luhn_check,
    scan_database_for_alerts,
    scan_evidence_for_alerts,
)


def test_luhn_check():
    # Valid test numbers
    assert _luhn_check("49927398716") is True
    assert _luhn_check("1234567812345670") is True
    # Invalid numbers
    assert _luhn_check("1234567812345678") is False
    assert _luhn_check("999") is False


def test_scan_database_for_alerts(tmp_path):
    db_file = tmp_path / "evidence_suspect.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("""
        CREATE TABLE notes (
            id INT,
            subject TEXT,
            body TEXT
        );
    """)
    con.execute("""
        INSERT INTO notes VALUES
        (1, 'Payment info', 'Send the 2.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa today'),
        (2, 'Wire transfer', 'Account IBAN GB33BUKB20201555555555 for the transfer'),
        (3, 'Supply list', 'Meet at the stash house with 500 grams of fentanyl'),
        (4, 'Hardware order', 'Clean glock with suppressor and 9mm ammo'),
        (5, 'Safe note', 'Just shopping groceries: apples, milk, bread');
    """)
    con.commit()
    con.close()

    alerts = scan_database_for_alerts(db_file)
    assert len(alerts) >= 4

    categories = {a.category for a in alerts}
    assert "Crypto" in categories
    assert "Financial" in categories
    assert "Narcotics" in categories
    assert "Weapons" in categories

    # Check alert details
    btc_alert = next(a for a in alerts if a.category == "Crypto")
    assert btc_alert.severity in ("CRITICAL", "HIGH")
    assert "Bitcoin Address" in btc_alert.matched_term


def test_scan_with_custom_keywords(tmp_path):
    db_file = tmp_path / "custom_suspect.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("CREATE TABLE chats (msg TEXT);")
    con.execute("INSERT INTO chats VALUES ('Operation Blackout rendezvous at warehouse');")
    con.commit()
    con.close()

    alerts = scan_database_for_alerts(db_file, custom_keywords=["Blackout", "rendezvous"])
    assert len(alerts) >= 1
    assert alerts[0].category == "Custom Watchlist"
    assert "blackout" in alerts[0].matched_term.lower()


def test_scan_evidence_for_alerts(tmp_path):
    db_file = tmp_path / "evidence.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("CREATE TABLE keys (val TEXT);")
    con.execute("INSERT INTO keys VALUES ('My secret seed phrase: apple banana cherry dog elephant fox grape');")
    con.commit()
    con.close()

    alerts = scan_evidence_for_alerts(tmp_path)
    assert len(alerts) >= 1
    assert any(a.category == "Crypto" for a in alerts)
