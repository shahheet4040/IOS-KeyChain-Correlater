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


# ---------------------------------------------------------------------------
# Performance optimisation tests
# ---------------------------------------------------------------------------

def test_column_type_filtering(tmp_path):
    """INT columns must be skipped; TEXT columns with crypto content must fire."""
    db_file = tmp_path / "typed_cols.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("""
        CREATE TABLE wallet_data (
            row_id INTEGER,
            address TEXT
        );
    """)
    # row_id is INTEGER — no pattern match expected from it.
    # address is TEXT — Bitcoin address should trigger a Crypto alert.
    con.execute(
        "INSERT INTO wallet_data VALUES (1, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');"
    )
    con.commit()
    con.close()

    alerts = scan_database_for_alerts(db_file)
    assert len(alerts) >= 1, "Expected at least one alert from TEXT column"
    crypto_alerts = [a for a in alerts if a.category == "Crypto"]
    assert crypto_alerts, "Expected a Crypto alert from the TEXT address column"
    # No alert should reference the integer column (row_id)
    assert all(a.column_name != "row_id" for a in alerts), (
        "INT column row_id should have been skipped"
    )


def test_early_exit_on_max_alerts(tmp_path):
    """scan_database_for_alerts must stop at exactly max_alerts_per_db alerts."""
    db_file = tmp_path / "many_rows.sqlite"
    con = sqlite3.connect(str(db_file))
    con.execute("CREATE TABLE creds (note TEXT);")
    # 200 rows each containing "password" → triggers Credentials alert per row
    con.executemany(
        "INSERT INTO creds VALUES (?);",
        [(f"stored password number {i:03d}",) for i in range(200)],
    )
    con.commit()
    con.close()

    alerts = scan_database_for_alerts(db_file, max_alerts_per_db=5)
    assert len(alerts) == 5, f"Expected exactly 5 alerts, got {len(alerts)}"


def test_scan_speed_stats():
    from correlator.watchlists import scan_speed_stats

    stats = scan_speed_stats()
    assert "patterns_total" in stats, "Missing key: patterns_total"
    assert "categories_count" in stats, "Missing key: categories_count"
    assert stats["patterns_total"] > 0, "patterns_total must be positive"
    assert stats["categories_count"] > 0, "categories_count must be positive"
