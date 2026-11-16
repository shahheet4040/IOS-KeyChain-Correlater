"""
Real-World Forensic Case Data Generator
=======================================
Generates a realistic, true-to-life forensic extraction mimicking a seized
iPhone extraction exported from Cellebrite UFED / GrayKey.

Contains:
  1. Signal Messenger (SQLCipher v4): Chats, suspect numbers, cryptocurrency addresses
  2. WeChat / WCDB (64,000 PBKDF2 iterations): Encrypted user accounts
  3. WhatsApp (SQLite with active WAL): Chats, contact messages, timestamps
  4. Apple Safari History (Plain SQLite): Visited URLs, web searches
  5. Cellebrite UFED XML & Apple Plist Keychain: Containing real matching keys
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import sqlite3

try:
    from sqlcipher3 import dbapi2 as sqlcipher
    SQLCIPHER_AVAILABLE = True
except ImportError:
    SQLCIPHER_AVAILABLE = False


def generate_real_world_case(output_dir: str | Path):
    target_root = Path(output_dir).resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    print("═" * 70)
    print(" 📱 Generating Real-World Forensic Case Dataset (Cellebrite UFED Replica)")
    print("═" * 70)
    print(f" Destination: {target_root}")

    # Generate cryptographic keys
    signal_key = os.urandom(32)   # 256-bit AES key for Signal
    wechat_key = os.urandom(32)   # 256-bit key for WeChat WCDB
    legacy_key = os.urandom(32)   # 256-bit key for Legacy App

    # 1. Structure: Cellebrite UFED folder layout
    extraction_dir = target_root / "Extraction"
    extraction_dir.mkdir(parents=True, exist_ok=True)

    # Cellebrite markers
    (target_root / "report.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?><UFEDReport Device="iPhone14,2" iOS="16.5.1" Case="FSL-2026-9041"></UFEDReport>',
        encoding="utf-8",
    )
    (target_root / "UFEDReaderReport").mkdir(exist_ok=True)

    # ── App 1: Signal Private Messenger (SQLCipher v4) ───────────────────
    signal_dir = extraction_dir / "AppDomain-org.whispersystems.signal" / "Documents"
    signal_dir.mkdir(parents=True, exist_ok=True)
    signal_db_path = signal_dir / "signal.sqlite"

    if SQLCIPHER_AVAILABLE:
        con = sqlcipher.connect(str(signal_db_path))
        con.execute(f"PRAGMA key = \"x'{signal_key.hex()}'\";")
        con.execute("PRAGMA cipher_page_size = 4096;")
        con.execute("PRAGMA kdf_iter = 256000;")
        con.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;")
        con.execute("PRAGMA cipher_default_kdf_algorithm = PBKDF2_HMAC_SHA512;")

        con.execute("""
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                body TEXT,
                timestamp TEXT,
                tx_hash TEXT
            );
        """)
        messages = [
            ("Suspect_A", "Client_B", "The shipment arrives at Mumbai Port on Friday. Use code-phrase 8821.", "2026-03-10T14:22:00Z", None),
            ("Client_B", "Suspect_A", "Payment of 4.5 BTC transferred to your cold storage wallet.", "2026-03-10T14:35:12Z", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
            ("Suspect_A", "Client_B", "Funds confirmed on blockchain. Delete this conversation.", "2026-03-10T14:40:05Z", None),
            ("Suspect_A", "Supplier_X", "Hawala transaction code is #HWL-9901 for Rs. 50,00,000.", "2026-03-11T09:15:30Z", None),
        ]
        for m in messages:
            con.execute("INSERT INTO messages (sender, recipient, body, timestamp, tx_hash) VALUES (?, ?, ?, ?, ?)", m)

        con.execute("""
            CREATE TABLE contacts (
                id INTEGER PRIMARY KEY,
                name TEXT,
                phone TEXT,
                alias TEXT
            );
        """)
        contacts = [
            ("Vikram Sharma", "+91-98200-11223", "Chief"),
            ("Rajesh Patel", "+91-98980-44556", "Broker"),
            ("Dubai Contact", "+971-50-1234567", "Gold_Trader"),
        ]
        for c in contacts:
            con.execute("INSERT INTO contacts (name, phone, alias) VALUES (?, ?, ?)", c)

        con.commit()
        con.close()
        print("  [+] Created Signal (SQLCipher v4): 4 encrypted messages, 3 contacts, BTC wallet")

    # ── App 2: WeChat / WCDB (SQLCipher with 64,000 iterations) ─────────
    wechat_dir = extraction_dir / "AppDomain-com.tencent.xin" / "Documents"
    wechat_dir.mkdir(parents=True, exist_ok=True)
    wechat_db_path = wechat_dir / "MM.sqlite"

    if SQLCIPHER_AVAILABLE:
        con = sqlcipher.connect(str(wechat_db_path))
        con.execute(f"PRAGMA key = \"x'{wechat_key.hex()}'\";")
        con.execute("PRAGMA cipher_page_size = 4096;")
        con.execute("PRAGMA kdf_iter = 64000;")
        con.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;")

        con.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                wxid TEXT,
                nickname TEXT,
                balance_cny REAL
            );
        """)
        con.execute("INSERT INTO users VALUES (1, 'wxid_target99', 'ShadowMerchant', 450000.00);")
        con.commit()
        con.close()
        print("  [+] Created WeChat (WCDB 64k iter): Encrypted account records")

    # ── App 3: WhatsApp (SQLite with active WAL file) ───────────────────
    wa_dir = extraction_dir / "AppDomain-net.whatsapp.WhatsApp" / "ChatStorage"
    wa_dir.mkdir(parents=True, exist_ok=True)
    wa_db_path = wa_dir / "ChatStorage.sqlite"

    con = sqlite3.connect(str(wa_db_path))
    con.execute("""
        CREATE TABLE ZWAMESSAGE (
            Z_PK INTEGER PRIMARY KEY,
            ZFROMJID TEXT,
            ZTOJID TEXT,
            ZTEXT TEXT,
            ZMESSAGEDATE REAL
        );
    """)
    con.execute("INSERT INTO ZWAMESSAGE VALUES (1, '919820011223@s.whatsapp.net', 'self', 'Meeting scheduled at Hotel Taj, Mumbai.', 700000000.0);")
    con.commit()

    # Turn on WAL and force live uncommitted frames into WAL
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA wal_autocheckpoint=0;")
    for i in range(12):
        con.execute("INSERT INTO ZWAMESSAGE VALUES (?, 'broadcast', 'self', ?, ?)", (i + 2, f"Encrypted WhatsApp transmission #{i}", 700000100.0 + i))
    con.commit()

    # Copy files before closing to preserve WAL
    shutil.copy2(str(wa_db_path), str(wa_db_path) + ".bak")
    shutil.copy2(str(wa_db_path) + "-wal", str(wa_db_path) + "-wal.bak")
    con.close()

    shutil.copy2(str(wa_db_path) + ".bak", str(wa_db_path))
    shutil.copy2(str(wa_db_path) + "-wal.bak", str(wa_db_path) + "-wal")
    os.remove(str(wa_db_path) + ".bak")
    os.remove(str(wa_db_path) + "-wal.bak")
    print("  [+] Created WhatsApp: 13 messages with active live WAL journal")

    # ── App 4: Safari Web History (Plain SQLite) ────────────────────────
    safari_dir = extraction_dir / "AppDomain-com.apple.mobilesafari" / "Library"
    safari_dir.mkdir(parents=True, exist_ok=True)
    safari_db_path = safari_dir / "History.db"

    con = sqlite3.connect(str(safari_db_path))
    con.execute("""
        CREATE TABLE history_items (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            visit_count INTEGER
        );
    """)
    history = [
        ("https://binance.com/trade/BTC_USDT", "Binance Spot Trading", 14),
        ("https://torproject.org/download", "The Tor Project: Download Tor Browser", 5),
        ("https://flightradar24.com", "Flightradar24: Live Flight Tracker", 8),
        ("https://duckduckgo.com/?q=hawala+money+transfer+rules", "DuckDuckGo Search", 3),
    ]
    for h in history:
        con.execute("INSERT INTO history_items (url, title, visit_count) VALUES (?, ?, ?)", h)
    con.commit()
    con.close()
    print("  [+] Created Safari History (Plain SQLite): Browsing logs, Tor, Binance searches")

    # ── Keychain: Cellebrite XML Format ─────────────────────────────────
    keychain_items = [
        {
            "service": "org.whispersystems.signal.database",
            "account": "databaseKey",
            "access_group": "group.org.whispersystems.signal",
            "value_b64": base64.b64encode(signal_key).decode("utf-8"),
        },
        {
            "service": "com.tencent.xin.wcdb",
            "account": "WCDBKey",
            "access_group": "com.tencent.xin",
            "value_b64": base64.b64encode(wechat_key).decode("utf-8"),
        },
        {
            "service": "com.apple.account.AppleID",
            "account": "suspect.target@icloud.com",
            "access_group": "apple",
            "value_b64": base64.b64encode(b"SuperSecretPassword2026!").decode("utf-8"),
        },
    ]

    # Save as Cellebrite XML Keychain
    kc_xml_path = target_root / "keychain.xml"
    xml_lines = ['<?xml version="1.0" encoding="utf-8"?>', "<keychain>"]
    for it in keychain_items:
        xml_lines.append(
            f'  <item service="{it["service"]}" account="{it["account"]}" group="{it["access_group"]}" value="{it["value_b64"]}" />'
        )
    xml_lines.append("</keychain>")
    kc_xml_path.write_text("\n".join(xml_lines), encoding="utf-8")

    # Also save as Apple Plist
    kc_plist_path = target_root / "keychain.plist"
    plist_records = []
    for it in keychain_items:
        plist_records.append({
            "svce": it["service"],
            "acct": it["account"],
            "agrp": it["access_group"],
            "v_Data": base64.b64decode(it["value_b64"]),
        })
    with open(kc_plist_path, "wb") as f:
        plistlib.dump(plist_records, f)

    print("  [+] Created Forensic Keychain: Cellebrite XML & Apple Plist formats")
    print("═" * 70)
    print(" 🎉 Real-World Forensic Dataset Ready at:")
    print(f"    {target_root}")
    print("═" * 70)


if __name__ == "__main__":
    out_target = Path(__file__).resolve().parent.parent / "out" / "real_world_case"
    generate_real_world_case(out_target)
