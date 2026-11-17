import os
import json
import random
import sqlite3
import plistlib
import base64
import shutil
import hashlib
import argparse
from pathlib import Path

try:
    from sqlcipher3 import dbapi2 as sqlcipher
except ImportError:
    print("FATAL: sqlcipher3-binary is not installed. Please run: pip install sqlcipher3-binary")
    exit(1)

def fingerprint(key_bytes: bytes) -> str:
    return hashlib.sha256(key_bytes).hexdigest()[:8]

def make_db_with_wal(path: Path, key: bytes, pragmas: list, is_plain: bool):
    """Creates a database, writes to it, forces a WAL file, and safely copies it before closing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for f in [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]:
        if f.exists():
            try:
                f.unlink()
            except Exception:
                pass
    
    if is_plain:
        con = sqlite3.connect(str(path))
    else:
        con = sqlcipher.connect(str(path))
        con.execute(f"PRAGMA key = \"x'{key.hex()}'\";")
        for p in pragmas:
            con.execute(p)

    # Create schema and initial commit
    con.execute("CREATE TABLE t(x);")
    con.execute("CREATE TABLE messages(id INTEGER, content TEXT);")
    if "ChatStorage" in path.name:
        con.execute("CREATE TABLE IF NOT EXISTS ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZMESSAGEDATE REAL, ZLATITUDE REAL, ZLONGITUDE REAL, ZTEXT TEXT);")
        con.execute("INSERT INTO ZWAMESSAGE VALUES (1, 100000.0, 37.7749, -122.4194, 'Meeting point near downtown');")
        con.execute("INSERT INTO ZWAMESSAGE VALUES (2, 100600.0, 37.7880, -122.4075, 'Union square checkpoint');")
        con.execute("INSERT INTO ZWAMESSAGE VALUES (3, 101800.0, 37.8080, -122.4177, 'Fishermans Wharf safehouse');")
    for i in range(10): 
        con.execute("INSERT INTO t VALUES (?)", (i,))
        con.execute("INSERT INTO messages VALUES (?, ?)", (i, f"message_{i}"))
    con.commit()

    # Switch to WAL mode and prevent automatic merging
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA wal_autocheckpoint=0;")
    
    # Write frames to the WAL
    for i in range(15): 
        con.execute("INSERT INTO t VALUES (?)", (i+10,))
        con.execute("INSERT INTO messages VALUES (?, ?)", (i+10, f"message_{i+10}"))
    con.commit()

    # SQLite deletes the WAL when the connection closes.
    # To bypass this, we copy the files out while the connection is still open.
    db_bak = path.with_suffix('.sqlite.bak')
    wal_bak = str(path) + '-wal.bak'
    shm_bak = str(path) + '-shm.bak'
    
    shutil.copy2(str(path), db_bak)
    shutil.copy2(str(path) + '-wal', wal_bak)
    shutil.copy2(str(path) + '-shm', shm_bak)
    
    con.close()
    
    # Replace the closed (WAL-less) files with our backups
    shutil.move(db_bak, path)
    shutil.move(wal_bak, str(path) + '-wal')
    shutil.move(shm_bak, str(path) + '-shm')

def write_plist(dir_path: Path, bundle_id: str):
    plist_path = dir_path / ".com.apple.mobile_container_manager.metadata.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump({"MCMMetadataIdentifier": bundle_id}, f)

def generate_fake_extraction(out_dir: Path | str):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    extraction_dir = out_dir / "extraction"
    if extraction_dir.exists():
        shutil.rmtree(extraction_dir, ignore_errors=True)
    containers = extraction_dir / "private" / "var" / "mobile" / "Containers"

    # Seed random for repeatable keys
    rng = random.Random(1234)
    key_a_48 = rng.randbytes(48)    # Signal Key
    key_b_32 = rng.randbytes(32)    # Legacy Key
    key_e_32 = rng.randbytes(32)    # Orphan Key
    lure_key_32 = rng.randbytes(32) # WhatsApp Lure Key
    short_key_16 = rng.randbytes(16)
    random_48 = rng.randbytes(48)

    print("Building 'Fragmented Enclave' Databases...")

    # 1. Signal (Encrypted, 48-byte, signal_like, Valid WAL)
    sig_dir = containers / "Shared" / "AppGroup" / "AAAA-1111"
    sig_dir.mkdir(parents=True, exist_ok=True)
    write_plist(sig_dir, "org.whispersystems.signal")
    make_db_with_wal(sig_dir / "grdb" / "signal.sqlite", key_a_48, ["PRAGMA cipher_plaintext_header_size = 32;"], False)

    # 2. Legacy App (Encrypted, 32-byte, compat3, Truncated 10-byte WAL)
    leg_dir = containers / "Data" / "Application" / "BBBB-2222"
    leg_dir.mkdir(parents=True, exist_ok=True)
    write_plist(leg_dir, "org.example.app_b")
    leg_db = leg_dir / "Documents" / "legacy.sqlite"
    make_db_with_wal(leg_db, key_b_32, ["PRAGMA cipher_compatibility = 3;"], False)
    # Mutate: Truncate WAL to 10 bytes
    with open(str(leg_db) + '-wal', 'wb') as f:
        f.write(b'1234567890')

    # 3. WhatsApp Control (Plaintext, Corrupt WAL Magic Header)
    wa_dir = containers / "Shared" / "AppGroup" / "CCCC-3333"
    wa_dir.mkdir(parents=True, exist_ok=True)
    write_plist(wa_dir, "net.whatsapp.WhatsApp")
    wa_db = wa_dir / "ChatStorage.sqlite"
    make_db_with_wal(wa_db, b'', [], True)
    # Mutate: Overwrite magic header with zeros
    with open(str(wa_db) + '-wal', 'r+b') as f:
        f.write(b'\x00\x00\x00\x00')

    # 4. Orphan DB (Encrypted, Key not in keychain, Valid 0-frame WAL)
    orp_dir = containers / "Data" / "Application" / "DDDD-4444"
    orp_dir.mkdir(parents=True, exist_ok=True)
    write_plist(orp_dir, "org.example.orphan")
    orp_db = orp_dir / "Library" / "orphan.db"
    make_db_with_wal(orp_db, key_e_32, [], False)
    # Mutate: Read 32-byte header and truncate rest (0 frames)
    with open(str(orp_db) + '-wal', 'r+b') as f:
        header = f.read(32)
    with open(str(orp_db) + '-wal', 'wb') as f:
        f.write(header)

    print("Generating Keychain...")
    keychain = [
        {"service": "org.whispersystems.signal", "account": "GRDBDatabaseCipherKeySpec", "access_group": "group.org.whispersystems.signal", "value_b64": base64.b64encode(key_a_48).decode('utf-8')},
        {"service": "unknown_service", "account": "unknown_account", "access_group": "", "value_b64": base64.b64encode(key_b_32).decode('utf-8')}, # Duplicate Trap
        {"service": "org.example.app_b.cipher", "account": "cipher_key", "access_group": "", "value_b64": base64.b64encode(key_b_32).decode('utf-8')}, # Valid Trap (higher hint_score)
        {"service": "WhatsApp-like-control", "account": "key", "access_group": "", "value_b64": base64.b64encode(lure_key_32).decode('utf-8')}, # False positive lure
        {"service": "short_key", "account": "short", "access_group": "", "value_b64": base64.b64encode(short_key_16).decode('utf-8')}, # Crash trigger 1
        {"service": "bad_base64", "account": "bad", "access_group": "", "value_b64": "!!!INVALID_BASE64!!!"}, # Crash trigger 2
        {"service": "random_decoy", "account": "decoy", "access_group": "", "value_b64": base64.b64encode(random_48).decode('utf-8')}
    ]
    with open(out_dir / "keychain.json", "w") as f:
        json.dump(keychain, f, indent=2)

    print("Generating Ground Truth...")
    ground_truth = [
        {
            "relpath": "private/var/mobile/Containers/Shared/AppGroup/AAAA-1111/grdb/signal.sqlite",
            "expected_status": "decrypted",
            "expected_key_fingerprint": fingerprint(key_a_48),
            "expected_profile": "signal_like"
        },
        {
            "relpath": "private/var/mobile/Containers/Data/Application/BBBB-2222/Documents/legacy.sqlite",
            "expected_status": "decrypted",
            "expected_key_fingerprint": fingerprint(key_b_32),
            "expected_profile": "compat3"
        },
        {
            "relpath": "private/var/mobile/Containers/Shared/AppGroup/CCCC-3333/ChatStorage.sqlite",
            "expected_status": "plain",
            "expected_key_fingerprint": None,
            "expected_profile": None
        },
        {
            "relpath": "private/var/mobile/Containers/Data/Application/DDDD-4444/Library/orphan.db",
            "expected_status": "not_decrypted",
            "expected_key_fingerprint": None,
            "expected_profile": None
        }
    ]
    with open(out_dir / "ground_truth.json", "w") as f:
        json.dump(ground_truth, f, indent=2)

    from correlator.pipeline import execute_pipeline
    execute_pipeline(
        extraction=extraction_dir,
        keychain=out_dir / "keychain.json",
        report=out_dir / "report.json",
        html_report=out_dir / "report.html",
        out_dir=out_dir,
        export_dir=out_dir / "decrypted_export",
    )

    print(f"Success! Fragmented Enclave test data generated at: {out_dir}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="Output directory for fake data")
    args = parser.parse_args()
    generate_fake_extraction(args.out)

if __name__ == "__main__":
    main()
