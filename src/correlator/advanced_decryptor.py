"""
Advanced Forensic Decryption & Multi-Engine Database Unlocking
=============================================================
Provides automated decryption, key recovery, and payload extraction
across diverse encrypted mobile formats:
1. SQLCipher v1, v2, v3, v4 (Raw Keys, Derived Hashes, Plaintext Headers)
2. WhatsApp Crypt12 / Crypt14 / Crypt15 (AES-256-GCM & CBC)
3. Container Secret Harvester (Extracts keys from Plists, SharedPreferences, JSON)
4. Smart Passcode & Dictionary Key Derivation (PINs, PBKDF2, SHA-256)
5. Fallback WAL & Raw Page Artifact Carver (Carves text/chats from locked pages)
"""

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple
import zlib

from sqlcipher3 import dbapi2 as sqlcipher

from correlator.sqlcipher_util import PROFILES, fingerprint, is_plain_sqlite, try_key
from correlator.whatsapp_crypt import (
    CRYPTOGRAPHY_AVAILABLE,
    decrypt_whatsapp_crypt14_15,
    is_crypt_database,
)

COMMON_PASSWORDS = [
    "1234", "0000", "123456", "password", "apple", "iphone",
    "1111", "1212", "qwerty", "12345678", "admin", "12345",
    "test", "default", "root", "toor", "passcode", "secret",
]

HEX_32_PATTERN = re.compile(r"\b[0-9a-fA-F]{64}\b")
HEX_48_PATTERN = re.compile(r"\b[0-9a-fA-F]{96}\b")
BASE64_32_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{44})(?![A-Za-z0-9+/])")
BASE64_48_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{64})(?![A-Za-z0-9+/])")


# ── 1. Container Secret Harvester ─────────────────────────────────────

def scrape_container_secrets(container_dir: Path) -> List[Dict[str, Any]]:
    """
    Crawls an application's container directory (Preferences, Application Support, Documents)
    and extracts candidate encryption keys, hex strings, and Base64 tokens.
    """
    candidates: List[Dict[str, Any]] = []
    seen_keys: Set[bytes] = set()

    if not container_dir.is_dir():
        return candidates

    # Files to inspect
    target_extensions = {".plist", ".json", ".xml", ".txt", ".conf", ".cfg", ".properties"}

    for file_path in container_dir.rglob("*"):
        if not file_path.is_file() or file_path.suffix.lower() not in target_extensions:
            continue
        if file_path.stat().st_size > 5 * 1024 * 1024:  # Skip files > 5MB
            continue

        raw_bytes = b""
        text_content = ""

        # A. Try parsing as plist
        if file_path.suffix.lower() == ".plist":
            try:
                with open(file_path, "rb") as f:
                    p_data = plistlib.load(f)
                    text_content = json.dumps(str(p_data))
                    # Check for binary data objects in plist
                    if isinstance(p_data, dict):
                        for k, v in p_data.items():
                            if isinstance(v, bytes) and len(v) in (32, 48):
                                if v not in seen_keys:
                                    seen_keys.add(v)
                                    candidates.append({
                                        "key_bytes": v,
                                        "fingerprint": fingerprint(v),
                                        "source": f"plist_data:{file_path.name}:{k}",
                                        "method": "container_plist_binary",
                                    })
            except Exception:
                pass

        # B. Fallback to raw text scanning
        if not text_content:
            try:
                raw_bytes = file_path.read_bytes()
                text_content = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                continue

        # Look for 64-char Hex (32 bytes)
        for h in HEX_32_PATTERN.findall(text_content):
            try:
                kb = bytes.fromhex(h)
                if kb not in seen_keys:
                    seen_keys.add(kb)
                    candidates.append({
                        "key_bytes": kb,
                        "fingerprint": fingerprint(kb),
                        "source": f"{file_path.name}:hex64",
                        "method": "container_hex_string",
                    })
            except Exception:
                pass

        # Look for 96-char Hex (48 bytes, e.g. Signal keys)
        for h in HEX_48_PATTERN.findall(text_content):
            try:
                kb = bytes.fromhex(h)
                if kb not in seen_keys:
                    seen_keys.add(kb)
                    candidates.append({
                        "key_bytes": kb,
                        "fingerprint": fingerprint(kb),
                        "source": f"{file_path.name}:hex96",
                        "method": "container_hex_string",
                    })
            except Exception:
                pass

        # Look for 44-char Base64 (32 bytes)
        for b64 in BASE64_32_PATTERN.findall(text_content):
            try:
                kb = base64.b64decode(b64)
                if len(kb) == 32 and kb not in seen_keys:
                    seen_keys.add(kb)
                    candidates.append({
                        "key_bytes": kb,
                        "fingerprint": fingerprint(kb),
                        "source": f"{file_path.name}:b64_32",
                        "method": "container_base64_string",
                    })
            except Exception:
                pass

        # Look for 64-char Base64 (48 bytes)
        for b64 in BASE64_48_PATTERN.findall(text_content):
            try:
                kb = base64.b64decode(b64)
                if len(kb) == 48 and kb not in seen_keys:
                    seen_keys.add(kb)
                    candidates.append({
                        "key_bytes": kb,
                        "fingerprint": fingerprint(kb),
                        "source": f"{file_path.name}:b64_48",
                        "method": "container_base64_string",
                    })
            except Exception:
                pass

    return candidates


# ── 2. Smart Passcode & Wordlist Key Generator ───────────────────────

def generate_smart_keys(
    passwords: Optional[List[str]] = None,
    device_udid: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Generates cryptographic key candidates from common forensic passwords,
    PINs, and device identifiers using SHA-256 and raw string encodings.
    """
    cands: List[Dict[str, Any]] = []
    seen: Set[bytes] = set()

    wordlist = list(COMMON_PASSWORDS)
    if passwords:
        wordlist.extend(passwords)
    if device_udid:
        wordlist.append(device_udid)
        wordlist.append(device_udid.replace("-", ""))

    for pw in wordlist:
        if not pw:
            continue

        # 1. SHA-256 of password (most common SQLCipher programmatic key derivation)
        sha256_k = hashlib.sha256(pw.encode("utf-8")).digest()
        if sha256_k not in seen:
            seen.add(sha256_k)
            cands.append({
                "key_bytes": sha256_k,
                "fingerprint": fingerprint(sha256_k),
                "source": f"sha256('{pw}')",
                "method": "smart_sha256_derivation",
            })

        # 2. Raw ASCII / UTF-8 password as 32-byte zero-padded key
        raw_bytes = pw.encode("utf-8")
        if len(raw_bytes) <= 32:
            padded_32 = raw_bytes.ljust(32, b"\x00")
            if padded_32 not in seen:
                seen.add(padded_32)
                cands.append({
                    "key_bytes": padded_32,
                    "fingerprint": fingerprint(padded_32),
                    "source": f"padded('{pw}')",
                    "method": "smart_padded_key",
                })

    return cands


# ── 3. Fallback Raw Artifact & WAL Carver ─────────────────────────────

def carve_text_artifacts(db_path: Path, max_items: int = 150) -> List[Dict[str, Any]]:
    """
    Carves human-readable messages, timestamps, and JSON strings from raw
    database pages and companion WAL files when no decryption key is available.
    """
    artifacts: List[Dict[str, Any]] = []
    seen_texts: Set[str] = set()

    target_files = [db_path]
    wal_file = db_path.with_name(db_path.name + "-wal")
    if wal_file.is_file():
        target_files.append(wal_file)

    msg_pattern = re.compile(rb"[\x20-\x7E\t\r\n]{6,250}")
    phone_pattern = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b")
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

    for f in target_files:
        try:
            data = f.read_bytes()
            matches = msg_pattern.findall(data)
            for m in matches:
                try:
                    s = m.decode("utf-8", errors="ignore").strip()
                    # Filter out binary junk / repetitive chars
                    if len(s) < 6 or len(set(s)) < 4:
                        continue
                    if s.startswith("SQLite format") or s.startswith("PRAGMA"):
                        continue
                    if s in seen_texts:
                        continue

                    # Check for high forensic value
                    item_type = "text"
                    if phone_pattern.search(s):
                        item_type = "phone_reference"
                    elif email_pattern.search(s):
                        item_type = "email_reference"
                    elif "{" in s and "}" in s and ":" in s:
                        item_type = "json_payload"

                    seen_texts.add(s)
                    artifacts.append({
                        "file": f.name,
                        "type": item_type,
                        "content": s,
                    })

                    if len(artifacts) >= max_items:
                        return artifacts
                except Exception:
                    continue
        except Exception:
            pass

    return artifacts


# ── 4. Unified Advanced Decryption Orchestrator ───────────────────────

def deep_unlock_database(
    db_path: Path,
    bundle_id: Optional[str] = None,
    container_dir: Optional[Path] = None,
    extra_keys: Optional[List[bytes]] = None,
    extra_passwords: Optional[List[str]] = None,
    export_dest: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    High-level forensic unlocking engine:
    1. Checks if unencrypted standard SQLite.
    2. Checks if WhatsApp crypt14/crypt15 AES backup and attempts GCM decryption.
    3. Scrapes local container files (.plist, .json, .xml) for hidden keys.
    4. Generates smart passcodes and dictionary derived keys.
    5. Tests candidates across all 9 SQLCipher profiles.
    6. Falls back to raw page & WAL artifact carving if key is unavailable.
    """
    db_path = Path(db_path).resolve()
    outcome: Dict[str, Any] = {
        "path": str(db_path),
        "status": "locked",
        "method": None,
        "key_bytes": None,
        "key_fingerprint": None,
        "profile": None,
        "tables": [],
        "carved_artifacts": [],
    }

    # Step 1: Plain SQLite Check
    if is_plain_sqlite(db_path):
        outcome["status"] = "plain"
        outcome["method"] = "plain_sqlite"
        try:
            con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            outcome["tables"] = [r[0] for r in cur.fetchall()]
            con.close()
        except Exception:
            pass
        return outcome

    # Step 2: WhatsApp Crypt14/15 AES Check
    if is_crypt_database(db_path) and CRYPTOGRAPHY_AVAILABLE:
        candidate_keys = []
        if extra_keys:
            candidate_keys.extend(extra_keys)
        # Try container keys
        if container_dir:
            scraped = scrape_container_secrets(container_dir)
            candidate_keys.extend([s["key_bytes"] for s in scraped if len(s["key_bytes"]) == 32])

        target_out = export_dest or db_path.with_suffix(".decrypted.sqlite")
        for k in candidate_keys:
            if len(k) == 32:
                try:
                    if decrypt_whatsapp_crypt14_15(db_path, target_out, k):
                        outcome["status"] = "decrypted"
                        outcome["method"] = "whatsapp_crypt_aes_gcm"
                        outcome["key_bytes"] = k
                        outcome["key_fingerprint"] = fingerprint(k)
                        try:
                            con = sqlite3.connect(f"{target_out.resolve().as_uri()}?mode=ro", uri=True)
                            cur = con.cursor()
                            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
                            outcome["tables"] = [r[0] for r in cur.fetchall()]
                            con.close()
                        except Exception:
                            pass
                        return outcome
                except Exception:
                    continue

    # Step 3: Gather candidates from Container Scrape & Smart Wordlists
    candidate_pool: List[Dict[str, Any]] = []

    if extra_keys:
        for k in extra_keys:
            candidate_pool.append({
                "key_bytes": k,
                "fingerprint": fingerprint(k),
                "source": "extra_keys",
                "method": "manual_supplied_key",
            })

    if container_dir:
        candidate_pool.extend(scrape_container_secrets(container_dir))

    candidate_pool.extend(generate_smart_keys(passwords=extra_passwords))

    # Step 4: Test SQLCipher Profiles against all candidate keys
    for cand in candidate_pool:
        kb = cand["key_bytes"]
        key_hex = kb.hex()
        for prof in PROFILES:
            try:
                con = sqlcipher.connect(str(db_path))
                con.execute(f"PRAGMA key = \"x'{key_hex}'\";")
                for p in prof["pragmas"]:
                    con.execute(p)
                con.execute("SELECT count(*) FROM sqlite_master;").fetchone()

                # Success!
                cur = con.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
                tables = [r[0] for r in cur.fetchall()]
                con.close()

                outcome["status"] = "decrypted"
                outcome["method"] = cand["method"]
                outcome["key_bytes"] = kb
                outcome["key_fingerprint"] = cand["fingerprint"]
                outcome["profile"] = prof["name"]
                outcome["tables"] = tables
                return outcome
            except Exception:
                try:
                    con.close()
                except Exception:
                    pass

    # Step 5: Fallback to Raw String / WAL Artifact Carving
    outcome["carved_artifacts"] = carve_text_artifacts(db_path, max_items=100)
    return outcome
