"""
Dedicated Application Profiles (Signal, Telegram, WhatsApp)
============================================================
Standardized forensic profiles for leading secure messaging apps on iOS:
- Signal Messenger (GRDB.swift / SQLCipher 4 / org.whispersystems.signal)
- Telegram Messenger (group.ph.telegra.Telegraph)
- WhatsApp Messenger (group.net.whatsapp.WhatsApp.shared / ChatStorage.sqlite)
"""

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from correlator.sqlcipher_util import try_key


@dataclass
class MessagingProfile:
    app_name: str
    bundle_id: str
    app_group_prefix: str
    keychain_service_match: str
    db_relative_paths: List[str]
    default_page_size: int
    default_compatibility: int


SIGNAL_PROFILE = MessagingProfile(
    app_name="Signal",
    bundle_id="org.whispersystems.signal",
    app_group_prefix="group.org.whispersystems.signal",
    keychain_service_match="org.whispersystems.signal",
    db_relative_paths=["Documents/signal.sqlite", "Documents/grdb.sqlite", "signal.sqlite"],
    default_page_size=4096,
    default_compatibility=4,
)

TELEGRAM_PROFILE = MessagingProfile(
    app_name="Telegram",
    bundle_id="ph.telegra.Telegraph",
    app_group_prefix="group.ph.telegra.Telegraph",
    keychain_service_match="ph.telegra.Telegraph",
    db_relative_paths=["data/tg_chats.sqlite", "data/account-*.sqlite", "Documents/Telegram.sqlite"],
    default_page_size=4096,
    default_compatibility=4,
)

WHATSAPP_PROFILE = MessagingProfile(
    app_name="WhatsApp",
    bundle_id="net.whatsapp.WhatsApp",
    app_group_prefix="group.net.whatsapp.WhatsApp.shared",
    keychain_service_match="net.whatsapp.WhatsApp",
    db_relative_paths=["ChatStorage.sqlite", "CallHistory.sqlite", "ContactsV2.sqlite"],
    default_page_size=4096,
    default_compatibility=4,
)

PROFILES = [SIGNAL_PROFILE, TELEGRAM_PROFILE, WHATSAPP_PROFILE]


def match_profile_for_container(bundle_or_group: str) -> Optional[MessagingProfile]:
    """Finds matching messaging profile for a given bundle ID or AppGroup."""
    clean = bundle_or_group.lower().strip()
    for prof in PROFILES:
        if prof.bundle_id.lower() in clean or prof.app_group_prefix.lower() in clean:
            return prof
    return None


def probe_signal_database(
    db_path: str | Path,
    key_candidates: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Attempts to decrypt a Signal iOS database using candidates from Keychain.
    Signal uses SQLCipher 4, 4096 page size, and a 32-byte raw key.
    """
    path = Path(db_path)
    if not path.is_file():
        return None

    for cand in key_candidates:
        kb = cand["key_bytes"]
        if len(kb) != 32:
            continue

        # Try raw hex key with SQLCipher 4 and 4096 page size
        res = try_key(
            path,
            kb,
            raw_key=True,
            cipher_version=4,
            page_size=4096,
            kdf_iter=64000,
        )
        if res.get("status") == "ok":
            return {
                "profile": "Signal",
                "database": str(path),
                "key_fingerprint": cand.get("fingerprint"),
                "tables": res.get("tables", []),
                "table_count": res.get("table_count", 0),
                "key_bytes": kb,
            }

    return None
