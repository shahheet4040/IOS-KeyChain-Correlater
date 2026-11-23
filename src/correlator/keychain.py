import base64
import binascii
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from correlator.sqlcipher_util import fingerprint

HINT_WORDS = ["key", "cipher", "grdb", "database", "sqlcipher", "encrypt"]

# Protection class descriptions conforming to Apple iOS Security Guide
PROTECTION_CLASSES = {
    "ck": ("Class C (AfterFirstUnlock)", "Accessible after device is unlocked once post-boot until power off.", False),
    "ksecattraccessibleafterfirstunlock": ("Class C (AfterFirstUnlock)", "Accessible after device is unlocked once post-boot until power off.", False),
    "cku": ("Class C (AfterFirstUnlockThisDeviceOnly)", "Device-bound; accessible after first unlock; not migrated in backups.", False),
    "ksecattraccessibleafterfirstunlockthisdeviceonly": ("Class C (AfterFirstUnlockThisDeviceOnly)", "Device-bound; accessible after first unlock; not migrated in backups.", False),
    "ak": ("Class A (WhenUnlocked)", "Accessible only while device is currently unlocked by the user.", False),
    "ksecattraccessiblewhenunlocked": ("Class A (WhenUnlocked)", "Accessible only while device is currently unlocked by the user.", False),
    "aku": ("Class A (WhenUnlockedThisDeviceOnly)", "Device-bound; accessible only while device is currently unlocked.", False),
    "ksecattraccessiblewhenunlockedthisdeviceonly": ("Class A (WhenUnlockedThisDeviceOnly)", "Device-bound; accessible only while device is currently unlocked.", False),
    "dku": ("Class D (Always)", "Accessible at all times, even before device unlock (legacy/deprecated).", False),
    "ksecattraccessiblealways": ("Class D (Always)", "Accessible at all times, even before device unlock (legacy/deprecated).", False),
    "akpu": ("Class A (WhenPasscodeSetThisDeviceOnly)", "Requires active device passcode set; device-bound.", False),
    "ksecattraccessiblewhenpasscodesetthisdeviceonly": ("Class A (WhenPasscodeSetThisDeviceOnly)", "Requires active device passcode set; device-bound.", False),
}


def classify_protection_class(raw_pdmn: str, access_control: str = "") -> Tuple[str, str, bool]:
    """
    Classifies Apple Data Protection Class and Biometric / Secure Enclave flags.
    Returns (protection_class_name, description, is_biometric).
    """
    clean_pdmn = str(raw_pdmn or "").strip().lower()
    clean_ac = str(access_control or "").strip().lower()

    is_biometric = any(b in clean_ac or b in clean_pdmn for b in ("biometry", "touchid", "faceid", "userpresence"))
    
    if clean_pdmn in PROTECTION_CLASSES:
        name, desc, _ = PROTECTION_CLASSES[clean_pdmn]
        return name, desc, is_biometric

    # Partial / substring matching
    for k, (name, desc, _) in PROTECTION_CLASSES.items():
        if k in clean_pdmn:
            return name, desc, is_biometric

    if not clean_pdmn:
        return "Unspecified", "Protection class not explicitly recorded in export.", is_biometric

    return clean_pdmn, f"Custom or raw protection domain: {clean_pdmn}", is_biometric


def load_keychain(path: str | Path) -> Tuple[List[Dict[str, Any]], int]:
    """
    Reads a normalized keychain JSON export file.
    Returns (rows, skipped_count).
    Fills missing text fields with empty strings.
    Invalid base64 rows are skipped.
    Raises ValueError if file content is not a JSON list.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Keychain file not found: {path}")

    # If non-json forensic format is supplied (plist, xml, csv), use importer
    if path.suffix.lower() in (".plist", ".xml", ".csv"):
        from correlator.importer import import_keychain
        items, _ = import_keychain(path)
        data = items
    else:
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as e:
                raise ValueError(f"Invalid JSON format in {path}: {e}")

    if not isinstance(data, list):
        raise ValueError("Keychain file must contain a JSON list")

    rows = []
    skipped = 0

    for item in data:
        if not isinstance(item, dict):
            skipped += 1
            continue

        val_b64 = item.get("value_b64")
        if not isinstance(val_b64, str):
            skipped += 1
            continue

        try:
            key_bytes = base64.b64decode(val_b64, validate=True)
        except (binascii.Error, ValueError):
            skipped += 1
            continue

        service = str(item.get("service") or "")
        account = str(item.get("account") or "")
        access_group = str(item.get("access_group") or "")
        raw_pdmn = str(item.get("protection_class") or item.get("pdmn") or item.get("accessible") or "")
        access_ctrl = str(item.get("access_control") or item.get("acflags") or "")
        prot_class, prot_desc, is_bio = classify_protection_class(raw_pdmn, access_ctrl)

        rows.append({
            "service": service,
            "account": account,
            "access_group": access_group,
            "key_bytes": key_bytes,
            "fingerprint": fingerprint(key_bytes),
            "protection_class": prot_class,
            "protection_description": prot_desc,
            "is_biometric": is_bio,
        })

    return rows, skipped


def candidates(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filters rows for 32 or 48 byte key candidates.
    Deduplicates identical keys (keeping the one with the higher hint_score).
    Sorts candidates by hint_score descending, then fingerprint ascending.
    """
    # Keyed by key_bytes: store candidate with highest hint_score
    by_key: Dict[bytes, Dict[str, Any]] = {}

    for row in rows:
        kb = row["key_bytes"]
        if len(kb) not in (32, 48):
            continue

        combined = (row["service"] + " " + row["account"]).lower()
        hint_score = sum(1 for w in HINT_WORDS if w in combined)
        fp = fingerprint(kb)

        cand = {
            "key_bytes": kb,
            "fingerprint": fp,
            "service": row["service"],
            "account": row["account"],
            "access_group": row["access_group"],
            "hint_score": hint_score,
            "protection_class": row.get("protection_class", "Unspecified"),
            "protection_description": row.get("protection_description", ""),
            "is_biometric": row.get("is_biometric", False),
        }

        if kb not in by_key or hint_score > by_key[kb]["hint_score"]:
            by_key[kb] = cand

    result = list(by_key.values())
    result.sort(key=lambda c: (-c["hint_score"], c["fingerprint"]))
    return result
