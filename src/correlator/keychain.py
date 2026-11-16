import base64
import binascii
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from correlator.sqlcipher_util import fingerprint

HINT_WORDS = ["key", "cipher", "grdb", "database", "sqlcipher", "encrypt"]


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

        rows.append({
            "service": service,
            "account": account,
            "access_group": access_group,
            "key_bytes": key_bytes,
            "fingerprint": fingerprint(key_bytes),
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
        }

        if kb not in by_key or hint_score > by_key[kb]["hint_score"]:
            by_key[kb] = cand

    result = list(by_key.values())
    result.sort(key=lambda c: (-c["hint_score"], c["fingerprint"]))
    return result
