"""
Universal Keychain Importer for Digital Forensic Toolkits
=========================================================
Converts raw keychain dumps from real-world forensic acquisition tools
(Frida/Keychain-Dumper, Cellebrite UFED, Elcomsoft EIFT, Apple Plists, CSV/XML)
into the standardized normalized format expected by the iOS Keychain Correlator:

[
  {
    "service": "...",
    "account": "...",
    "access_group": "...",
    "value_b64": "..."
  }
]
"""

import base64
import csv
import json
import os
from pathlib import Path
import plistlib
import re
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET


def _to_b64(raw: Any) -> Optional[str]:
    """Convert string, hex string, bytes, or raw base64 to clean base64 string."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return base64.b64encode(raw).decode("utf-8")
    if isinstance(raw, str):
        raw = raw.strip()
        if not raw:
            return None
        # Check if already valid base64
        try:
            decoded = base64.b64decode(raw, validate=True)
            if len(decoded) > 0:
                return raw
        except Exception:
            pass

        # Check if hex string (e.g. 0x..., or continuous hex digits)
        clean_hex = raw.lower().replace("0x", "").replace(" ", "").replace(":", "")
        if clean_hex and len(clean_hex) % 2 == 0 and all(c in "0123456789abcdef" for c in clean_hex):
            try:
                b = bytes.fromhex(clean_hex)
                return base64.b64encode(b).decode("utf-8")
            except Exception:
                pass

        # Treat as raw UTF-8 string payload
        return base64.b64encode(raw.encode("utf-8", errors="replace")).decode("utf-8")

    return None


def parse_frida_keychain_dump(data: Any) -> List[Dict[str, str]]:
    """
    Parses outputs from Frida scripts (e.g. keychain-dump) and Keychain-Dumper.
    Often outputs JSON lists of dictionaries with keys like:
    'service', 'account', 'access_group', 'data', 'v_Data', 'kSecValueData'
    """
    items = []
    if isinstance(data, dict):
        if "items" in data:
            data = data["items"]
        elif "results" in data:
            data = data["results"]
        elif "keychain" in data:
            data = data["keychain"]
        else:
            data = [data]

    if not isinstance(data, list):
        return items

    for entry in data:
        if not isinstance(entry, dict):
            continue
        service = str(entry.get("service") or entry.get("svce") or entry.get("kSecAttrService") or "")
        account = str(entry.get("account") or entry.get("acct") or entry.get("kSecAttrAccount") or "")
        agrp = str(entry.get("access_group") or entry.get("agrp") or entry.get("kSecAttrAccessGroup") or "")
        
        raw_val = (
            entry.get("value_b64")
            or entry.get("data")
            or entry.get("v_Data")
            or entry.get("kSecValueData")
            or entry.get("value")
        )
        b64 = _to_b64(raw_val)
        if b64:
            items.append({
                "service": service,
                "account": account,
                "access_group": agrp,
                "value_b64": b64
            })
    return items


def parse_plist_keychain(plist_bytes: bytes) -> List[Dict[str, str]]:
    """
    Parses Apple binary or XML plists containing keychain entries
    (e.g. from decrypted backups, Apple Configurator, or raw keychain.plist).
    """
    items = []
    try:
        obj = plistlib.loads(plist_bytes)
    except Exception:
        return items

    def _extract_from_plist_obj(target: Any):
        if isinstance(target, dict):
            # Check if this dict itself looks like a keychain record
            has_data = any(k in target for k in ("v_Data", "kSecValueData", "data", "value"))
            if has_data:
                svc = str(target.get("svce") or target.get("service") or target.get("kSecAttrService") or "")
                acct = str(target.get("acct") or target.get("account") or target.get("kSecAttrAccount") or "")
                agrp = str(target.get("agrp") or target.get("access_group") or target.get("kSecAttrAccessGroup") or "")
                raw_val = target.get("v_Data") or target.get("kSecValueData") or target.get("data") or target.get("value")
                b64 = _to_b64(raw_val)
                if b64:
                    items.append({
                        "service": svc,
                        "account": acct,
                        "access_group": agrp,
                        "value_b64": b64
                    })
            # Also recurse on sub-dictionaries (e.g. 'genp', 'inet', 'cert', 'keys')
            for val in target.values():
                _extract_from_plist_obj(val)
        elif isinstance(target, list):
            for elem in target:
                _extract_from_plist_obj(elem)

    _extract_from_plist_obj(obj)
    return items


def parse_cellebrite_xml(xml_content: str) -> List[Dict[str, str]]:
    """
    Parses Cellebrite UFED / Physical Analyzer exported Keychain XML.
    """
    items = []
    try:
        root = ET.fromstring(xml_content)
    except Exception:
        return items

    # Search for all elements that represent keychain records
    for elem in root.iter():
        tag = elem.tag.lower()
        if "item" in tag or "keychain" in tag or "record" in tag:
            svc = ""
            acct = ""
            agrp = ""
            val = None

            for child in elem:
                c_tag = child.tag.lower()
                c_text = child.text or ""
                if "service" in c_tag:
                    svc = c_text
                elif "account" in c_tag:
                    acct = c_text
                elif "group" in c_tag:
                    agrp = c_text
                elif "value" in c_tag or "data" in c_tag or "password" in c_tag:
                    val = c_text

            if not val and elem.attrib:
                val = elem.attrib.get("value") or elem.attrib.get("data")
                svc = svc or elem.attrib.get("service", "")
                acct = acct or elem.attrib.get("account", "")
                agrp = agrp or elem.attrib.get("access_group", "")

            if val:
                b64 = _to_b64(val)
                if b64:
                    items.append({
                        "service": svc.strip(),
                        "account": acct.strip(),
                        "access_group": agrp.strip(),
                        "value_b64": b64
                    })
    return items


def parse_csv_keychain(csv_content: str) -> List[Dict[str, str]]:
    """
    Parses generic CSV exports from Elcomsoft EIFT, Cellebrite, or custom exports.
    Identifies column headers flexibly (service, account, access_group, value/data).
    """
    items = []
    lines = csv_content.splitlines()
    if not lines:
        return items

    reader = csv.reader(lines)
    header = next(reader, None)
    if not header:
        return items

    col_map = {}
    for idx, col in enumerate(header):
        norm = col.lower().strip().replace(" ", "_")
        if "service" in norm or "svce" in norm:
            col_map["service"] = idx
        elif "account" in norm or "acct" in norm or "user" in norm:
            col_map["account"] = idx
        elif "group" in norm or "agrp" in norm:
            col_map["access_group"] = idx
        elif any(v in norm for v in ("value", "data", "key", "payload", "secret", "password")):
            col_map["value"] = idx

    if "value" not in col_map:
        return items

    for row in reader:
        if not row or len(row) <= col_map["value"]:
            continue
        val = row[col_map["value"]]
        svc = row[col_map["service"]] if "service" in col_map and len(row) > col_map["service"] else ""
        acct = row[col_map["account"]] if "account" in col_map and len(row) > col_map["account"] else ""
        agrp = row[col_map["access_group"]] if "access_group" in col_map and len(row) > col_map["access_group"] else ""

        b64 = _to_b64(val)
        if b64:
            items.append({
                "service": svc.strip(),
                "account": acct.strip(),
                "access_group": agrp.strip(),
                "value_b64": b64
            })
    return items


def import_keychain(source_path: str | Path, output_json: Optional[str | Path] = None) -> Tuple[List[Dict[str, str]], str]:
    """
    Universal importer: automatically detects file format and converts to normalized keychain format.
    Returns (items_list, detected_format_name).
    """
    p = Path(source_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Source file not found: {p}")

    raw_bytes = p.read_bytes()
    items = []
    detected_format = "unknown"

    # 1. Try Plist format (binary or XML plist)
    if raw_bytes.startswith(b"bplist") or b"<!DOCTYPE plist" in raw_bytes[:200] or b"<plist" in raw_bytes[:200]:
        items = parse_plist_keychain(raw_bytes)
        if items:
            detected_format = "Apple Plist (bplist / XML)"

    # 2. Try JSON (Frida / Keychain-Dumper / Correlator native)
    if not items:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            json_obj = json.loads(text)
            items = parse_frida_keychain_dump(json_obj)
            if items:
                detected_format = "Frida / JSON Dump"
        except Exception:
            pass

    # 3. Try XML (Cellebrite UFED / Physical Analyzer)
    if not items:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            if "<" in text and ">" in text:
                items = parse_cellebrite_xml(text)
                if items:
                    detected_format = "Cellebrite / Forensic XML"
        except Exception:
            pass

    # 4. Try CSV (Elcomsoft EIFT / UFED CSV)
    if not items:
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            items = parse_csv_keychain(text)
            if items:
                detected_format = "Forensic CSV Export"
        except Exception:
            pass

    if output_json and items:
        out_p = Path(output_json).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)

    return items, detected_format
