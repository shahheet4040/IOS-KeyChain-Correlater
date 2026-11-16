"""
Automated Forensic Watchlists & Keyword Alert Engine
====================================================
Performs pattern recognition, regular expression matching, and semantic lexicons
against all decrypted databases and text columns. Flags high-priority findings:
- Cryptocurrency Wallets (Bitcoin, Ethereum/EVM, Monero, Bech32)
- Financial & Banking (IBANs, Credit Cards, SWIFT codes, Wires)
- Narcotics & Controlled Substances
- Weapons, Firearms & Explosives
- Leaked Credentials, Secret Keys & Seed Phrases
- Case-specific examiner watchlists
"""

from dataclasses import asdict, dataclass
import re
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class WatchlistAlert:
    alert_id: str
    category: str
    matched_term: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    database_name: str
    table_name: str
    column_name: str
    context_snippet: str
    row_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Precompiled High-Confidence Regex Patterns
PATTERNS = {
    "Crypto": [
        (re.compile(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b"), "Bitcoin Address", "HIGH"),
        (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "Ethereum / EVM Address", "HIGH"),
        (re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), "Monero Wallet", "HIGH"),
        (re.compile(r"\b(seed phrase|bip39|mnemonic|private key|metamask|trezor)\b", re.I), "Crypto Key/Seed Phrase", "CRITICAL"),
    ],
    "Financial": [
        (re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b"), "IBAN Account Number", "HIGH"),
        (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "Credit Card Number", "CRITICAL"),
        (re.compile(r"\b(wire transfer|money mule|offshore account|swift code|routing number)\b", re.I), "Suspicious Financial Operation", "HIGH"),
    ],
    "Narcotics": [
        (re.compile(r"\b(fentanyl|cocaine|methamphetamine|heroin|oxycodone|mdma|ketamine|cartel|kilo|stash house)\b", re.I), "Narcotics Trafficking Term", "CRITICAL"),
        (re.compile(r"\b(grams|ounces|dropsite|dealer|substances|pills)\b", re.I), "Controlled Substance Indicator", "MEDIUM"),
    ],
    "Weapons": [
        (re.compile(r"\b(glock|ak-47|ak47|ar-15|ar15|ghost gun|silencer|suppressor|c4 explosive|detonator)\b", re.I), "Firearm / Weapon Trafficking", "CRITICAL"),
        (re.compile(r"\b(ammo|ammunition|magazine|caliber|handgun|rifle)\b", re.I), "Weaponry Component", "HIGH"),
    ],
    "Credentials": [
        (re.compile(r"\b(bearer [a-zA-Z0-9_\-\.]{20,}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9\-]{20,})\b", re.I), "API Token / Bearer Key", "CRITICAL"),
        (re.compile(r"\b(password|passwd|secret_key|masterkey)\b", re.I), "Exposed Password/Key Keyword", "MEDIUM"),
    ],
}


def _luhn_check(pan: str) -> bool:
    """Verifies potential credit card / account number using Luhn algorithm."""
    digits = [int(c) for c in pan if c.isdigit()]
    if len(digits) < 2 or len(digits) > 30:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum % 10) == 0


def scan_database_for_alerts(
    db_path: Path,
    custom_keywords: Optional[List[str]] = None,
    max_alerts_per_db: int = 100,
) -> List[WatchlistAlert]:
    alerts = []
    p = Path(db_path).resolve()
    if not p.is_file():
        return alerts

    # Prepare custom compiled regex if supplied
    custom_regex = None
    if custom_keywords:
        escaped = [re.escape(k.strip()) for k in custom_keywords if k.strip()]
        if escaped:
            custom_regex = re.compile(r"\b(" + "|".join(escaped) + r")\b", re.I)

    try:
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [r[0] for r in cur.fetchall()]

        for tbl in tables:
            try:
                cur.execute(f'SELECT * FROM "{tbl}" LIMIT 500;')
                col_names = [d[0] for d in cur.description] if cur.description else []
                rows = cur.fetchall()

                for row_idx, row in enumerate(rows):
                    row_dict = {col_names[i]: str(v) if v is not None else None for i, v in enumerate(row)}

                    for c_idx, cell in enumerate(row):
                        if cell is None:
                            continue
                        text = str(cell).strip()
                        if len(text) < 3:
                            continue

                        # 1. Custom Keywords
                        if custom_regex:
                            m = custom_regex.search(text)
                            if m:
                                matched_str = m.group(0)
                                start = max(0, m.start() - 30)
                                end = min(len(text), m.end() + 30)
                                snippet = ("..." if start > 0 else "") + text[start:end] + ("..." if end < len(text) else "")

                                alerts.append(WatchlistAlert(
                                    alert_id=f"ALT-CUST-{len(alerts)+1}",
                                    category="Custom Watchlist",
                                    matched_term=matched_str,
                                    severity="HIGH",
                                    database_name=p.name,
                                    table_name=tbl,
                                    column_name=col_names[c_idx],
                                    context_snippet=snippet,
                                    row_data=row_dict,
                                ))

                        # 2. Built-in Categories
                        for category, pattern_list in PATTERNS.items():
                            for regex, label, severity in pattern_list:
                                match = regex.search(text)
                                if match:
                                    matched_val = match.group(0)
                                    # Validate PAN if credit card
                                    if "Credit Card" in label and not _luhn_check(matched_val):
                                        continue

                                    start = max(0, match.start() - 30)
                                    end = min(len(text), match.end() + 30)
                                    snippet = ("..." if start > 0 else "") + text[start:end] + ("..." if end < len(text) else "")

                                    alerts.append(WatchlistAlert(
                                        alert_id=f"ALT-{category[:3].upper()}-{len(alerts)+1}",
                                        category=category,
                                        matched_term=f"{label}: {matched_val}",
                                        severity=severity,
                                        database_name=p.name,
                                        table_name=tbl,
                                        column_name=col_names[c_idx],
                                        context_snippet=snippet,
                                        row_data=row_dict,
                                    ))

                                    if len(alerts) >= max_alerts_per_db:
                                        con.close()
                                        return alerts
            except Exception:
                continue

        con.close()
    except Exception:
        pass

    return alerts


def scan_evidence_for_alerts(
    evidence_directory: Path | str,
    custom_keywords: Optional[List[str]] = None,
    max_total_alerts: int = 500,
) -> List[WatchlistAlert]:
    """
    Scans all decrypted SQLite databases in directory against intelligence watchlists.
    Returns prioritized list of forensic alert objects.
    """
    d = Path(evidence_directory).resolve()
    all_alerts: List[WatchlistAlert] = []

    if not d.is_dir():
        return all_alerts

    for db_file in d.rglob("*"):
        if db_file.is_file() and db_file.suffix.lower() in (".sqlite", ".db", ".sqlite3"):
            db_alerts = scan_database_for_alerts(db_file, custom_keywords=custom_keywords)
            all_alerts.extend(db_alerts)
            if len(all_alerts) >= max_total_alerts:
                break

    # Prioritize CRITICAL -> HIGH -> MEDIUM
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_alerts.sort(key=lambda a: severity_order.get(a.severity, 3))
    return all_alerts[:max_total_alerts]
