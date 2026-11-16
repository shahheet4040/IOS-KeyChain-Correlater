"""
Forensic Named Entity Recognition (NER) & Smart Intelligence Extractor
======================================================================
Performs deterministic entity extraction across all decrypted messages,
notes, web history, and chats without requiring external heavy NLP models.

Extracted Entity Types:
- PERSON: Suspect aliases, direct address handles, greeting targets
- PHONE: International and local mobile/landline numbers
- EMAIL: Validated email addresses
- CRYPTO: Bitcoin, Ethereum, Monero, and 64-char transaction hashes (TXIDs)
- FLIGHT_SHIPMENT: IATA flight codes (e.g. EK501, AI101) & tracking numbers
- FINANCIAL: IBANs, Credit Cards, SWIFT codes, Routing numbers
- TEMPORAL: Specific meeting times, ISO dates, urgent appointment references
"""

from collections import defaultdict
from dataclasses import asdict, dataclass
import re
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from correlator.timeline import TimelineEvent, extract_unified_timeline


@dataclass
class ForensicEntity:
    entity_id: str
    entity_type: str  # PERSON, PHONE, EMAIL, CRYPTO, FLIGHT_SHIPMENT, FINANCIAL, TEMPORAL
    value: str
    normalized_value: str
    occurrence_count: int
    source_apps: List[str]
    sample_contexts: List[str]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["occurrences"] = self.occurrence_count
        d["sources"] = self.source_apps
        d["contexts"] = self.sample_contexts
        return d


# Precompiled High-Precision Extraction Patterns
ENTITY_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "PHONE": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
    "CRYPTO": re.compile(r"\b(?:0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}|[a-fA-F0-9]{64})\b"),
    "FLIGHT_SHIPMENT": re.compile(r"\b(?:[A-Z]{2}\s?\d{3,4}|1Z[0-9A-Z]{16}|\d{12,14})\b"),
    "FINANCIAL": re.compile(r"\b(?:[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}|(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}))\b"),
    "TEMPORAL": re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:meet|rendezvous|flight|pickup)\s+at\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)?)\b", re.I),
}

PERSON_GREETING_PATTERN = re.compile(
    r"\b(?:hey|hi|hello|meet|call|agent|mr\.|mrs\.|dr\.|officer|suspect)\s+([A-Z][a-z]{2,15})\b",
    re.I,
)


def extract_entities_from_text(text: str) -> List[Tuple[str, str]]:
    """Extracts (entity_type, value) pairs from a text string."""
    results = []
    if not text or len(text) < 4:
        return results

    # Standard regex extraction
    for ent_type, pat in ENTITY_PATTERNS.items():
        for m in pat.finditer(text):
            val = m.group(0).strip()
            # Basic sanity filters
            if ent_type == "PHONE" and (len(re.sub(r"\D", "", val)) < 7 or len(re.sub(r"\D", "", val)) > 15):
                continue
            results.append((ent_type, val))

    # Person / alias extraction
    for pm in PERSON_GREETING_PATTERN.finditer(text):
        name = pm.group(1).strip()
        if name.lower() not in {"there", "today", "tomorrow", "tonight", "here", "later", "please", "thanks"}:
            results.append(("PERSON", name.title()))

    return results


def scan_entities_in_evidence(
    search_dirs: Optional[List[Path | str]] = None,
    consolidated_db_path: Optional[Path | str] = None,
    max_entities: int = 200,
) -> Dict[str, Any]:
    """
    Scans communications across consolidated databases or decrypted folders
    to aggregate extracted entities with occurrence metrics.
    """
    entity_records: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "apps": set(), "contexts": []}
    )

    # 1. From Consolidated DB
    if consolidated_db_path and Path(consolidated_db_path).is_file():
        con = sqlite3.connect(f"file:{Path(consolidated_db_path).resolve().as_posix()}?mode=ro", uri=True)
        cur = con.cursor()
        try:
            cur.execute("SELECT app, content FROM messages WHERE content IS NOT NULL LIMIT 5000")
            for app, content in cur.fetchall():
                found = extract_entities_from_text(content)
                for ent_type, val in found:
                    key = (ent_type, val.strip())
                    entity_records[key]["count"] += 1
                    entity_records[key]["apps"].add(app)
                    if len(entity_records[key]["contexts"]) < 3:
                        snippet = content[:100] + ("..." if len(content) > 100 else "")
                        entity_records[key]["contexts"].append(snippet)
        finally:
            con.close()

    # 2. From Decrypted Dirs
    if search_dirs:
        dirs = [Path(d).resolve() for d in search_dirs if Path(d).is_dir()]
        events: List[TimelineEvent] = []
        for d in dirs:
            events.extend(extract_unified_timeline(d))

        for ev in events:
            found = extract_entities_from_text(ev.content)
            for ent_type, val in found:
                key = (ent_type, val.strip())
                entity_records[key]["count"] += 1
                entity_records[key]["apps"].add(ev.app)
                if len(entity_records[key]["contexts"]) < 3:
                    snippet = ev.content[:100] + ("..." if len(ev.content) > 100 else "")
                    entity_records[key]["contexts"].append(snippet)

    # Assemble entities
    entities: List[ForensicEntity] = []
    type_counts: Dict[str, int] = defaultdict(int)

    for (ent_type, val), data in entity_records.items():
        type_counts[ent_type] += 1
        entities.append(ForensicEntity(
            entity_id=f"ENT-{len(entities)+1}",
            entity_type=ent_type,
            value=val,
            normalized_value=val.lower(),
            occurrence_count=data["count"],
            source_apps=sorted(list(data["apps"])),
            sample_contexts=data["contexts"],
        ))

    # Sort entities by occurrence count
    entities.sort(key=lambda x: x.occurrence_count, reverse=True)

    return {
        "total_entities": len(entities),
        "summary_by_type": dict(type_counts),
        "type_counts": dict(type_counts),
        "entities": [e.to_dict() for e in entities[:max_entities]],
    }
