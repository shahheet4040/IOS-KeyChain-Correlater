"""
Native iTunes & Apple Finder Backup Ingestion Module
====================================================
Ingests and reconstructs Apple iTunes / iOS Finder forensic backups
directly from their unencrypted or decrypted Manifest.db catalogs.

In an iTunes backup:
- Files are hashed into 40-character SHA-1 hex IDs
- Stored on disk at: <backup_root>/<hash[:2]>/<hash>
- Manifest.db records domain (e.g. AppDomain-net.whatsapp.WhatsApp)
  and relativePath (e.g. Documents/ChatStorage.sqlite)
"""

from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional


@dataclass
class iTunesFileRecord:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    physical_path: Path
    file_size: int


def is_itunes_backup(path: str | Path) -> bool:
    """
    Detects if a directory is an Apple iTunes / macOS Finder backup directory.
    Checks for presence of Manifest.db or Manifest.plist / Info.plist.
    """
    p = Path(path)
    if not p.is_dir():
        return False

    has_manifest_db = (p / "Manifest.db").is_file()
    has_manifest_plist = (p / "Manifest.plist").is_file()
    has_info_plist = (p / "Info.plist").is_file()

    return has_manifest_db or (has_manifest_plist and has_info_plist)


def parse_itunes_manifest(backup_path: str | Path) -> List[iTunesFileRecord]:
    """
    Parses Manifest.db in an iTunes backup directory.
    Returns a list of iTunesFileRecord objects mapping virtual iOS paths
    to their physical hash locations on disk.
    """
    backup_dir = Path(backup_path).resolve()
    manifest_db = backup_dir / "Manifest.db"

    if not manifest_db.is_file():
        raise FileNotFoundError(f"Manifest.db not found in backup directory: {backup_dir}")

    records = []
    # Open with strict 5s timeout to prevent locking
    conn = sqlite3.connect(str(manifest_db), timeout=5.0)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT fileID, domain, relativePath, flags FROM Files")
        rows = cursor.fetchall()

        for file_id, domain, rel_path, flags in rows:
            if not file_id or not rel_path:
                continue

            # Standard 2-character subfolder layout: <root>/<hash[:2]>/<hash>
            phys_path = backup_dir / file_id[:2] / file_id
            # Fallback for flat backup layout
            if not phys_path.is_file():
                flat_path = backup_dir / file_id
                if flat_path.is_file():
                    phys_path = flat_path

            file_size = phys_path.stat().st_size if phys_path.is_file() else 0

            records.append(iTunesFileRecord(
                file_id=str(file_id),
                domain=str(domain or ""),
                relative_path=str(rel_path or ""),
                flags=int(flags or 0),
                physical_path=phys_path,
                file_size=file_size,
            ))
    finally:
        conn.close()

    return records


def find_app_databases_in_itunes_backup(
    backup_path: str | Path,
    bundle_id_substr: str = "",
) -> List[iTunesFileRecord]:
    """
    Searches an iTunes backup for SQLite databases matching an application domain or bundle ID.
    """
    all_files = parse_itunes_manifest(backup_path)
    clean_sub = bundle_id_substr.strip().lower()

    matched = []
    for rec in all_files:
        if clean_sub and clean_sub not in rec.domain.lower():
            continue

        rel_lower = rec.relative_path.lower()
        if any(rel_lower.endswith(ext) for ext in (".sqlite", ".db", ".sqlite3")):
            if rec.physical_path.is_file():
                matched.append(rec)

    return matched
