from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from correlator.scanner import DiscoveredDatabase, scan_extraction
from correlator.sqlcipher_util import is_plain_sqlite, sha256_file


@dataclass
class TriageDatabase:
    path: Path
    relpath: str
    name: str
    size_bytes: int
    sha256: str
    classification: str  # "plain", "encrypted", "empty"
    container_type: Optional[str] = None
    container_uuid: Optional[str] = None
    bundle_id: Optional[str] = None
    has_wal: bool = False
    has_shm: bool = False
    has_journal: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relpath": self.relpath,
            "name": self.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "classification": self.classification,
            "container_type": self.container_type,
            "container_uuid": self.container_uuid,
            "bundle_id": self.bundle_id,
            "has_wal": self.has_wal,
            "has_shm": self.has_shm,
            "has_journal": self.has_journal,
        }


def classify(scratch_copy: str | Path) -> str:
    """Returns 'plain' if is_plain_sqlite is true, otherwise 'not_plain'."""
    p = Path(scratch_copy)
    return "plain" if is_plain_sqlite(p) else "not_plain"


def find_databases(root: str | Path) -> List[str]:
    """
    Walks the whole root. Keeps files ending in .sqlite, .sqlite3, .db or .sqlitedb
    with size above 0. Never returns names ending -wal, -shm or -journal.
    Returns paths relative to root with forward slashes, sorted.
    Unreadable files: skips and logs, never crashes.
    """
    root_path = Path(root).resolve()
    valid_extensions = {".sqlite", ".sqlite3", ".db", ".sqlitedb"}
    db_relpaths = []

    for item in root_path.rglob("*"):
        try:
            if not item.is_file():
                continue

            name = item.name.lower()
            if name.endswith("-wal") or name.endswith("-shm") or name.endswith("-journal"):
                continue

            if item.suffix.lower() in valid_extensions:
                if item.stat().st_size > 0:
                    rel = item.relative_to(root_path).as_posix()
                    db_relpaths.append(rel)
        except (PermissionError, OSError) as e:
            # Unreadable files: skip and add a note, never crash
            print(f"[NOTE] Skipping unreadable file {item}: {e}")
            continue

    db_relpaths.sort()
    return db_relpaths


def classify_database(db_path: str | Path) -> str:
    """
    Classifies a candidate database file into:
    - "empty": 0 bytes
    - "plain": unencrypted SQLite database
    - "encrypted": encrypted database (e.g. SQLCipher)
    """
    p = Path(db_path)
    if not p.is_file():
        raise ValueError(f"Database file not found: {p}")

    size = p.stat().st_size
    if size == 0:
        return "empty"

    if is_plain_sqlite(p):
        return "plain"

    return "encrypted"


def triage_extraction(root: str | Path) -> List[TriageDatabase]:
    """
    Discovers all candidate databases in the extraction root,
    computes SHA-256 digests, resolves container metadata,
    and triages each into plain vs encrypted without altering evidence.
    """
    discovered = scan_extraction(root)
    results: List[TriageDatabase] = []

    for d in discovered:
        digest = sha256_file(d.path)
        cls = classify_database(d.path)
        results.append(
            TriageDatabase(
                path=d.path,
                relpath=d.relpath,
                name=d.name,
                size_bytes=d.size_bytes,
                sha256=digest,
                classification=cls,
                container_type=d.container_type,
                container_uuid=d.container_uuid,
                bundle_id=d.bundle_id,
                has_wal=d.has_wal,
                has_shm=d.has_shm,
                has_journal=d.has_journal,
            )
        )

    results.sort(key=lambda r: r.relpath)
    return results
