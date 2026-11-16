import plistlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

DB_EXTENSIONS: Set[str] = {".sqlite", ".sqlite3", ".db", ".sqlitedb", ".storedata"}
JOURNAL_SUFFIXES: Set[str] = {"-wal", "-shm", "-journal"}


@dataclass
class DiscoveredDatabase:
    path: Path
    relpath: str
    name: str
    size_bytes: int
    container_type: Optional[str] = None
    container_uuid: Optional[str] = None
    bundle_id: Optional[str] = None
    has_wal: bool = False
    has_shm: bool = False
    has_journal: bool = False


def _find_container_info(db_path: Path, root: Path) -> Dict[str, Optional[str]]:
    """
    Climbs up the directory hierarchy from db_path up to root looking for
    .com.apple.mobile_container_manager.metadata.plist.
    Extracts bundle_id (MCMMetadataIdentifier), container_uuid, and container_type.
    """
    curr = db_path.parent
    root_resolved = root.resolve()

    while True:
        plist_path = curr / ".com.apple.mobile_container_manager.metadata.plist"
        if plist_path.is_file():
            bundle_id = None
            category = None
            try:
                with open(plist_path, "rb") as f:
                    plist_data = plistlib.load(f)
                    if isinstance(plist_data, dict):
                        bundle_id = plist_data.get("MCMMetadataIdentifier") or plist_data.get("CFBundleIdentifier")
                        category = plist_data.get("MCMMetadataCategory")
            except Exception:
                pass

            container_uuid = curr.name
            container_type = None
            parts = curr.parts
            if "AppGroup" in parts or category == 7:
                container_type = "AppGroup"
            elif "Application" in parts or category == 2:
                container_type = "Application"
            elif "PluginKitPlugin" in parts or category == 4:
                container_type = "PluginKitPlugin"

            return {
                "bundle_id": str(bundle_id) if bundle_id else None,
                "container_uuid": container_uuid,
                "container_type": container_type,
            }

        if curr.resolve() == root_resolved or curr.parent == curr:
            break
        curr = curr.parent

    return {
        "bundle_id": None,
        "container_uuid": None,
        "container_type": None,
    }


def scan_extraction(root: str | Path) -> List[DiscoveredDatabase]:
    """
    Recursively scans extraction root directory for SQLite databases.
    Identifies paired WAL / SHM / journal files and associates databases with
    their container metadata.
    Returns list of DiscoveredDatabase sorted by relative path.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"Extraction root directory not found: {root}")

    databases: List[DiscoveredDatabase] = []

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        lower_name = file_path.name.lower()

        # Skip journal/wal/shm companion files
        if any(lower_name.endswith(suffix) for suffix in JOURNAL_SUFFIXES):
            continue

        suffix = file_path.suffix.lower()
        if suffix not in DB_EXTENSIONS:
            continue

        relpath = file_path.relative_to(root).as_posix()
        size_bytes = file_path.stat().st_size

        parent = file_path.parent
        wal_path = parent / (file_path.name + "-wal")
        shm_path = parent / (file_path.name + "-shm")
        journal_path = parent / (file_path.name + "-journal")

        container_info = _find_container_info(file_path, root)

        databases.append(
            DiscoveredDatabase(
                path=file_path,
                relpath=relpath,
                name=file_path.name,
                size_bytes=size_bytes,
                container_type=container_info["container_type"],
                container_uuid=container_info["container_uuid"],
                bundle_id=container_info["bundle_id"],
                has_wal=wal_path.is_file(),
                has_shm=shm_path.is_file(),
                has_journal=journal_path.is_file(),
            )
        )

    databases.sort(key=lambda d: d.relpath)
    return databases
