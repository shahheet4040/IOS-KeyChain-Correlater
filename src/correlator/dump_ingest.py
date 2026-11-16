"""
Cellebrite / GrayKey / iTunes Dump Auto-Ingestion Engine
========================================================
Automatically detects forensic dump formats from major extraction tools,
locates keychain files and application databases, normalizes the folder
structure, and feeds everything into the correlation pipeline.

Supported formats:
  - Cellebrite UFED / Physical Analyzer exports
  - GrayKey full file system extractions
  - iTunes / Finder encrypted/unencrypted backups
  - Generic folder dumps (flat directory of databases + keychain)
"""

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Format Detection ────────────────────────────────────────────────

CELLEBRITE_MARKERS = [
    "report.xml", "UFEDReaderReport", "Report.xml",
    "Chats", "Contacts", "Locations", "InstalledApplications",
]
CELLEBRITE_EXTENSIONS = {".ufd", ".ufdr", ".zip"}

GRAYKEY_MARKERS = [
    "device_info.plist", "keychain", "files",
]

ITUNES_MARKERS = [
    "Manifest.db", "Manifest.plist", "Info.plist", "Status.plist",
]


def detect_dump_format(dump_path: str | Path) -> str:
    """
    Auto-detect the format of a forensic dump folder.

    Returns one of:
      'cellebrite'  — Cellebrite UFED / Physical Analyzer
      'graykey'     — GrayKey full filesystem
      'itunes'      — iTunes / Finder backup
      'generic'     — Unrecognized / flat dump
    """
    p = Path(dump_path).resolve()
    if not p.is_dir():
        return "generic"

    children = {c.name for c in p.iterdir()}
    extensions = {c.suffix.lower() for c in p.iterdir() if c.is_file()}

    # Check Cellebrite markers
    cellebrite_hits = sum(1 for m in CELLEBRITE_MARKERS if m in children)
    has_ufd = bool(CELLEBRITE_EXTENSIONS & extensions)
    if cellebrite_hits >= 2 or has_ufd:
        return "cellebrite"

    # Check GrayKey markers
    graykey_hits = sum(1 for m in GRAYKEY_MARKERS if m in children)
    if graykey_hits >= 2:
        return "graykey"

    # Check iTunes/Finder backup
    itunes_hits = sum(1 for m in ITUNES_MARKERS if m in children)
    if itunes_hits >= 2:
        return "itunes"

    return "generic"


# ── Keychain Locator ────────────────────────────────────────────────

def locate_keychain_in_dump(
    dump_path: str | Path,
    fmt: Optional[str] = None,
) -> Optional[Path]:
    """
    Finds the keychain file inside a forensic dump.
    Searches format-specific locations first, then falls back to recursive scan.
    """
    p = Path(dump_path).resolve()
    if fmt is None:
        fmt = detect_dump_format(p)

    # Format-specific search paths
    search_dirs: List[str] = []
    if fmt == "cellebrite":
        search_dirs = ["Passwords", "Keychain", "Artifacts", "keychain", "passwords"]
    elif fmt == "graykey":
        search_dirs = ["keychain", "Keychain"]
    elif fmt == "itunes":
        search_dirs = ["KeychainDomain", "."]

    # Check known filenames in search dirs
    keychain_names = [
        "keychain-backup.plist", "keychain.plist",
        "keychain.json", "keychain-2.db",
        "genp.db", "keychain_data.plist",
    ]

    for subdir in search_dirs:
        d = p / subdir if subdir != "." else p
        if d.is_dir():
            for name in keychain_names:
                candidate = d / name
                if candidate.is_file():
                    return candidate
            # Check any plist in the directory
            for f in d.iterdir():
                if f.is_file() and f.suffix.lower() == ".plist" and "keychain" in f.name.lower():
                    return f

    # Fallback: recursive scan for anything keychain-related
    for pattern in ["*keychain*", "*Keychain*"]:
        for f in p.rglob(pattern):
            if f.is_file() and f.suffix.lower() in (".plist", ".json", ".xml", ".csv", ".db"):
                return f

    return None


# ── Database Locator ────────────────────────────────────────────────

DB_EXTENSIONS = {".sqlite", ".db", ".sqlite3", ".sqlitedb"}
SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv"}


def locate_databases_in_dump(
    dump_path: str | Path,
    fmt: Optional[str] = None,
) -> List[Path]:
    """
    Finds all SQLite / SQLCipher database files in a forensic dump.
    Returns sorted list of database Paths.
    """
    p = Path(dump_path).resolve()
    if fmt is None:
        fmt = detect_dump_format(p)

    # Format-specific top-level scan directories
    scan_roots: List[Path] = []
    if fmt == "cellebrite":
        for subdir in ["Applications", "files", "AppDomain", "UserData"]:
            d = p / subdir
            if d.is_dir():
                scan_roots.append(d)
        # Also check for AppDomain-* pattern
        for d in p.iterdir():
            if d.is_dir() and d.name.startswith("AppDomain-"):
                scan_roots.append(d)
    elif fmt == "graykey":
        for subdir in ["files", "Applications", "private"]:
            d = p / subdir
            if d.is_dir():
                scan_roots.append(d)
    elif fmt == "itunes":
        scan_roots.append(p)

    if not scan_roots:
        scan_roots = [p]

    databases: List[Path] = []
    seen: set = set()

    for root in scan_roots:
        for f in root.rglob("*"):
            if f.is_file() and f.suffix.lower() in DB_EXTENSIONS:
                if any(skip in f.parts for skip in SKIP_DIRS):
                    continue
                real = f.resolve()
                if real not in seen:
                    seen.add(real)
                    # Quick check: is it actually a sqlite file?
                    try:
                        header = f.read_bytes()[:16]
                        is_sqlite = header.startswith(b"SQLite format 3")
                        is_encrypted = len(header) >= 16 and not is_sqlite
                        if is_sqlite or is_encrypted:
                            databases.append(f)
                    except (OSError, PermissionError):
                        pass

    databases.sort(key=lambda x: str(x))
    return databases


# ── Dump Normalizer ─────────────────────────────────────────────────

def normalize_dump_to_extraction(
    dump_path: str | Path,
    output_path: str | Path,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> Dict[str, Any]:
    """
    Creates a normalized extraction folder structure from any supported dump format.

    Output structure:
      output_path/
        extraction/           — organized database files
        keychain.json         — normalized keychain (via universal importer)
        dump_info.json        — metadata about the ingestion

    Returns dict with: format, extraction_path, keychain_path, db_count, app_count
    """
    dump_p = Path(dump_path).resolve()
    out_p = Path(output_path).resolve()
    extraction_dir = out_p / "extraction"
    extraction_dir.mkdir(parents=True, exist_ok=True)

    fmt = detect_dump_format(dump_p)

    if progress_callback:
        progress_callback(f"Detected dump format: {fmt}", 0.1)

    # Locate keychain
    keychain_src = locate_keychain_in_dump(dump_p, fmt)
    keychain_out = out_p / "keychain.json"
    keychain_found = False

    if keychain_src:
        if progress_callback:
            progress_callback(f"Found keychain: {keychain_src.name}", 0.2)
        try:
            from correlator.importer import import_keychain
            items, detected_fmt = import_keychain(keychain_src, output_json=keychain_out)
            keychain_found = True
            if progress_callback:
                progress_callback(f"Imported {len(items)} keychain records ({detected_fmt})", 0.3)
        except Exception as e:
            if progress_callback:
                progress_callback(f"Keychain import failed: {e}", 0.3)
            # Copy raw file as fallback
            shutil.copy2(keychain_src, out_p / keychain_src.name)

    # Locate and organize databases
    databases = locate_databases_in_dump(dump_p, fmt)

    if progress_callback:
        progress_callback(f"Found {len(databases)} database files", 0.4)

    app_containers: Dict[str, int] = {}
    db_count = 0

    for i, db_path in enumerate(databases):
        # Try to determine the app container
        container_name = _guess_container_name(db_path, dump_p, fmt)
        app_containers[container_name] = app_containers.get(container_name, 0) + 1

        # Create container directory in extraction
        container_dir = extraction_dir / container_name
        container_dir.mkdir(parents=True, exist_ok=True)

        # Copy database + companion files (WAL, SHM)
        dest = container_dir / db_path.name
        if not dest.exists():
            shutil.copy2(db_path, dest)
            db_count += 1

            # Copy WAL and SHM if they exist
            for suffix in ["-wal", "-shm", "-journal"]:
                companion = db_path.with_name(db_path.name + suffix)
                if companion.is_file():
                    shutil.copy2(companion, container_dir / companion.name)

        if progress_callback and len(databases) > 0:
            pct = 0.4 + (0.5 * (i + 1) / len(databases))
            progress_callback(f"Copied: {container_name}/{db_path.name}", pct)

    # Write ingestion metadata
    info = {
        "source_path": str(dump_p),
        "detected_format": fmt,
        "keychain_found": keychain_found,
        "keychain_source": str(keychain_src) if keychain_src else None,
        "total_databases": db_count,
        "app_containers": len(app_containers),
        "container_details": app_containers,
    }
    with open(out_p / "dump_info.json", "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)

    if progress_callback:
        progress_callback("Normalization complete", 1.0)

    return {
        "format": fmt,
        "extraction_path": extraction_dir,
        "keychain_path": keychain_out if keychain_found else None,
        "db_count": db_count,
        "app_count": len(app_containers),
    }


def _guess_container_name(db_path: Path, dump_root: Path, fmt: str) -> str:
    """Guess the app container name from the database path."""
    try:
        rel = db_path.relative_to(dump_root)
        parts = rel.parts
    except ValueError:
        return "unknown_app"

    if fmt == "cellebrite":
        # Cellebrite uses AppDomain-<bundle_id> or Applications/<uuid>
        for i, part in enumerate(parts):
            if part.startswith("AppDomain-"):
                return part.replace("AppDomain-", "")
            if part == "Applications" and i + 1 < len(parts):
                return parts[i + 1]

    elif fmt == "graykey":
        # GrayKey uses files/private/var/mobile/Containers/Data/Application/<UUID>
        for i, part in enumerate(parts):
            if part in ("Application", "Containers") and i + 2 < len(parts):
                return parts[i + 1]

    elif fmt == "itunes":
        # iTunes backups use flat hash structure, but domain is in Manifest.db
        if len(parts) >= 2:
            return parts[0]

    # Fallback: use parent directory name
    if len(parts) >= 2:
        return parts[-2]
    return "root"


# ── End-to-End Ingest & Analyze ─────────────────────────────────────

def ingest_and_analyze(
    dump_path: str | Path,
    output_path: str | Path,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> Dict[str, Any]:
    """
    End-to-end pipeline: Detect format → Normalize → Correlate → Report.

    Returns dict with full pipeline results including:
      format, db_count, decrypted_count, report_html, etc.
    """
    out_p = Path(output_path).resolve()
    out_p.mkdir(parents=True, exist_ok=True)

    # Step 1: Normalize the dump
    norm = normalize_dump_to_extraction(
        dump_path, out_p,
        progress_callback=lambda msg, pct: progress_callback(msg, pct * 0.5) if progress_callback else None,
    )

    if not norm["keychain_path"] or not Path(norm["keychain_path"]).is_file():
        raise FileNotFoundError(
            f"No keychain file found in the dump at {dump_path}. "
            "Please provide a keychain export separately using --keychain."
        )

    if norm["db_count"] == 0:
        return {
            **norm,
            "decrypted_count": 0,
            "plain_count": 0,
            "locked_count": 0,
            "report_html": None,
            "message": "No databases found in the dump.",
        }

    # Step 2: Run correlation pipeline
    if progress_callback:
        progress_callback("Running correlation and decryption pipeline...", 0.55)

    from correlator.pipeline import execute_pipeline

    pipe_res = execute_pipeline(
        extraction=norm["extraction_path"],
        keychain=norm["keychain_path"],
        out_dir=out_p / "results",
        export_dir=out_p / "decrypted_exports",
    )

    if progress_callback:
        progress_callback("Analysis complete!", 1.0)

    return {
        **norm,
        "decrypted_count": pipe_res["decrypted_count"],
        "plain_count": pipe_res["plain_count"],
        "locked_count": pipe_res["locked_count"],
        "report_html": pipe_res["report_html_path"],
        "report_json": pipe_res["report_json_path"],
        "exported_files": pipe_res["exported_files"],
        "pipeline_result": pipe_res,
    }
