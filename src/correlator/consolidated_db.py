"""
Consolidated Forensic Master Database Generator
================================================
Merges all disparate decrypted evidence, communications, geotags,
keyword alerts, and provenance audit trails into a single, unified,
relational SQLite database: `consolidated_case_evidence.sqlite`.

Unified Schema:
- case_info: Case metadata, examiner details, timestamps
- messages: Normalized cross-app communications (Signal, WhatsApp, WeChat, Safari visits)
- timeline_events: Chronological sequence of all interactions and events
- locations: Geotagged coordinates, photo EXIF metadata, camera make/model
- keyword_alerts: High-confidence intelligence alerts (Crypto, Financial, Weapons, Narcotics)
- audit_trail: Step-by-step cryptographic provenance and chain of custody
- decrypted_databases: Registry of unlocked databases, key fingerprints, table counts
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from correlator.geospatial import GeoPoint, scan_media_for_gps
from correlator.timeline import TimelineEvent, extract_unified_timeline
from correlator.watchlists import WatchlistAlert, scan_evidence_for_alerts


def init_consolidated_schema(con: sqlite3.Connection) -> None:
    """Initializes tables and high-performance indices in the master database."""
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS case_info (
            case_id TEXT PRIMARY KEY,
            case_name TEXT,
            case_number TEXT,
            examiner TEXT,
            description TEXT,
            created_at TEXT,
            exported_at TEXT,
            device_count INTEGER,
            summary_metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            app TEXT,
            event_type TEXT,
            timestamp_utc TEXT,
            timestamp_epoch REAL,
            sender TEXT,
            recipient TEXT,
            content TEXT,
            source_database TEXT,
            source_table TEXT,
            raw_metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS timeline_events (
            event_id TEXT PRIMARY KEY,
            timestamp_utc TEXT,
            timestamp_epoch REAL,
            app TEXT,
            event_type TEXT,
            sender TEXT,
            recipient TEXT,
            content TEXT,
            source_database TEXT,
            source_table TEXT,
            metadata_json TEXT
        );

        CREATE TABLE IF NOT EXISTS locations (
            location_id TEXT PRIMARY KEY,
            file_name TEXT,
            file_path TEXT,
            latitude REAL,
            longitude REAL,
            altitude REAL,
            timestamp_utc TEXT,
            timestamp_epoch REAL,
            camera_make TEXT,
            camera_model TEXT
        );

        CREATE TABLE IF NOT EXISTS keyword_alerts (
            alert_id TEXT PRIMARY KEY,
            category TEXT,
            matched_term TEXT,
            severity TEXT,
            database_name TEXT,
            table_name TEXT,
            column_name TEXT,
            context_snippet TEXT,
            row_data_json TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_trail (
            step_number INTEGER PRIMARY KEY,
            phase TEXT,
            action TEXT,
            target TEXT,
            status TEXT,
            timestamp TEXT,
            details_json TEXT
        );

        CREATE TABLE IF NOT EXISTS decrypted_databases (
            database_name TEXT PRIMARY KEY,
            source_path TEXT,
            status TEXT,
            key_fingerprint TEXT,
            profile TEXT,
            table_count INTEGER,
            row_count INTEGER,
            sha256_hash TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_messages_epoch ON messages(timestamp_epoch);
        CREATE INDEX IF NOT EXISTS idx_messages_app ON messages(app);
        CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);
        CREATE INDEX IF NOT EXISTS idx_timeline_epoch ON timeline_events(timestamp_epoch);
        CREATE INDEX IF NOT EXISTS idx_locations_coords ON locations(latitude, longitude);
        CREATE INDEX IF NOT EXISTS idx_locations_epoch ON locations(timestamp_epoch);
        CREATE INDEX IF NOT EXISTS idx_alerts_category ON keyword_alerts(category);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON keyword_alerts(severity);

        CREATE TABLE IF NOT EXISTS contacts (
            contact_id TEXT PRIMARY KEY,
            name TEXT,
            phone_number TEXT,
            email TEXT,
            organization TEXT,
            source_app TEXT,
            last_seen_utc TEXT,
            message_count INTEGER,
            first_seen_utc TEXT
        );

        CREATE TABLE IF NOT EXISTS app_artifacts (
            artifact_id TEXT PRIMARY KEY,
            app_name TEXT,
            artifact_type TEXT,
            artifact_key TEXT,
            artifact_value TEXT,
            source_database TEXT,
            source_table TEXT,
            discovered_at TEXT
        );

        CREATE TABLE IF NOT EXISTS file_registry (
            file_id TEXT PRIMARY KEY,
            file_name TEXT,
            file_path TEXT,
            file_size_bytes INTEGER,
            sha256_hash TEXT,
            mime_type TEXT,
            extracted_via TEXT,
            extracted_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_contacts_phone ON contacts(phone_number);
        CREATE INDEX IF NOT EXISTS idx_contacts_app ON contacts(source_app);
        CREATE INDEX IF NOT EXISTS idx_artifacts_app ON app_artifacts(app_name);
        CREATE INDEX IF NOT EXISTS idx_files_hash ON file_registry(sha256_hash);
    """)
    con.commit()


def generate_consolidated_database(
    output_path: Path | str,
    case_data: Optional[Dict[str, Any]] = None,
    decrypted_dirs: Optional[List[Path | str]] = None,
    media_dirs: Optional[List[Path | str]] = None,
    provenance_steps: Optional[List[Dict[str, Any]]] = None,
    custom_keywords: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Builds a single consolidated master SQLite database containing all
    messages, timeline events, locations, keyword alerts, decrypted database
    registries, and chain-of-custody audit logs.
    """
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if out_file.is_file():
        out_file.unlink()

    con = sqlite3.connect(str(out_file))
    init_consolidated_schema(con)

    cur = con.cursor()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Insert Case Info
    c_meta = case_data or {}
    cur.execute("""
        INSERT INTO case_info VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        c_meta.get("case_id", "CASE-DEFAULT"),
        c_meta.get("case_name", "Untitled Investigation"),
        c_meta.get("case_number", "CASE/2026/01"),
        c_meta.get("examiner", "Forensic Examiner"),
        c_meta.get("description", "Automated consolidated forensic export"),
        c_meta.get("created_at", now_utc),
        now_utc,
        len(c_meta.get("devices", [])),
        json.dumps(c_meta.get("summary", {}), default=str),
    ))

    # 2. Extract & Insert Timeline Events and Messages
    search_dirs: List[Path] = []
    if decrypted_dirs:
        for d in decrypted_dirs:
            dp = Path(d).resolve()
            if dp.is_dir() and dp not in search_dirs:
                search_dirs.append(dp)

    events: List[TimelineEvent] = []
    for s_dir in search_dirs:
        events.extend(extract_unified_timeline(s_dir))

    # De-duplicate events by event_id
    seen_events = set()
    msg_rows = []
    timeline_rows = []

    for ev in events:
        if ev.event_id in seen_events:
            continue
        seen_events.add(ev.event_id)

        meta_str = json.dumps(ev.metadata, default=str)
        timeline_rows.append((
            ev.event_id,
            ev.timestamp_utc,
            ev.timestamp_epoch,
            ev.app,
            ev.event_type,
            ev.sender,
            ev.recipient,
            ev.content,
            ev.source_database,
            ev.source_table,
            meta_str,
        ))

        # Also populate messages table for easy query access
        msg_rows.append((
            ev.event_id,
            ev.app,
            ev.event_type,
            ev.timestamp_utc,
            ev.timestamp_epoch,
            ev.sender,
            ev.recipient,
            ev.content,
            ev.source_database,
            ev.source_table,
            meta_str,
        ))

    cur.executemany("""
        INSERT INTO timeline_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, timeline_rows)

    cur.executemany("""
        INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, msg_rows)

    # 3. Extract & Insert GPS Geotags from Media
    m_search_dirs: List[Path] = []
    if media_dirs:
        for m in media_dirs:
            mp = Path(m).resolve()
            if mp.is_dir() and mp not in m_search_dirs:
                m_search_dirs.append(mp)

    geo_points: List[GeoPoint] = []
    for md in m_search_dirs:
        geo_points.extend(scan_media_for_gps(md))

    seen_points = set()
    location_rows = []
    for gp in geo_points:
        if gp.point_id in seen_points:
            continue
        seen_points.add(gp.point_id)
        location_rows.append((
            gp.point_id,
            gp.file_name,
            gp.file_path,
            gp.latitude,
            gp.longitude,
            gp.altitude,
            gp.timestamp_utc,
            gp.timestamp_epoch,
            gp.camera_make,
            gp.camera_model,
        ))

    cur.executemany("""
        INSERT INTO locations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, location_rows)

    # 4. Scan & Insert Keyword Alerts
    alerts: List[WatchlistAlert] = []
    for s_dir in search_dirs:
        alerts.extend(scan_evidence_for_alerts(s_dir, custom_keywords=custom_keywords))

    seen_alerts = set()
    alert_rows = []
    for alt in alerts:
        if alt.alert_id in seen_alerts:
            continue
        seen_alerts.add(alt.alert_id)
        alert_rows.append((
            alt.alert_id,
            alt.category,
            alt.matched_term,
            alt.severity,
            alt.database_name,
            alt.table_name,
            alt.column_name,
            alt.context_snippet,
            json.dumps(alt.row_data, default=str),
        ))

    cur.executemany("""
        INSERT INTO keyword_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alert_rows)

    # 5. Insert Provenance Steps
    audit_rows = []
    steps = provenance_steps or []
    for idx, s in enumerate(steps, start=1):
        step_num = s.get("step_number", idx)
        phase = s.get("phase", "General Execution")
        action = s.get("action", "")
        target = s.get("target", "")
        status = s.get("status", "success")
        timestamp = s.get("timestamp", now_utc)
        details = json.dumps(s.get("details", {}), default=str)
        audit_rows.append((step_num, phase, action, target, status, timestamp, details))

    cur.executemany("""
        INSERT INTO audit_trail VALUES (?, ?, ?, ?, ?, ?, ?)
    """, audit_rows)

    # 6. Inspect & Register Decrypted Databases Found
    db_rows = []
    file_registry_rows = []
    for s_dir in search_dirs:
        for db_file in s_dir.glob("*.sqlite"):
            try:
                sub_con = sqlite3.connect(f"file:{db_file.as_posix()}?mode=ro", uri=True)
                sub_cur = sub_con.cursor()
                tables = sub_cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
                # calculate simple row count across user tables
                tbl_names = [r[0] for r in sub_cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                total_rows = 0
                for tn in tbl_names[:20]:
                    try:
                        total_rows += sub_cur.execute(f"SELECT count(*) FROM \"{tn}\"").fetchone()[0]
                    except Exception:
                        pass
                sub_con.close()

                sha = hashlib.sha256(db_file.read_bytes()).hexdigest()
                file_size = db_file.stat().st_size
                db_rows.append((
                    db_file.name,
                    str(db_file),
                    "decrypted",
                    "CORRELATED",
                    "SQLCipher Export",
                    tables,
                    total_rows,
                    sha,
                ))
                # Also register in file_registry
                file_registry_rows.append((
                    sha,  # file_id = sha256 (unique per content)
                    db_file.name,
                    str(db_file),
                    file_size,
                    sha,
                    "application/vnd.sqlite3",
                    "decryption",
                    now_utc,
                ))
            except Exception:
                continue

    cur.executemany("""
        INSERT OR REPLACE INTO decrypted_databases VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, db_rows)

    cur.executemany("""
        INSERT OR REPLACE INTO file_registry VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, file_registry_rows)

    con.commit()
    con.close()

    file_size_bytes = out_file.stat().st_size

    return {
        "database_path": str(out_file),
        "file_size_bytes": file_size_bytes,
        "total_messages": len(msg_rows),
        "total_timeline_events": len(timeline_rows),
        "total_locations": len(location_rows),
        "total_alerts": len(alert_rows),
        "total_audit_steps": len(audit_rows),
        "total_decrypted_dbs": len(db_rows),
        "exported_at": now_utc,
    }
