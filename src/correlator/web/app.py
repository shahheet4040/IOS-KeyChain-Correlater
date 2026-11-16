"""
Enterprise Forensic Web Application API & Static Server
========================================================
Built with FastAPI, providing modern asynchronous REST APIs,
automatic OpenAPI documentation (/docs), and serving the
responsive Forensic Investigation Dashboard.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from correlator.case_manager import CaseManager
from correlator.consolidated_db import generate_consolidated_database
from correlator.dump_ingest import detect_dump_format, ingest_and_analyze, normalize_dump_to_extraction
from correlator.geospatial import GeoPoint, scan_media_for_gps
from correlator.pairing import find_pairing_records, match_device_to_pairing
from correlator.pdf_report import generate_case_pdf
from correlator.pipeline import execute_pipeline
from correlator.search_engine import export_search_results, generate_search_report_html, search_sqlite_files
from correlator.timeline import TimelineEvent, extract_unified_timeline
from correlator.watchlists import WatchlistAlert, scan_evidence_for_alerts
from correlator.web.schemas import (
    AfcPullRequest,
    CaseCreateRequest,
    CrackBackupRequest,
    DeviceAddRequest,
    DeviceTriageRequest,
    GeospatialRequest,
    IngestDumpRequest,
    PairingDeviceCheck,
    RunAnalysisRequest,
    SearchRequest,
    TimelineRequest,
    WatchlistScanRequest,
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
CASES_DIR = BASE_DIR / "cases_workspace"
CASES_DIR.mkdir(parents=True, exist_ok=True)
case_manager = CaseManager(CASES_DIR)

app = FastAPI(
    title="iOS Keychain Correlator — Digital Forensic Suite",
    description="Professional enterprise REST API and Web Dashboard for iOS Keychain analysis, cryptographic correlation, and database decryption.",
    version="2.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)


# ── System Health & Overview ─────────────────────────────────────────

@app.get("/api/overview")
def get_system_overview():
    """Returns high-level statistics for the dashboard."""
    cases = case_manager.list_cases()
    total_devices = sum(c.get("device_count", 0) for c in cases)
    pairings = find_pairing_records()

    return {
        "status": "operational",
        "total_cases": len(cases),
        "total_devices": total_devices,
        "pairing_records_found": len(pairings),
        "workspace_path": str(CASES_DIR),
    }


# ── Case Management Routes ───────────────────────────────────────────

@app.get("/api/cases")
def list_cases():
    return case_manager.list_cases()


@app.post("/api/cases")
def create_case(payload: CaseCreateRequest):
    case_id = case_manager.create_case(
        case_name=payload.case_name,
        case_number=payload.case_number,
        examiner=payload.examiner,
        description=payload.description or "",
    )
    return {"case_id": case_id, "message": "Case created successfully"}


@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: str):
    try:
        return case_manager.get_case(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/cases/{case_id}/devices")
def add_device_to_case(case_id: str, payload: DeviceAddRequest):
    try:
        dev_id = case_manager.add_device(
            case_id=case_id,
            device_name=payload.device_name,
            device_model=payload.device_model,
            os_version=payload.os_version,
            serial_number=payload.serial_number,
            source_type=payload.source_type,
            source_path=payload.source_path or "",
        )
        return {"device_id": dev_id, "message": "Device registered in case."}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/cases/{case_id}/report")
def get_case_consolidated_report(case_id: str):
    try:
        return case_manager.generate_case_report(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/cases/{case_id}/pdf")
def download_case_pdf(case_id: str):
    """
    Generates and downloads a court-ready, publication-grade PDF report
    containing complete case details, inventory, decrypted databases, and evidence records.
    """
    try:
        case_data = case_manager.generate_case_report(case_id)
        # Augment with detailed databases from all device analysis runs
        all_res = case_manager.get_analysis_results(case_id)
        dbs = []
        for r in all_res:
            r_data = r.get("data", {})
            for db in r_data.get("databases", []):
                dbs.append(db)
        case_data["databases"] = dbs

        # Collect sample evidence rows from cross-device search
        samples = []
        try:
            hits = case_manager.cross_device_search(case_id, " ")
            for h in hits[:25]:
                samples.append({
                    "database": h.get("db_name", "evidence.sqlite"),
                    "table": h.get("table", "messages"),
                    "column": h.get("column", "body"),
                    "snippet": h.get("matched_value", "")[:75],
                })
        except Exception:
            pass
        case_data["evidence_samples"] = samples

        # Collect provenance steps from analysis runs
        prov_steps = []
        for r in all_res:
            r_data = r.get("data", {})
            if "provenance_map" in r_data:
                prov_steps.extend(r_data["provenance_map"])
        case_data["provenance_map"] = prov_steps

        pdf_dir = CASES_DIR / case_id / "reports"
        pdf_dir.mkdir(parents=True, exist_ok=True)
        safe_num = case_data.get("case_number", "Case").replace("/", "_").replace("\\", "_")
        pdf_path = pdf_dir / f"{safe_num}_Forensic_Report.pdf"
        generate_case_pdf(case_data, pdf_path)

        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"{safe_num}_Official_Forensic_Report.pdf",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation error: {e}")


@app.get("/api/cases/{case_id}/consolidated-db")
def download_case_consolidated_db(case_id: str):
    """
    Generates and downloads a single consolidated master SQLite database
    (consolidated_case_evidence.sqlite) merging all decrypted communications,
    timeline events, geotagged GPS photos, keyword alerts, and audit trail steps.
    """
    try:
        case_data = case_manager.generate_case_report(case_id)
        all_res = case_manager.get_analysis_results(case_id)

        decrypted_dirs = [
            BASE_DIR / "out" / "analysis_results" / "decrypted_exports",
            BASE_DIR / "out" / "real_world_case_results" / "decrypted_exports",
            BASE_DIR / "out" / "web_ingest" / "decrypted_exports",
            BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
            BASE_DIR / "out" / "fake" / "decrypted_export",
        ]
        for dev in case_data.get("devices", []):
            sp = dev.get("source_path")
            if sp and Path(sp).is_dir():
                decrypted_dirs.append(Path(sp))

        media_dirs = [
            BASE_DIR / "out" / "afc_extracted",
            BASE_DIR / "out" / "afc_photos",
            BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
            BASE_DIR / "out" / "real_world_case",
        ]

        prov_steps = []
        for r in all_res:
            r_data = r.get("data", {})
            if "provenance_map" in r_data:
                prov_steps.extend(r_data["provenance_map"])

        export_dir = CASES_DIR / case_id / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        safe_num = case_data.get("case_number", "Case").replace("/", "_").replace("\\", "_")
        db_path = export_dir / f"{safe_num}_consolidated_evidence.sqlite"

        generate_consolidated_database(
            output_path=db_path,
            case_data=case_data,
            decrypted_dirs=decrypted_dirs,
            media_dirs=media_dirs,
            provenance_steps=prov_steps,
        )

        return FileResponse(
            path=str(db_path),
            media_type="application/vnd.sqlite3",
            filename=f"{safe_num}_consolidated_evidence.sqlite",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Consolidated DB export error: {e}")


@app.get("/api/cases/{case_id}/provenance")
def get_case_provenance(case_id: str):
    """Returns the step-by-step forensic execution and provenance map for a case."""
    try:
        case_data = case_manager.get_case(case_id)
        all_res = case_manager.get_analysis_results(case_id)
        steps = []
        for r in all_res:
            r_data = r.get("data", {})
            if "provenance_map" in r_data:
                steps.extend(r_data["provenance_map"])
        if not steps:
            from correlator.provenance import build_default_provenance_map
            dbs = []
            for r in all_res:
                r_data = r.get("data", {})
                dbs.extend(r_data.get("databases", []))
            tracker = build_default_provenance_map(dbs, f"Case_{case_id}", "Keychain")
            steps = tracker.get_timeline()
        return {
            "case_id": case_id,
            "case_name": case_data.get("case_name"),
            "total_steps": len(steps),
            "provenance_map": steps,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Live USB Acquisition & Triage Routes ─────────────────────────────

@app.get("/api/usb/status")
def get_usb_status():
    from correlator.acquisition import is_acquisition_available, is_usbmuxd_running, list_connected_devices
    available = is_acquisition_available()
    usbmux_active = is_usbmuxd_running()
    devices = list_connected_devices() if (available and usbmux_active) else []

    return {
        "acquisition_module_available": available,
        "usbmuxd_service_running": usbmux_active,
        "connected_devices": devices,
    }


@app.post("/api/usb/triage")
def triage_device(payload: DeviceTriageRequest):
    """
    Evaluates USB pairing state and device lock state (AFU vs BFU)
    to determine exact forensic AccessTier.
    """
    from correlator.acquisition import BackupAccessResolver, _get_lockdown_client, is_usbmuxd_running
    try:
        client = None
        if is_usbmuxd_running():
            try:
                client = _get_lockdown_client(payload.udid)
            except Exception:
                pass
        resolver = BackupAccessResolver(payload.udid, client)
        tier, meta = resolver.resolve()
        return {
            "udid": payload.udid,
            "access_tier": tier.value,
            "lock_state": meta.get("lock_state", "UNKNOWN"),
            "paired": meta.get("paired", False),
            "password_set": meta.get("password_set", False),
            "recommendation": (
                "FULL LOGICAL EXTRACTION: Ready for immediate password-free acquisition."
                if tier.value == "full_backup"
                else "PARTIAL EXTRACTION: Device has backup password. Use AFC Media Fallback or Password Dictionary Cracker."
                if tier.value == "encrypted_unknown"
                else "BFU SEALED: Device requires passcode entry to unseal keybag."
                if tier.value == "bfu_locked"
                else "UNPAIRED: Device requires user interaction to establish lockdown trust."
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/usb/afc-pull")
def pull_afc_media(payload: AfcPullRequest):
    """
    Pulls DCIM photos, voice memos, and crash logs over AFC
    without requiring the device passcode or backup password.
    """
    from correlator.acquisition import PasswordFreeBackup, _get_lockdown_client, list_connected_devices
    target_udid = payload.udid
    if not target_udid:
        devs = list_connected_devices()
        if not devs:
            raise HTTPException(status_code=400, detail="No iOS device connected over USB.")
        target_udid = devs[0]["udid"]

    out_p = Path(payload.output_dir).resolve() if payload.output_dir else (BASE_DIR / "out" / "afc_extracted" / target_udid)
    out_p.mkdir(parents=True, exist_ok=True)

    try:
        client = _get_lockdown_client(target_udid)
        backup_agent = PasswordFreeBackup(client, target_udid)
        pulled = backup_agent.partial_afc_pull(out_p)
        return {
            "success": True,
            "udid": target_udid,
            "output_directory": str(out_p),
            "total_files_extracted": len(pulled),
            "extracted_files": list(pulled.keys())[:100],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AFC extraction failed: {e}")


@app.post("/api/backup/crack")
def crack_backup_password(payload: CrackBackupRequest):
    """
    Evaluates password candidates against PBKDF2 hash in Manifest.plist.
    Recovers access for ENCRYPTED_UNKNOWN backups.
    """
    from correlator.acquisition import BackupPasswordCracker
    manifest_p = Path(payload.manifest_path).resolve()
    if not manifest_p.is_file():
        raise HTTPException(status_code=400, detail="Manifest.plist not found at specified path.")

    cracker = BackupPasswordCracker(manifest_p)
    if not cracker.salt or not cracker.expected_hash:
        return {
            "cracked": False,
            "reason": "Manifest.plist does not contain PasswordHash / PasswordSalt (unencrypted backup).",
            "password": None,
        }

    # 1. Test direct candidates if provided
    candidates = payload.candidate_passwords or []
    # Add top forensic dictionary defaults if no custom wordlist
    if not candidates and not payload.wordlist_path:
        candidates = [
            "1234", "0000", "123456", "password", "apple", "iphone",
            "1111", "1212", "qwerty", "12345678", "admin", "12345",
        ]

    for cand in candidates:
        if cracker.try_password(cand):
            return {
                "cracked": True,
                "password": cand,
                "method": "candidate_list",
                "rounds": cracker.rounds,
            }

    # 2. Test wordlist if provided
    if payload.wordlist_path:
        w_path = Path(payload.wordlist_path).resolve()
        if w_path.is_file():
            found = cracker.dictionary_attack(w_path)
            if found:
                return {
                    "cracked": True,
                    "password": found,
                    "method": "dictionary_wordlist",
                    "rounds": cracker.rounds,
                }

    return {
        "cracked": False,
        "password": None,
        "message": "Tested candidates exhausted without a cryptographic match.",
    }


# ── Dump Ingestion Routes ────────────────────────────────────────────

@app.post("/api/ingest/detect")
def detect_dump(payload: Dict[str, str]):
    path_str = payload.get("path", "").strip()
    p = Path(path_str)
    if not p.is_dir():
        raise HTTPException(status_code=400, detail="Provided path is not an existing directory.")
    fmt = detect_dump_format(p)
    return {"path": path_str, "detected_format": fmt}


@app.post("/api/ingest/run")
def execute_dump_ingestion(payload: IngestDumpRequest):
    dump_path = Path(payload.dump_path).resolve()
    if not dump_path.is_dir():
        raise HTTPException(status_code=400, detail="Dump directory does not exist.")

    out_dir = Path(payload.out_dir).resolve() if payload.out_dir else (BASE_DIR / "out" / "web_ingest")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        if payload.auto_analyze:
            result = ingest_and_analyze(dump_path, out_dir)
            prov = result.get("pipeline_result", {}).get("provenance_map", [])
            return {
                "success": True,
                "format": result["format"],
                "total_databases": result["db_count"],
                "decrypted_count": result.get("decrypted_count", 0),
                "plain_count": result.get("plain_count", 0),
                "locked_count": result.get("locked_count", 0),
                "report_html": str(result.get("report_html")),
                "report_json": str(result.get("report_json")),
                "provenance_map": prov,
            }
        else:
            result = normalize_dump_to_extraction(dump_path, out_dir)
            return {
                "success": True,
                "format": result["format"],
                "total_databases": result["db_count"],
                "app_containers": result["app_count"],
                "extraction_path": str(result["extraction_path"]),
                "keychain_path": str(result.get("keychain_path")),
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Correlation & Decryption Execution ───────────────────────────────

@app.post("/api/analysis/run")
def run_analysis(payload: RunAnalysisRequest):
    ext_p = Path(payload.extraction_path).resolve()
    kc_p = Path(payload.keychain_path).resolve()

    if not ext_p.is_dir():
        raise HTTPException(status_code=400, detail="Extraction directory not found.")
    if not kc_p.is_file():
        raise HTTPException(status_code=400, detail="Keychain file not found.")

    out_dir = Path(payload.out_dir).resolve() if payload.out_dir else (BASE_DIR / "out" / "web_analysis")
    out_dir.mkdir(parents=True, exist_ok=True)
    export_dir = out_dir / "decrypted_exports"

    try:
        res = execute_pipeline(
            extraction=ext_p,
            keychain=kc_p,
            out_dir=out_dir,
            export_dir=export_dir,
        )
        return {
            "success": True,
            "total_databases": res["total_databases"],
            "decrypted_count": res["decrypted_count"],
            "plain_count": res["plain_count"],
            "locked_count": res["locked_count"],
            "report_html_path": str(res["report_html_path"]),
            "export_dir": str(export_dir),
            "provenance_map": res.get("provenance_map", []),
            "databases": [
                {
                    "name": r.name,
                    "relpath": r.relpath,
                    "status": r.status,
                    "bundle_id": r.bundle_id,
                    "profile": r.profile,
                    "key_fingerprint": r.key_fingerprint,
                    "has_wal": r.has_wal,
                }
                for r in res["results"]
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Deep Evidence Search Routes ──────────────────────────────────────

@app.post("/api/search")
def search_evidence(payload: SearchRequest):
    dir_p = Path(payload.directory).resolve()
    if not dir_p.is_dir():
        raise HTTPException(status_code=400, detail="Target search directory does not exist.")

    hits = search_sqlite_files(
        directory=dir_p,
        keyword=payload.keyword,
        case_insensitive=payload.case_insensitive,
        max_results=payload.max_results,
    )
    return {
        "keyword": payload.keyword,
        "total_hits": len(hits),
        "hits": [h.to_dict() for h in hits],
    }


# ── Decrypted Evidence Explorer Routes ───────────────────────────────

import sqlite3


@app.get("/api/evidence/databases")
def list_decrypted_databases(export_dir: Optional[str] = None):
    """Discovers all decrypted SQLite databases available for inspection."""
    search_dirs: List[Path] = []
    if export_dir and Path(export_dir).is_dir():
        search_dirs.append(Path(export_dir).resolve())

    # Fallback to standard output locations
    for sub in [
        BASE_DIR / "out" / "analysis_results" / "decrypted_exports",
        BASE_DIR / "out" / "real_world_case_results" / "decrypted_exports",
        BASE_DIR / "out" / "web_ingest" / "decrypted_exports",
        BASE_DIR / "out" / "fake" / "decrypted_export",
    ]:
        if sub.is_dir() and sub not in search_dirs:
            search_dirs.append(sub)

    databases: List[Dict[str, Any]] = []
    seen_paths = set()

    for s_dir in search_dirs:
        for f in sorted(s_dir.rglob("*")):
            if f.is_file() and f.suffix.lower() in (".sqlite", ".db", ".sqlite3"):
                real_p = str(f.resolve())
                if real_p not in seen_paths:
                    seen_paths.add(real_p)
                    try:
                        stat = f.stat()
                        databases.append({
                            "name": f.name,
                            "path": real_p,
                            "relpath": str(f.relative_to(s_dir)),
                            "size_bytes": stat.st_size,
                            "source_dir": str(s_dir),
                        })
                    except Exception:
                        pass

    return databases


@app.get("/api/evidence/tables")
def list_database_tables(db_path: str):
    """Returns all tables inside a decrypted database."""
    p = Path(db_path).resolve()
    if not p.is_file():
        raise HTTPException(status_code=400, detail="Database file not found.")

    try:
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
        tables_info = []
        for row in cur.fetchall():
            tbl = row[0]
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
                count = cur.fetchone()[0]
            except Exception:
                count = 0
            tables_info.append({"name": tbl, "row_count": count})
        con.close()
        return {"database": p.name, "tables": tables_info}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read database: {e}")


@app.get("/api/evidence/rows")
def get_table_rows(db_path: str, table: str, limit: int = 500, offset: int = 0):
    """Fetches records and columns from a specific table."""
    p = Path(db_path).resolve()
    if not p.is_file():
        raise HTTPException(status_code=400, detail="Database file not found.")

    try:
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute(f'SELECT * FROM "{table}" LIMIT ? OFFSET ?;', (limit, offset))
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
        con.close()

        formatted_rows = []
        for r in rows:
            formatted_rows.append([str(v) if v is not None else None for v in r])

        return {
            "database": p.name,
            "table": table,
            "columns": cols,
            "total_rows_loaded": len(formatted_rows),
            "rows": formatted_rows,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query table: {e}")


# ── Unified Chat & Activity Timeline Routes ──────────────────────────

@app.get("/api/timeline")
def get_timeline(directory: Optional[str] = None, max_records: int = 5000):
    """Aggregates chronological communications across Signal, WhatsApp, WeChat, and Safari."""
    search_dirs = []
    if directory and Path(directory).is_dir():
        search_dirs.append(Path(directory).resolve())
    else:
        for sub in [
            BASE_DIR / "out" / "analysis_results" / "decrypted_exports",
            BASE_DIR / "out" / "real_world_case_results" / "decrypted_exports",
            BASE_DIR / "out" / "web_ingest" / "decrypted_exports",
            BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
            BASE_DIR / "out" / "fake" / "decrypted_export",
            BASE_DIR / "out" / "fake" / "extraction",
        ]:
            if sub.is_dir() and sub not in search_dirs:
                search_dirs.append(sub)

    events = []
    for s_dir in search_dirs:
        events.extend(extract_unified_timeline(s_dir, max_records=max_records))
        if len(events) >= max_records:
            break

    events.sort(key=lambda x: x.timestamp_epoch)
    events = events[:max_records]

    app_breakdown = {}
    for ev in events:
        app_breakdown[ev.app] = app_breakdown.get(ev.app, 0) + 1

    return {
        "total_events": len(events),
        "app_breakdown": app_breakdown,
        "events": [ev.to_dict() for ev in events],
    }


# ── GPS & Photo EXIF Geospatial Routes ────────────────────────────────

@app.get("/api/geospatial")
def get_geospatial(directory: Optional[str] = None):
    """Extracts GPS coordinates and timestamps from seized media and AFC photos."""
    search_dirs = []
    if directory and Path(directory).is_dir():
        search_dirs.append(Path(directory).resolve())
    else:
        for sub in [
            BASE_DIR / "out" / "afc_extracted",
            BASE_DIR / "out" / "afc_photos",
            BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
            BASE_DIR / "out" / "real_world_case",
        ]:
            if sub.is_dir() and sub not in search_dirs:
                search_dirs.append(sub)

    points = []
    for s_dir in search_dirs:
        points.extend(scan_media_for_gps(s_dir))

    points.sort(key=lambda x: x.timestamp_epoch)

    center = {"latitude": 37.7749, "longitude": -122.4194}
    if points:
        center = {
            "latitude": sum(p.latitude for p in points) / len(points),
            "longitude": sum(p.longitude for p in points) / len(points),
        }

    return {
        "total_points": len(points),
        "center": center,
        "points": [p.to_dict() for p in points],
    }


# ── Automated Watchlist & Keyword Alert Routes ────────────────────────

@app.get("/api/watchlists/alerts")
def get_watchlist_alerts(directory: Optional[str] = None):
    """Scans decrypted databases against intelligence watchlists."""
    search_dirs = []
    if directory and Path(directory).is_dir():
        search_dirs.append(Path(directory).resolve())
    else:
        for sub in [
            BASE_DIR / "out" / "analysis_results" / "decrypted_exports",
            BASE_DIR / "out" / "real_world_case_results" / "decrypted_exports",
            BASE_DIR / "out" / "web_ingest" / "decrypted_exports",
            BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
            BASE_DIR / "out" / "fake" / "decrypted_export",
        ]:
            if sub.is_dir() and sub not in search_dirs:
                search_dirs.append(sub)

    alerts = []
    for s_dir in search_dirs:
        alerts.extend(scan_evidence_for_alerts(s_dir))

    category_counts = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for a in alerts:
        category_counts[a.category] = category_counts.get(a.category, 0) + 1
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    return {
        "total_alerts": len(alerts),
        "severity_summary": severity_counts,
        "category_summary": category_counts,
        "alerts": [a.to_dict() for a in alerts],
    }


@app.post("/api/watchlists/scan")
def trigger_watchlist_scan(payload: WatchlistScanRequest):
    search_dir = Path(payload.directory).resolve() if payload.directory else None
    if search_dir and not search_dir.is_dir():
        raise HTTPException(status_code=400, detail="Target search directory does not exist.")

    dir_to_scan = search_dir or (BASE_DIR / "out" / "analysis_results" / "decrypted_exports")
    if not dir_to_scan.is_dir():
        dir_to_scan = BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite"

    alerts = scan_evidence_for_alerts(dir_to_scan, custom_keywords=payload.custom_keywords)

    category_counts = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for a in alerts:
        category_counts[a.category] = category_counts.get(a.category, 0) + 1
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    return {
        "total_alerts": len(alerts),
        "severity_summary": severity_counts,
        "category_summary": category_counts,
        "alerts": [a.to_dict() for a in alerts],
    }


# ── Pairing Record Routes ────────────────────────────────────────────

@app.get("/api/pairing")
def get_pairing_records():
    return find_pairing_records()


@app.post("/api/pairing/match")
def match_pairing(payload: PairingDeviceCheck):
    match = match_device_to_pairing(payload.udid)
    if match:
        return {"matched": True, "record": match}
    return {"matched": False, "record": None}


# ── Consolidated Master Database Routes ──────────────────────────────

@app.get("/api/export/consolidated-db")
def export_general_consolidated_db(directory: Optional[str] = None):
    """Generates and downloads a consolidated master SQLite database for the workstation evidence."""
    search_dirs = []
    if directory and Path(directory).is_dir():
        search_dirs.append(Path(directory).resolve())
    else:
        for sub in [
            BASE_DIR / "out" / "analysis_results" / "decrypted_exports",
            BASE_DIR / "out" / "real_world_case_results" / "decrypted_exports",
            BASE_DIR / "out" / "web_ingest" / "decrypted_exports",
            BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
            BASE_DIR / "out" / "fake" / "decrypted_export",
        ]:
            if sub.is_dir() and sub not in search_dirs:
                search_dirs.append(sub)

    media_dirs = [
        BASE_DIR / "out" / "afc_extracted",
        BASE_DIR / "out" / "afc_photos",
        BASE_DIR / "data" / "public_datasets" / "real_world_cellebrite",
        BASE_DIR / "out" / "real_world_case",
    ]

    out_dir = BASE_DIR / "out" / "consolidated_exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "consolidated_case_evidence.sqlite"

    generate_consolidated_database(
        output_path=db_path,
        case_data={"case_name": "General Evidence Consolidation", "case_number": "GEN/2026/001"},
        decrypted_dirs=search_dirs,
        media_dirs=media_dirs,
    )

    return FileResponse(
        path=str(db_path),
        media_type="application/vnd.sqlite3",
        filename="consolidated_case_evidence.sqlite",
    )


# ── Web UI Dashboard Root ────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_file = STATIC_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(index_file)
    return HTMLResponse("<h1>Forensic Dashboard Loading...</h1>")
