import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional

from correlator.correlate import correlate as correlate_single
from correlator.engine import CorrelationResult, correlate as correlate_engine
from correlator.inventory import scan_containers
from correlator.keychain import candidates, load_keychain
from correlator.provenance import ProvenanceTracker, build_default_provenance_map
from correlator.report import generate_html_report, generate_json_report, write_html, write_json
from correlator.sqlcipher_util import PROFILES, export_decrypted, sha256_file
from correlator.triage import classify, find_databases
from correlator.wal import parse_wal


class IntegrityError(Exception):
    """Raised when evidence files have been altered during processing."""
    pass


def run(root: str | Path, keychain_path: str | Path, out_dir: str | Path, keep_work: bool = False) -> Dict[str, Any]:
    """
    Executes pipeline.run following the exact 11-step sequence:
    1.  Check that root exists and keychain_path is a file. Otherwise raise ValueError.
    2.  Call find_databases. For each database, also note whether <name>-wal and <name>-shm exist beside it.
    3.  Compute SHA-256 of every database, WAL and SHM file found. Store as hashes_before.
    4.  Call scan_containers, then load_keychain and candidates.
    5.  For each database, create out_dir/work/<index>/pristine/ and copy the main file plus its WAL and SHM files into it with shutil.copy2.
    6.  Create out_dir/work/<index>/scratch/ and copy only the main file into it. All opening happens on this copy, never on the pristine copy, because opening a database can change it.
    7.  Run classify on the scratch copy. If plain, status is plain. Otherwise run correlate and set the status from the number of distinct matching keys.
    8.  If a WAL file exists, run parse_wal on the pristine WAL copy.
    9.  Determine container_id and bundle_id by matching the database path against the inventory.
    10. Compute SHA-256 of every original file again as hashes_after. If it differs from hashes_before, raise IntegrityError and write nothing.
    11. Build the report, compute result_digest, write report.json and report.html. Delete out_dir/work unless keep_work is true.
    """
    # Step 1: Check root and keychain_path
    root_path = Path(root).resolve()
    keychain_file = Path(keychain_path).resolve()
    out_path = Path(out_dir).resolve()

    if not root_path.exists():
        raise ValueError(f"Root path does not exist: {root_path}")
    if not keychain_file.is_file():
        raise ValueError(f"Keychain path is not a file: {keychain_file}")

    # Step 2: Call find_databases, note companion WAL/SHM
    db_relpaths = find_databases(root_path)
    db_info_list = []
    for idx, rel in enumerate(db_relpaths):
        db_orig = root_path / rel
        wal_orig = db_orig.with_name(db_orig.name + "-wal")
        shm_orig = db_orig.with_name(db_orig.name + "-shm")
        db_info_list.append({
            "index": idx,
            "relpath": rel,
            "db_path": db_orig,
            "wal_path": wal_orig if wal_orig.is_file() else None,
            "shm_path": shm_orig if shm_orig.is_file() else None,
        })

    # Step 3: Compute SHA-256 of every database, WAL and SHM file found
    hashes_before: Dict[Path, str] = {}
    for item in db_info_list:
        hashes_before[item["db_path"]] = sha256_file(item["db_path"])
        if item["wal_path"]:
            hashes_before[item["wal_path"]] = sha256_file(item["wal_path"])
        if item["shm_path"]:
            hashes_before[item["shm_path"]] = sha256_file(item["shm_path"])

    # Step 4: Call scan_containers, then load_keychain and candidates
    inventory = scan_containers(root_path)
    keychain_rows, _ = load_keychain(keychain_file)
    cands = candidates(keychain_rows)

    work_base = out_path / "work"
    work_base.mkdir(parents=True, exist_ok=True)

    try:
        # Step 5: Copy main file plus WAL and SHM to pristine/
        for item in db_info_list:
            idx = item["index"]
            pristine_dir = work_base / str(idx) / "pristine"
            pristine_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item["db_path"], pristine_dir / item["db_path"].name)
            if item["wal_path"]:
                shutil.copy2(item["wal_path"], pristine_dir / item["wal_path"].name)
            if item["shm_path"]:
                shutil.copy2(item["shm_path"], pristine_dir / item["shm_path"].name)
            item["pristine_dir"] = pristine_dir

        # Step 6: Copy ONLY the main file to scratch/
        for item in db_info_list:
            idx = item["index"]
            scratch_dir = work_base / str(idx) / "scratch"
            scratch_dir.mkdir(parents=True, exist_ok=True)
            scratch_db = scratch_dir / item["db_path"].name
            shutil.copy2(item["db_path"], scratch_db)
            item["scratch_db"] = scratch_db

        # Step 7: Run classify and correlate on scratch copy
        for item in db_info_list:
            cls = classify(item["scratch_db"])
            if cls == "plain":
                item["status"] = "plain"
                item["key_fingerprint"] = None
                item["profile"] = None
                item["matches"] = []
            else:
                status, matches = correlate_single(item["scratch_db"], cands)
                item["status"] = status
                item["matches"] = matches
                if status == "decrypted" and matches:
                    item["key_fingerprint"] = matches[0]["key_fingerprint"]
                    item["profile"] = matches[0]["profile"]
                else:
                    item["key_fingerprint"] = None
                    item["profile"] = None

        # Step 8: If WAL file exists, run parse_wal on pristine WAL copy
        for item in db_info_list:
            if item["wal_path"]:
                pristine_wal = item["pristine_dir"] / item["wal_path"].name
                item["wal_result"] = parse_wal(pristine_wal)
            else:
                item["wal_result"] = None

        # Step 9: Determine container_id and bundle_id against inventory
        for item in db_info_list:
            rel_parts = Path(item["relpath"]).parts
            container_id = "unknown"
            bundle_id = "unknown"
            for folder_name, meta in inventory.items():
                if folder_name in rel_parts:
                    container_id = folder_name
                    bundle_id = meta.get("bundle_id", "unknown")
                    break
            item["container_id"] = container_id
            item["bundle_id"] = bundle_id

        # Step 10: Compute SHA-256 of every original file again as hashes_after
        for orig_path, orig_sha in hashes_before.items():
            curr_sha = sha256_file(orig_path)
            if curr_sha != orig_sha:
                raise IntegrityError(f"Evidence file was modified: {orig_path}")

        # Step 11: Build report, compute result_digest, write report.json & report.html
        db_report_entries = []
        for item in db_info_list:
            entry = {
                "relpath": item["relpath"],
                "container_id": item["container_id"],
                "bundle_id": item["bundle_id"],
                "status": item["status"],
                "key_fingerprint": item["key_fingerprint"],
                "profile": item["profile"],
                "has_wal": item["wal_path"] is not None,
                "wal_info": dict(item["wal_result"]) if item["wal_result"] else None,
            }
            db_report_entries.append(entry)

        canonical_bytes = json.dumps(db_report_entries, sort_keys=True).encode("utf-8")
        result_digest = hashlib.sha256(canonical_bytes).hexdigest()

        report_data = {
            "metadata": {
                "root": str(root_path),
                "keychain_path": str(keychain_file),
                "total_databases": len(db_report_entries),
                "result_digest": result_digest,
            },
            "databases": db_report_entries,
        }

        report_json_path = out_path / "report.json"
        report_html_path = out_path / "report.html"

        write_json(report_data, report_json_path)
        write_html(report_data, report_html_path)

        return report_data

    finally:
        # Delete out_dir/work unless keep_work is true
        if not keep_work and work_base.is_dir():
            shutil.rmtree(work_base, ignore_errors=True)


def format_table(results: List[CorrelationResult]) -> str:
    """Format correlation results into a clean, human-readable terminal table."""
    headers = ["Status", "Database", "Container / Bundle ID", "Key FP", "Profile", "WAL"]
    rows = []
    for r in results:
        status_disp = {
            "decrypted": "[DECRYPTED]",
            "plain": "[PLAIN]",
            "not_decrypted": "[LOCKED]",
        }.get(r.status, r.status)

        name = r.name
        bundle = r.bundle_id or (f"UUID: {r.container_uuid}" if r.container_uuid else "-")
        fp = r.key_fingerprint or "-"
        prof = r.profile or "-"
        wal = "Yes" if r.has_wal else "No"
        rows.append([status_disp, name, bundle, fp, prof, wal])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [" | ".join(r[i].ljust(col_widths[i]) for i in range(len(headers))) for r in rows]

    return "\n".join([header_line, sep_line] + row_lines)


def execute_pipeline(
    extraction: Path,
    keychain: Path,
    report: Optional[Path] = None,
    html_report: Optional[Path] = None,
    export_dir: Optional[Path] = None,
    work_dir: Optional[Path] = None,
    out_dir: Optional[Path] = None,
    deep_recover: bool = False,
    passwords: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Executes the end-to-end correlation pipeline programmatically.
    Returns a dictionary with results, paths, and metrics.
    """
    extraction_path = Path(extraction).resolve()
    keychain_path = Path(keychain).resolve()

    if not extraction_path.exists():
        raise FileNotFoundError(f"Extraction directory not found: {extraction_path}")
    if not keychain_path.exists():
        raise FileNotFoundError(f"Keychain file not found: {keychain_path}")

    if out_dir:
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        if report is None:
            report = out_dir / "report.json"
        if html_report is None:
            html_report = out_dir / "report.html"

    results = correlate_engine(
        extraction_path,
        keychain_path,
        work_dir=work_dir,
        deep_recover=deep_recover,
        passwords=passwords,
    )

    # ── Automated Orphan & Locked Database Recovery Escalation ──────
    orphan_recovery_items = []
    orphan_out_dir = Path(out_dir) / "orphan_recovery" if out_dir else None
    for r in results:
        if r.status == "not_decrypted":
            try:
                from correlator.advanced_decryptor import recover_orphan_database
                src_db = extraction_path / r.relpath if not Path(r.relpath).is_absolute() else Path(r.relpath)
                orp_res = recover_orphan_database(
                    db_path=src_db,
                    extra_passwords=passwords,
                    out_dir=orphan_out_dir,
                    force_carve=True,
                )
                orphan_recovery_items.append(orp_res.to_dict())
                # If orphan recovery unlocked it, promote to decrypted!
                if orp_res.status == "decrypted" and orp_res.key_bytes:
                    r.status = "decrypted"
                    r.key_bytes = orp_res.key_bytes
                    r.key_fingerprint = orp_res.key_fingerprint
                    r.profile = orp_res.profile
                    r.recovery_method = orp_res.recovery_method
            except Exception as e:
                print(f"  [!] Notice during orphan database recovery: {e}", file=sys.stderr)

    exported_files = []
    decrypted_count = sum(1 for r in results if r.status == "decrypted")
    plain_count = sum(1 for r in results if r.status == "plain")
    locked_count = sum(1 for r in results if r.status == "not_decrypted")

    if export_dir and decrypted_count > 0:
        export_path = Path(export_dir).resolve()
        export_path.mkdir(parents=True, exist_ok=True)
        for r in results:
            if r.status == "decrypted" and r.key_bytes and r.profile:
                dest = export_path / r.relpath
                profile_obj = next((p for p in PROFILES if p["name"] == r.profile), None)
                if profile_obj:
                    src_db = extraction_path / r.relpath
                    try:
                        export_decrypted(src_db, dest, r.key_bytes, profile_obj)
                        exported_files.append((r.relpath, dest))
                    except Exception as e:
                        print(f"  [-] Failed export for {r.relpath}: {e}", file=sys.stderr)

    tracker = build_default_provenance_map(
        results=results,
        extraction_path=extraction_path,
        keychain_path=keychain_path,
        export_dir=export_dir,
    )
    provenance_timeline = tracker.get_timeline()
    if out_dir:
        tracker.export_json(Path(out_dir) / "provenance_map.json")

    json_data = None
    if report:
        report = Path(report).resolve()
        json_data = generate_json_report(results, extraction_path, keychain_path, out_file=report, provenance=provenance_timeline)

    if html_report:
        html_report = Path(html_report).resolve()
        # Determine where decrypted exports live so the Evidence Explorer can read them.
        # Priority: explicit export_dir → out_dir/decrypted_export → sibling of html report
        _ev_dir = None
        if export_dir and Path(export_dir).is_dir():
            _ev_dir = Path(export_dir).resolve()
        elif out_dir and (Path(out_dir) / "decrypted_export").is_dir():
            _ev_dir = (Path(out_dir) / "decrypted_export").resolve()
        elif html_report.parent and (html_report.parent / "decrypted_export").is_dir():
            _ev_dir = (html_report.parent / "decrypted_export").resolve()
        generate_html_report(results, extraction_path, keychain_path, out_file=html_report, export_dir=_ev_dir, provenance=provenance_timeline)

    # Geospatial & GPS route trail intelligence
    geo_points = []
    geo_summary = {}
    geo_files = {}
    try:
        from correlator.geospatial import (
            analyze_movement_trail,
            export_csv,
            export_geojson,
            export_kml,
            generate_interactive_map_html,
            harvest_all_locations,
        )
        geo_points, geo_summary = harvest_all_locations(extraction_path)
        if export_dir and Path(export_dir).is_dir():
            exp_pts, _ = harvest_all_locations(export_dir)
            if exp_pts:
                geo_points.extend(exp_pts)
                geo_points, geo_summary = analyze_movement_trail(geo_points)

        if out_dir and geo_points:
            out_p = Path(out_dir).resolve()
            map_html_path = out_p / "route_map.html"
            geojson_path = out_p / "route.geojson"
            kml_path = out_p / "route.kml"
            csv_path = out_p / "route.csv"

            generate_interactive_map_html(geo_points, summary=geo_summary, out_path=map_html_path)
            export_geojson(geo_points, geojson_path)
            export_kml(geo_points, kml_path, case_name=out_p.name)
            export_csv(geo_points, csv_path)

            geo_files = {
                "map_html": map_html_path,
                "geojson": geojson_path,
                "kml": kml_path,
                "csv": csv_path,
            }
    except Exception as e:
        print(f"  [!] Geospatial analysis notice: {e}", file=sys.stderr)

    # SQLite deleted data & slack space carving
    carved_records_all: List[Any] = []
    carved_files: Dict[str, Path] = {}
    try:
        from correlator.carver import carve_directory_databases, export_carved_csv, export_carved_json
        target_carve_dir = export_dir if export_dir and Path(export_dir).is_dir() else extraction_path
        carved_map = carve_directory_databases(target_carve_dir)
        for _, rec_list in carved_map.items():
            carved_records_all.extend(rec_list)

        if out_dir and carved_records_all:
            out_p = Path(out_dir).resolve()
            c_json = out_p / "deleted_records.json"
            c_csv = out_p / "deleted_records.csv"
            export_carved_json(carved_records_all, c_json)
            export_carved_csv(carved_records_all, c_csv)
            carved_files = {"json": c_json, "csv": c_csv}
    except Exception as e:
        print(f"  [!] Deleted data carving notice: {e}", file=sys.stderr)

    # Master cross-application timeline & correlation
    timeline_events_all: List[Any] = []
    timeline_clusters: List[Any] = []
    timeline_files: Dict[str, Path] = {}
    timeline_summary: Dict[str, Any] = {}
    try:
        from correlator.timeline import (
            export_timeline_csv,
            export_timeline_json,
            extract_master_timeline,
            generate_master_timeline_html,
        )
        target_timeline_dir = export_dir if export_dir and Path(export_dir).is_dir() else extraction_path
        t_data = extract_master_timeline(
            evidence_directory=target_timeline_dir,
            geo_points=geo_points,
            carved_records=carved_records_all,
        )
        timeline_events_all = t_data.get("events", [])
        timeline_clusters = t_data.get("clusters", [])
        timeline_summary = t_data.get("summary", {})

        if out_dir and timeline_events_all:
            out_p = Path(out_dir).resolve()
            t_html = out_p / "master_timeline.html"
            t_json = out_p / "timeline.json"
            t_csv = out_p / "timeline.csv"

            generate_master_timeline_html(timeline_events_all, clusters=timeline_clusters, out_path=t_html)
            export_timeline_json(timeline_events_all, t_json, clusters=timeline_clusters)
            export_timeline_csv(timeline_events_all, t_csv)
            timeline_files = {"html": t_html, "json": t_json, "csv": t_csv}
    except Exception as e:
        print(f"  [!] Master timeline analysis notice: {e}", file=sys.stderr)

    # Forensic Lead Intelligence & Target Dossier Synthesis
    lead_dossiers_all: List[Any] = []
    case_briefing_obj: Any = None
    lead_files: Dict[str, Path] = {}
    try:
        from correlator.lead_synthesis import (
            export_dossiers_csv,
            export_dossiers_json,
            generate_case_briefing,
            generate_lead_dossier_html,
            synthesize_target_dossiers,
        )
        if timeline_events_all:
            lead_dossiers_all = synthesize_target_dossiers(
                events=timeline_events_all,
                clusters=timeline_clusters,
                carved_records=carved_records_all,
            )
            case_briefing_obj = generate_case_briefing(
                dossiers=lead_dossiers_all,
                events=timeline_events_all,
                clusters=timeline_clusters,
                carved_records=carved_records_all,
            )

            if out_dir and lead_dossiers_all:
                out_p = Path(out_dir).resolve()
                l_html = out_p / "lead_dossier.html"
                l_json = out_p / "lead_dossier.json"
                l_csv = out_p / "lead_dossier.csv"

                generate_lead_dossier_html(case_briefing_obj, out_path=l_html)
                export_dossiers_json(case_briefing_obj, l_json)
                export_dossiers_csv(lead_dossiers_all, l_csv)
                lead_files = {"html": l_html, "json": l_json, "csv": l_csv}
    except Exception as e:
        print(f"  [!] Lead synthesis analysis notice: {e}", file=sys.stderr)

    return {
        "results": results,
        "total_databases": len(results),
        "decrypted_count": decrypted_count,
        "plain_count": plain_count,
        "locked_count": locked_count,
        "exported_files": exported_files,
        "report_json_path": report,
        "report_html_path": html_report,
        "report_data": json_data,
        "provenance_map": provenance_timeline,
        "geospatial": {
            "points": geo_points,
            "summary": geo_summary,
            "files": geo_files,
        },
        "carved_deleted": {
            "total_recovered": len(carved_records_all),
            "records": carved_records_all,
            "files": carved_files,
        },
        "master_timeline": {
            "total_events": len(timeline_events_all),
            "events": timeline_events_all,
            "clusters": timeline_clusters,
            "summary": timeline_summary,
            "files": timeline_files,
        },
        "lead_intelligence": {
            "total_suspects": len(lead_dossiers_all),
            "dossiers": lead_dossiers_all,
            "briefing": case_briefing_obj,
            "files": lead_files,
        },
        "orphan_recovery": {
            "total_processed": len(orphan_recovery_items),
            "items": orphan_recovery_items,
        },
    }


def run_pipeline(
    extraction: Path,
    keychain: Path,
    report: Optional[Path] = None,
    html_report: Optional[Path] = None,
    export_dir: Optional[Path] = None,
    work_dir: Optional[Path] = None,
    out_dir: Optional[Path] = None,
    deep_recover: bool = False,
    passwords: Optional[List[str]] = None,
) -> int:
    """CLI orchestrator for the forensic correlation pipeline."""
    extraction = Path(extraction)
    keychain = Path(keychain)

    if not extraction.exists():
        print(f"Error: Extraction directory not found: {extraction}", file=sys.stderr)
        return 1

    if not keychain.exists():
        print(f"Error: Keychain file not found: {keychain}", file=sys.stderr)
        return 1

    print(f"[*] Scanning extraction: {extraction}")
    print(f"[*] Reading keychain: {keychain}")

    pipe_res = execute_pipeline(
        extraction=extraction,
        keychain=keychain,
        report=report,
        html_report=html_report,
        export_dir=export_dir,
        work_dir=work_dir,
        out_dir=out_dir,
        deep_recover=deep_recover,
        passwords=passwords,
    )

    results = pipe_res["results"]
    print("\n" + format_table(results) + "\n")

    decrypted = pipe_res["decrypted_count"]
    plain = pipe_res["plain_count"]
    locked = pipe_res["locked_count"]
    print(f"Summary: {len(results)} databases ({decrypted} decrypted, {plain} plain, {locked} locked)")

    if pipe_res["exported_files"]:
        print(f"\n[*] Exporting decrypted databases to {export_dir}...")
        for relpath, dest in pipe_res["exported_files"]:
            print(f"  [+] Decrypted: {relpath} -> {dest}")

    if pipe_res["report_json_path"]:
        print(f"\n[*] JSON report written to {pipe_res['report_json_path']}")

    if pipe_res["report_html_path"]:
        print(f"[*] HTML report written to {pipe_res['report_html_path']}")

    return 0
