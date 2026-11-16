import argparse
from pathlib import Path
import sys
from typing import List, Optional

from correlator.diagnostics import diagnose_exception, format_diagnostic_box, run_system_doctor
from correlator.evaluate import run_evaluation
from correlator.importer import import_keychain
from correlator.pipeline import IntegrityError, format_table, run, run_pipeline


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="correlator",
        description="iOS Keychain Correlator: Forensic correlation of iOS Keychain keys with application databases.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 'run' subcommand
    run_parser = subparsers.add_parser("run", help="Run forensic correlation scan")
    run_parser.add_argument("--root", "--extraction", "-e", dest="root", required=True, type=Path, help="Path to iOS extraction root")
    run_parser.add_argument("--keychain", "-k", required=True, type=Path, help="Path to normalized keychain JSON export")
    run_parser.add_argument("--out", "--out-dir", dest="out", required=True, type=Path, help="Directory to save report files")
    run_parser.add_argument("--keep-work", action="store_true", default=False, help="Preserve work/ directory after run")
    run_parser.add_argument("--export-dir", type=Path, default=None, help="Directory to export decrypted SQLite databases")
    run_parser.add_argument("--report", "-r", type=Path, default=None, help="Path to output correlation JSON report")
    run_parser.add_argument("--html", type=Path, default=None, help="Path to output standalone HTML report")
    run_parser.add_argument("--work-dir", type=Path, default=None, help="Scratch working directory")

    # 'evaluate' subcommand
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate report against ground truth")
    eval_parser.add_argument("--report", "-r", required=True, type=Path, help="Path to generated report.json")
    eval_parser.add_argument("--truth", "--ground-truth", "-g", "-t", dest="truth", required=True, type=Path, help="Path to ground_truth.json")

    # 'gui' subcommand
    subparsers.add_parser("gui", help="Launch interactive graphical user interface")

    # 'doctor' subcommand
    doc_parser = subparsers.add_parser("doctor", help="Run automated diagnostic health checks and self-healing")
    doc_parser.add_argument("--fix", action="store_true", help="Automatically generate missing demo data and fix issues")

    # 'import-keychain' subcommand
    imp_parser = subparsers.add_parser("import-keychain", help="Import & normalize raw keychain dumps (Frida, Cellebrite, Plist, CSV)")
    imp_parser.add_argument("--input", "-i", required=True, type=Path, help="Path to raw keychain export file")
    imp_parser.add_argument("--out", "-o", required=True, type=Path, help="Output path for normalized keychain.json")

    # 'acquire' subcommand (Live USB acquisition)
    acq_parser = subparsers.add_parser("acquire", help="Live USB physical & logical acquisition from connected iOS devices")
    acq_parser.add_argument("--devices", "-d", action="store_true", help="List all connected iOS devices over USB")
    acq_parser.add_argument("--profile", "-p", action="store_true", help="Dump complete forensic hardware & OS profile")
    acq_parser.add_argument("--udid", type=str, default=None, help="Target specific device by UDID")
    acq_parser.add_argument("--out", "-o", type=Path, default=Path("out/live_acquisition"), help="Output directory for acquired data")
    acq_parser.add_argument("--all-in-one", action="store_true", help="Execute complete flow: Acquire -> Correlate -> Decrypt -> Report")

    # 'ingest-dump' subcommand (Cellebrite / GrayKey / iTunes auto-ingestion)
    ingest_parser = subparsers.add_parser("ingest-dump", help="Auto-ingest and analyze Cellebrite UFED, GrayKey, or iTunes dumps")
    ingest_parser.add_argument("--dump", "-d", required=True, type=Path, help="Path to raw dump directory")
    ingest_parser.add_argument("--out", "-o", required=True, type=Path, help="Output directory for normalized data & reports")
    ingest_parser.add_argument("--analyze", action="store_true", help="Automatically run correlation & decryption pipeline")

    # 'pairing' subcommand (Lockdown trust certificate scanner)
    pairing_parser = subparsers.add_parser("pairing", help="Discover and inspect iOS lockdown pairing records on this PC")
    pairing_parser.add_argument("--scan", "-s", action="store_true", help="Scan and display all pairing records found on PC")
    pairing_parser.add_argument("--match", "-m", type=str, default=None, help="Check if a specific UDID has a pairing record on this PC")

    # 'search' subcommand (Deep keyword search across decrypted evidence)
    search_parser = subparsers.add_parser("search", help="Search keywords, phone numbers, or suspects across all decrypted SQLite evidence")
    search_parser.add_argument("--dir", "-d", required=True, type=Path, help="Directory containing decrypted SQLite databases")
    search_parser.add_argument("--keyword", "-k", required=True, type=str, help="Keyword, phone number, name, or pattern to find")
    search_parser.add_argument("--export", type=Path, default=None, help="Path to export search hits (JSON or CSV)")
    search_parser.add_argument("--html", type=Path, default=None, help="Path to generate standalone HTML search report")

    # 'web' subcommand (Launch modern FastAPI forensic web dashboard)
    web_parser = subparsers.add_parser("web", help="Launch modern forensic web application & REST API")
    web_parser.add_argument("--port", "-p", type=int, default=8888, help="Web server port (default: 8888)")
    web_parser.add_argument("--host", default="127.0.0.1", help="Web server host binding (default: 127.0.0.1)")
    web_parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")

    # Top-level direct arguments (backward-compatibility when subcommand omitted)
    parser.add_argument("--root", "--extraction", "-e", dest="root", type=Path, help="Path to iOS extraction root")
    parser.add_argument("--keychain", "-k", type=Path, help="Path to normalized keychain JSON export")
    parser.add_argument("--out", "--out-dir", dest="out", type=Path, help="Directory to save report files")
    parser.add_argument("--keep-work", action="store_true", default=False, help="Preserve work/ directory")
    parser.add_argument("--export-dir", type=Path, default=None, help="Directory to export decrypted SQLite databases")
    parser.add_argument("--report", "-r", type=Path, default=None, help="Path to output correlation JSON report")
    parser.add_argument("--html", type=Path, default=None, help="Path to output standalone HTML report")
    parser.add_argument("--truth", "--ground-truth", "-g", "-t", dest="truth", type=Path, help="Path to ground_truth.json")

    # Parse arguments
    if argv and argv[0] == "web":
        try:
            args = web_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1
        from run_webapp import main as web_main
        web_main(host=args.host, port=args.port, open_browser=not args.no_browser)
        return 0

    if argv and argv[0] == "gui":
        from correlator.gui import main as gui_main
        gui_main()
        return 0

    if argv and argv[0] == "doctor":
        fix = "--fix" in argv
        res = run_system_doctor(auto_fix=fix)
        print("\n" + "═" * 70)
        print(" 🏥 iOS Keychain Correlator — System Doctor & Health Check")
        print("═" * 70)
        for c in res["checks"]:
            sym = "✅" if c["status"] in ("PASS", "FIXED") else ("⚠️" if c["status"] == "WARN" else "❌")
            print(f" {sym} {c['name']:<25} [{c['status']}] - {c['msg']}")
        print("─" * 70)
        if res["healthy"]:
            print(" 🎉 System is 100% healthy, configured, and ready to correlate!\n")
            return 0
        else:
            print(" ⚠️  Some items require attention. Run with '--fix' to automatically resolve them:\n")
            print("     python -m correlator.cli doctor --fix\n")
            return 1

    if argv and argv[0] == "evaluate":
        try:
            args = eval_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1
        return run_evaluation(args.report, args.truth)

    if argv and argv[0] == "import-keychain":
        try:
            args = imp_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1
        try:
            items, fmt = import_keychain(args.input, output_json=args.out)
            print("\n" + "═" * 70)
            print(" 🔑 Universal Forensic Keychain Importer")
            print("═" * 70)
            print(f" [+] Detected Format : {fmt}")
            print(f" [+] Records Loaded  : {len(items)}")
            print(f" [+] Saved to        : {args.out}")
            print("═" * 70)
            print(" 🎉 File normalized successfully. Ready for correlation run!\n")
            return 0
        except Exception as e:
            print(f"[-] Failed to import keychain: {e}", file=sys.stderr)
            return 1

    if argv and argv[0] == "acquire":
        try:
            args = acq_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1

        from correlator.acquisition import (
            acquire_backup,
            acquire_live_pipeline,
            dump_device_profile,
            is_acquisition_available,
            list_connected_devices,
        )

        if not is_acquisition_available():
            print("[-] Error: pymobiledevice3 is required for USB acquisition. Run: pip install pymobiledevice3", file=sys.stderr)
            return 1

        if args.devices:
            from correlator.acquisition import is_usbmuxd_running
            print("\n" + "═" * 70)
            print(" 📱 iOS Live USB Device Discovery")
            print("═" * 70)
            if not is_usbmuxd_running():
                print(" [!] Apple Mobile Device Service (usbmuxd) is not running on port 27015.")
                print("     To connect to physical iPhones on Windows:")
                print("     1. Make sure iTunes or Apple Devices for Windows is installed.")
                print("     2. Ensure the 'Apple Mobile Device Service' is started.")
                print("     3. Connect the iPhone via USB, unlock the screen, and tap 'Trust'.\n")
                return 0

            devs = list_connected_devices()
            if not devs:
                print(" [!] No iOS devices detected over USB.")
                print("     Make sure the iPhone is connected via USB and unlocked, then tap 'Trust'.\n")
            else:
                for idx, d in enumerate(devs, 1):
                    pair_str = "Paired & Trusted" if d.get("paired") else "Untrusted / Pair Required"
                    print(f" [{idx}] {d.get('device_name')} ({d.get('product_type')})")
                    print(f"     UDID    : {d.get('udid')}")
                    print(f"     iOS     : {d.get('product_version')} (Build {d.get('build_version')})")
                    print(f"     Status  : {pair_str}")
                print()
            return 0

        if args.profile:
            try:
                prof = dump_device_profile(udid=args.udid, out_file=args.out / "device_profile.json")
                print("\n" + "═" * 70)
                print(" 📋 Forensic Device Hardware Profile")
                print("═" * 70)
                for k, v in prof.items():
                    print(f"  {k:<35}: {v}")
                print("═" * 70)
                print(f" [+] Saved profile to: {args.out / 'device_profile.json'}\n")
                return 0
            except Exception as e:
                print(f"[-] Profile extraction failed: {e}", file=sys.stderr)
                return 1

        if args.all_in_one:
            print("\n" + "═" * 70)
            print(" 🚀 Live USB All-in-One: Acquire -> Correlate -> Decrypt -> Report")
            print("═" * 70)
            try:
                def prog(msg, pct):
                    print(f" [{int(pct*100):>3}%] {msg}")

                res = acquire_live_pipeline(out_dir=args.out, udid=args.udid, progress_callback=prog)
                print("\n" + "═" * 70)
                print(" 🎉 Complete Live Acquisition and Decryption Succeeded!")
                print("═" * 70)
                print(f" [+] Device Profile   : {args.out / 'device_profile.json'}")
                print(f" [+] Decrypted DBs    : {res['decrypted_exports']}")
                print(f" [+] HTML Report      : {res['report_html']}")
                print("═" * 70 + "\n")
                return 0
            except Exception as e:
                print(f"[-] All-in-one acquisition failed: {e}", file=sys.stderr)
                return 1

        # Default help
        acq_parser.print_help()
        return 0

    if argv and argv[0] == "ingest-dump":
        try:
            args = ingest_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1

        from correlator.dump_ingest import ingest_and_analyze, normalize_dump_to_extraction
        print("\n" + "═" * 70)
        print(" 📦 Cellebrite / GrayKey / iTunes Auto-Ingestion Engine")
        print("═" * 70)

        def progress_printer(msg, pct):
            print(f" [{int(pct*100):>3}%] {msg}")

        try:
            if args.analyze:
                res = ingest_and_analyze(args.dump, args.out, progress_callback=progress_printer)
                print("\n" + "═" * 70)
                print(" 🎉 Ingestion & Correlation Analysis Complete!")
                print("═" * 70)
                print(f" [+] Source Format : {res['format']}")
                print(f" [+] Databases     : {res['db_count']} ({res['decrypted_count']} decrypted, {res['plain_count']} plain)")
                print(f" [+] HTML Report   : {res.get('report_html')}")
                print("═" * 70 + "\n")
            else:
                res = normalize_dump_to_extraction(args.dump, args.out, progress_callback=progress_printer)
                print("\n" + "═" * 70)
                print(" 🎉 Normalization Complete!")
                print("═" * 70)
                print(f" [+] Detected Format : {res['format']}")
                print(f" [+] Extracted DBs   : {res['db_count']}")
                print(f" [+] App Containers  : {res['app_count']}")
                print(f" [+] Ready in        : {res['extraction_path']}")
                print("═" * 70 + "\n")
            return 0
        except Exception as e:
            print(f"[-] Dump ingestion failed: {e}", file=sys.stderr)
            return 1

    if argv and argv[0] == "pairing":
        try:
            args = pairing_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1

        from correlator.pairing import get_pairing_summary, match_device_to_pairing
        if args.match:
            match = match_device_to_pairing(args.match)
            if match:
                print(f"\n✅ Pairing record FOUND for UDID: {args.match}")
                print(f"   Path: {match['path']}")
                print(f"   Modified: {match.get('file_modified')}\n")
            else:
                print(f"\n❌ No pairing record found on this PC for UDID: {args.match}\n")
            return 0
        else:
            print(get_pairing_summary())
            return 0

    if argv and argv[0] == "search":
        try:
            args = search_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1

        from correlator.search_engine import export_search_results, generate_search_report_html, search_sqlite_files
        print("\n" + "═" * 70)
        print(f" 🔍 Searching for keyword: '{args.keyword}' in {args.dir}")
        print("═" * 70)

        hits = search_sqlite_files(args.dir, args.keyword)
        print(f" [+] Total Matches Found: {len(hits)}")
        for i, h in enumerate(hits[:10], 1):
            print(f"  [{i}] {h.db_name} -> {h.table_name}.{h.column_name}: {h.match_context}")
        if len(hits) > 10:
            print(f"  ... and {len(hits) - 10} more matches.")

        if args.export:
            fmt = "csv" if args.export.suffix.lower() == ".csv" else "json"
            export_search_results(hits, args.export, fmt=fmt)
            print(f" [+] Results exported to: {args.export}")

        if args.html:
            generate_search_report_html(hits, args.keyword, args.html)
            print(f" [+] HTML Search Report: {args.html}")

        print("═" * 70 + "\n")
        return 0

    elif argv and argv[0] == "run":
        try:
            args = run_parser.parse_args(argv[1:])
        except SystemExit as e:
            return e.code if e.code is not None else 1

        try:
            # If export_dir or custom report paths given, run_pipeline provides decrypted exports
            if args.export_dir:
                return run_pipeline(
                    extraction=args.root,
                    keychain=args.keychain,
                    report=args.report,
                    html_report=args.html,
                    export_dir=args.export_dir,
                    work_dir=args.work_dir,
                    out_dir=args.out,
                )

            # Call pipeline.run following the exact 11-step sequence
            rep = run(root=args.root, keychain_path=args.keychain, out_dir=args.out, keep_work=args.keep_work)

            # Print one summary line per database: relative path, status, profile, key fingerprint, WAL frame count
            print("\nDatabase Summary:")
            for db in rep.get("databases", []):
                rel = db.get("relpath", "-")
                st = db.get("status", "-")
                prof = db.get("profile") or "-"
                fp = db.get("key_fingerprint") or "-"
                wal_info = db.get("wal_info") or {}
                wal_frames = wal_info.get("frames_valid", wal_info.get("valid_frames", 0)) if db.get("has_wal") else 0
                print(f"  {rel} | status: {st} | profile: {prof} | key_fp: {fp} | wal_frames: {wal_frames}")

            print(f"\n[*] Report written to {args.out / 'report.json'}")
            print(f"[*] HTML report written to {args.out / 'report.html'}")
            return 0

        except IntegrityError as e:
            print(f"Integrity Error: {e}", file=sys.stderr)
            diag = diagnose_exception(e, {"root": getattr(args, "root", None), "keychain": getattr(args, "keychain", None)})
            print(format_diagnostic_box(diag), file=sys.stderr)
            return 2
        except ValueError as e:
            print(f"Input Error: {e}", file=sys.stderr)
            diag = diagnose_exception(e, {"root": getattr(args, "root", None), "keychain": getattr(args, "keychain", None)})
            print(format_diagnostic_box(diag), file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            diag = diagnose_exception(e, {"root": getattr(args, "root", None), "keychain": getattr(args, "keychain", None)})
            print(format_diagnostic_box(diag), file=sys.stderr)
            return 1

    else:
        try:
            args = parser.parse_args(argv)
        except SystemExit as e:
            return e.code if e.code is not None else 1

        if getattr(args, "subcommand", None) == "gui":
            from correlator.gui import main as gui_main
            gui_main()
            return 0
        elif args.subcommand == "evaluate" or (args.report and args.truth):
            return run_evaluation(args.report, args.truth)
        elif args.root and args.keychain:
            out_target = args.out
            if not out_target:
                if args.report:
                    out_target = args.report.parent
                elif args.export_dir:
                    out_target = args.export_dir.parent
                else:
                    out_target = Path(".")

            if args.export_dir or (args.report and not args.out):
                return run_pipeline(
                    extraction=args.root,
                    keychain=args.keychain,
                    report=args.report,
                    html_report=args.html,
                    export_dir=args.export_dir,
                    work_dir=getattr(args, "work_dir", None),
                    out_dir=out_target,
                )

            try:
                rep = run(root=args.root, keychain_path=args.keychain, out_dir=out_target, keep_work=args.keep_work)
                for db in rep.get("databases", []):
                    rel = db.get("relpath", "-")
                    st = db.get("status", "-")
                    prof = db.get("profile") or "-"
                    fp = db.get("key_fingerprint") or "-"
                    wal_info = db.get("wal_info") or {}
                    wal_frames = wal_info.get("frames_valid", wal_info.get("valid_frames", 0)) if db.get("has_wal") else 0
                    print(f"  {rel} | status: {st} | profile: {prof} | key_fp: {fp} | wal_frames: {wal_frames}")
                return 0
            except IntegrityError as e:
                print(f"Integrity Error: {e}", file=sys.stderr)
                diag = diagnose_exception(e, {"root": getattr(args, "root", None), "keychain": getattr(args, "keychain", None)})
                print(format_diagnostic_box(diag), file=sys.stderr)
                return 2
            except ValueError as e:
                print(f"Input Error: {e}", file=sys.stderr)
                diag = diagnose_exception(e, {"root": getattr(args, "root", None), "keychain": getattr(args, "keychain", None)})
                print(format_diagnostic_box(diag), file=sys.stderr)
                return 1
        else:
            parser.print_help()
            return 1


if __name__ == "__main__":
    sys.exit(main())
