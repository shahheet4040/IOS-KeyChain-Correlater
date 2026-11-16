"""
Forensic Evidence Integrity Verifier
=====================================
Uses the custom SHA-256 implementation to re-hash every evidence database
and cross-check against the hashes stored in report.json.

A MATCH  = file is untampered (same as when the pipeline ran)
A CHANGE = file was modified after the report was written — forensic alert!
"""

import json
import sys
import time
from pathlib import Path

# Use our custom SHA-256 (the user's script)
sys.path.insert(0, str(Path(__file__).parent / "src"))
from correlator.sha256_custom import hash_file

REPORT_JSON = Path("out/fake/report.json")
EXTRACTION  = Path("out/fake/extraction")

RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║   🔐  Forensic Integrity Verifier                    ║
║       Powered by Custom SHA-256 (your algorithm)     ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def verify():
    banner()

    if not REPORT_JSON.exists():
        print(f"{RED}✗ report.json not found at {REPORT_JSON}{RESET}")
        print("  Run:  .venv\\Scripts\\python.exe harness/make_fake_extraction.py --out out/fake")
        return

    report = json.loads(REPORT_JSON.read_text())
    databases = report.get("databases", [])

    if not databases:
        print(f"{YELLOW}⚠ No databases found in report.json{RESET}")
        return

    print(f"{DIM}Report generated: {report.get('metadata', {}).get('generated_at', 'unknown')}{RESET}")
    print(f"{DIM}Checking {len(databases)} evidence file(s) using your custom SHA-256...{RESET}\n")

    passed = 0
    failed = 0
    missing = 0

    for entry in databases:
        relpath   = entry.get("relpath", "")
        stored_hash = entry.get("sha256", "")
        status    = entry.get("status", "unknown")
        name      = relpath.split("/")[-1] if relpath else "unknown"

        status_badge = {
            "decrypted":    f"{GREEN}[DECRYPTED]{RESET}",
            "plain":        f"{CYAN}[PLAIN    ]{RESET}",
            "not_decrypted":f"{RED}[LOCKED   ]{RESET}",
        }.get(status, f"{YELLOW}[UNKNOWN  ]{RESET}")

        full_path = EXTRACTION / relpath
        print(f"  {status_badge}  {BOLD}{name}{RESET}")
        print(f"           Path  : {DIM}{relpath}{RESET}")

        if not stored_hash:
            print(f"           Hash  : {YELLOW}⚠ No hash in report — skipping{RESET}\n")
            missing += 1
            continue

        print(f"           Stored: {DIM}{stored_hash}{RESET}")

        if not full_path.exists():
            print(f"           File  : {RED}✗ FILE NOT FOUND on disk{RESET}\n")
            missing += 1
            continue

        # --- Re-hash using the custom SHA-256 ---
        t0 = time.time()
        computed = hash_file(str(full_path))
        elapsed  = time.time() - t0

        print(f"           Actual: {computed}  {DIM}({elapsed:.3f}s){RESET}")

        if computed == stored_hash:
            print(f"           Check : {GREEN}{BOLD}✓ MATCH — file is untampered{RESET}\n")
            passed += 1
        else:
            print(f"           Check : {RED}{BOLD}✗ MISMATCH — FILE MAY HAVE BEEN ALTERED!{RESET}\n")
            failed += 1

    # --- Summary ---
    total = passed + failed + missing
    print("─" * 56)
    print(f"  Results: {GREEN}{passed} ✓ intact{RESET}  |  "
          f"{RED}{failed} ✗ changed{RESET}  |  "
          f"{YELLOW}{missing} ? missing{RESET}  "
          f"(of {total} total)\n")

    if failed > 0:
        print(f"{RED}{BOLD}  ⚠  FORENSIC ALERT: One or more files have changed!{RESET}")
        print(f"{RED}     This evidence may be inadmissible. Investigate immediately.{RESET}")
    elif missing > 0:
        print(f"{YELLOW}  ⚠  Some files could not be verified (missing from disk).{RESET}")
    else:
        print(f"{GREEN}{BOLD}  ✓  All evidence files verified — chain of custody intact.{RESET}")

    print()


if __name__ == "__main__":
    verify()
