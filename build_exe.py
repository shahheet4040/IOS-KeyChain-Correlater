"""
Automated Build Script for IOSCorrelator Standalone Windows Executable
=====================================================================
Usage:
    python build_exe.py

Produces:
    dist/IOSCorrelator.exe (Standalone single-file executable)
    dist/IOSCorrelator-v2.4-Windows-x64.zip (Court-ready release archive)
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


def main():
    root = Path(__file__).resolve().parent
    os.chdir(root)

    print("\n" + "═" * 70)
    print(" 📦 IOS KEYCHAIN CORRELATOR — STANDALONE EXECUTABLE BUILDER")
    print("═" * 70)

    # 1. Clean previous build artifacts
    for folder in ["build", "dist"]:
        p = root / folder
        if p.exists():
            print(f"[*] Cleaning old {folder}/ directory...", flush=True)
            try:
                shutil.rmtree(p, ignore_errors=True)
            except Exception as e:
                print(f"    Warning: Could not remove {folder}: {e}", flush=True)

    # 2. Run PyInstaller
    spec_file = root / "IOSCorrelator.spec"
    if not spec_file.exists():
        print(f"[-] Error: Spec file not found: {spec_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Compiling standalone binary using PyInstaller ({spec_file.name})...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_file),
    ]

    ret = subprocess.run(cmd)
    if ret.returncode != 0:
        print("[-] Build failed during PyInstaller compilation.", file=sys.stderr)
        sys.exit(ret.returncode)

    exe_path = root / "dist" / "IOSCorrelator.exe"
    if not exe_path.exists():
        print("[-] Error: Executable was not found at expected path: dist/IOSCorrelator.exe", file=sys.stderr)
        sys.exit(1)

    size_mb = exe_path.stat().st_size / (1024 * 1024)
    print(f"\n[+] 🎉 Executable successfully created!")
    print(f"    Path : {exe_path}")
    print(f"    Size : {size_mb:.2f} MB")

    # 3. Create Release Zip Archive
    zip_name = "dist/IOSCorrelator-v2.4-Windows-x64.zip"
    zip_path = root / zip_name
    print(f"\n[*] Packaging standalone release archive: {zip_path.name}...")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(exe_path, arcname="IOSCorrelator.exe")
        for doc in ["README.md", "LICENSE"]:
            doc_p = root / doc
            if doc_p.exists():
                zf.write(doc_p, arcname=doc)

    zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"[+] 🎉 Release bundle ready: {zip_path}")
    print(f"    Package Size : {zip_size_mb:.2f} MB")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
