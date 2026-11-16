"""
Executable Build Script
=======================
Automates building the standalone Windows binary using PyInstaller.
Usage:
    .venv\\Scripts\\python.exe scripts/build_exe.py
"""

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def build():
    print("[*] Starting PyInstaller build for iOS Keychain Correlator...")
    spec_file = BASE_DIR / "ios_correlator.spec"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_file),
    ]

    print(f"[*] Running command: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(BASE_DIR))
    if result.returncode == 0:
        exe_path = BASE_DIR / "dist" / "IOSKeychainCorrelator.exe"
        print(f"\n[+] Build successful! Standalone binary created at:\n    {exe_path}")
    else:
        print(f"\n[-] Build failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)


if __name__ == "__main__":
    build()
