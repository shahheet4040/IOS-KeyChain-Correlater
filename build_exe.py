"""
PyInstaller Standalone Executable Build Script
==============================================
Builds a standalone, single-file Windows executable (iOS_Keychain_Correlator.exe)
that can be run directly by Scientific Officers without requiring Python, pip, or git.
"""

import os
from pathlib import Path
import subprocess
import sys


def build_executable():
    root = Path(__file__).resolve().parent
    src = root / "src"
    entry_point = src / "correlator" / "__main__.py"

    print("═" * 70)
    print(" 🔨 iOS Keychain Correlator — Standalone .EXE Compiler")
    print("═" * 70)
    print(f" Source directory: {src}")
    print(f" Entry point:      {entry_point}")

    # Check if pyinstaller is installed
    try:
        import PyInstaller
        print(f" PyInstaller:      v{PyInstaller.__version__}")
    except ImportError:
        print(" [!] PyInstaller not found in environment. Installing now...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=iOS_Keychain_Correlator",
        "--noconfirm",
        "--onedir",  # onedir is faster to launch and handles native C DLLs (sqlcipher3) reliably
        "--windowed", # Windows GUI mode
        f"--paths={src}",
        "--hidden-import=sqlcipher3",
        "--hidden-import=pymobiledevice3",
        "--hidden-import=cryptography",
        "--hidden-import=correlator",
        "--hidden-import=correlator.dump_ingest",
        "--hidden-import=correlator.pairing",
        "--hidden-import=correlator.case_manager",
        "--hidden-import=correlator.search_engine",
        "--hidden-import=correlator.acquisition",
        "--hidden-import=correlator.whatsapp_crypt",
        "--hidden-import=correlator.importer",
        "--hidden-import=correlator.gui",
        "--hidden-import=correlator.cli",
        f"--distpath={root / 'dist'}",
        f"--workpath={root / 'build'}",
        str(entry_point),
    ]

    print("\n[*] Invoking PyInstaller...")
    print(" ".join(cmd))
    res = subprocess.run(cmd)

    if res.returncode == 0:
        dist_exe = root / "dist" / "iOS_Keychain_Correlator" / "iOS_Keychain_Correlator.exe"
        print("\n" + "═" * 70)
        print(" 🎉 Standalone Executable Successfully Built!")
        print("═" * 70)
        print(f" Output Location: {dist_exe}")
        print(" Scientific Officers can now run this executable without Python installed.")
        print("═" * 70 + "\n")
    else:
        print(f"\n[-] Build failed with exit code: {res.returncode}", file=sys.stderr)


if __name__ == "__main__":
    build_executable()
