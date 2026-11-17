"""
IOSCorrelator — Standalone Windows & Cross-Platform Forensic Executable Entrypoint.
Dual GUI/CLI mode:
- Double-clicking from Windows Explorer -> launches modern desktop forensic GUI without any console window.
- Running from CLI with args (e.g. `IOSCorrelator.exe run ...`, `IOSCorrelator.exe doctor`) -> attaches to terminal and executes CLI commands.
"""

import ctypes
import io
import os
import sys
from pathlib import Path

# When bundled with PyInstaller, adjust sys.path and environment
if getattr(sys, "frozen", False):
    bundle_dir = Path(sys._MEIPASS)
    sys.path.insert(0, str(bundle_dir))
    os.environ["PATH"] = str(bundle_dir) + os.pathsep + os.environ.get("PATH", "")
else:
    src_dir = Path(__file__).resolve().parent / "src"
    if src_dir.exists():
        sys.path.insert(0, str(src_dir))


# Ensure safe stdout/stderr streams on Windows
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    if sys.stdout is None:
        try:
            sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
        except Exception:
            sys.stdout = io.StringIO()
    else:
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if sys.stderr is None:
        try:
            sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")
        except Exception:
            sys.stderr = io.StringIO()
    else:
        try:
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def attach_parent_console():
    """Attach to calling parent console (PowerShell/CMD) if launched from terminal."""
    if sys.platform == "win32":
        try:
            # If stdout is already connected to a terminal pipe or file, ensure UTF-8
            if sys.stdout is not None and not isinstance(sys.stdout, io.StringIO) and getattr(sys.stdout, "name", "") != os.devnull:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                if sys.stderr is not None and hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
                return

            # -1 = ATTACH_PARENT_PROCESS
            if ctypes.windll.kernel32.AttachConsole(-1):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        attach_parent_console()
        from correlator.cli import main as cli_main
        sys.exit(cli_main(sys.argv[1:]))
    else:
        from correlator.gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
