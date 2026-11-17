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


def attach_parent_console():
    """Attach to calling parent console (PowerShell/CMD) if launched from terminal."""
    if sys.platform == "win32":
        try:
            # -1 = ATTACH_PARENT_PROCESS
            # If already attached, GetLastError() returns 5 (ERROR_ACCESS_DENIED) which is fine!
            ctypes.windll.kernel32.AttachConsole(-1)
        except Exception:
            pass

        # Ensure sys.stdout and sys.stderr are bound to safe streams that never fail on charmap encoding
        for stream_name in ("stdout", "stderr"):
            stream = getattr(sys, stream_name, None)
            reconfigured = False
            if stream is not None and not isinstance(stream, io.StringIO):
                name = getattr(stream, "name", "")
                if name not in (os.devnull, "<nul>", "nul"):
                    try:
                        if hasattr(stream, "reconfigure"):
                            stream.reconfigure(encoding="utf-8", errors="replace")
                            reconfigured = True
                    except Exception:
                        pass

            if not reconfigured:
                try:
                    setattr(sys, stream_name, open("CONOUT$", "w", encoding="utf-8", errors="replace"))
                except Exception:
                    try:
                        setattr(sys, stream_name, open(os.devnull, "w", encoding="utf-8", errors="replace"))
                    except Exception:
                        setattr(sys, stream_name, io.StringIO())


def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        attach_parent_console()
        try:
            from correlator.cli import main as cli_main
            sys.exit(cli_main(sys.argv[1:]))
        except SystemExit:
            raise
        except Exception as e:
            print(f"[-] Unhandled CLI exception: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        from correlator.gui import main as gui_main
        gui_main()


if __name__ == "__main__":
    main()
