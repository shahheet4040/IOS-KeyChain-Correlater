"""
Forensic Web Application Launcher
=================================
Launches the FastAPI backend and forensic web dashboard.
Automatically detects and uses an available port (defaults to 8888)
to avoid conflicts with local services like Splunk or Jenkins.
"""

import socket
import sys
import webbrowser
from pathlib import Path
import uvicorn


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a TCP port is currently occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def find_free_port(start_port: int = 8888, host: str = "127.0.0.1", max_attempts: int = 50) -> int:
    """Finds the first available port starting from start_port."""
    for p in range(start_port, start_port + max_attempts):
        if not is_port_in_use(p, host):
            return p
    return start_port


def main(host: str = "127.0.0.1", port: int = 8888, open_browser: bool = True):
    # If the requested port is busy, find the next free port automatically
    actual_port = find_free_port(port, host)
    if actual_port != port:
        print(f" [!] Notice: Port {port} is occupied by another service (e.g. Splunk).")
        print(f" [+] Automatically switched to available port: {actual_port}")

    print("═" * 70)
    print(" 🛡️  iOS Keychain Correlator — Digital Forensic Suite (Web Dashboard)")
    print("═" * 70)
    print(f" [+] Web Dashboard URL      : http://{host}:{actual_port}")
    print(f" [+] REST API Docs (Swagger): http://{host}:{actual_port}/docs")
    print(f" [+] Alternative ReDoc      : http://{host}:{actual_port}/redoc")
    print("═" * 70)
    print(" Press Ctrl+C in terminal to stop the web server.\n")

    if open_browser:
        try:
            webbrowser.open(f"http://{host}:{actual_port}")
        except Exception:
            pass

    uvicorn.run("correlator.web.app:app", host=host, port=actual_port, log_level="info")


if __name__ == "__main__":
    p = 8888
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        p = int(sys.argv[1])
    main(port=p)
