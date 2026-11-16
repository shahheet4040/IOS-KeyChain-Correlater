"""
Local Web Server for iOS Keychain Correlator.
Serves the forensic reports, decrypted evidence explorer, and JSON datasets
over HTTP at http://localhost:8080.
"""

import http.server
import os
from pathlib import Path
import socketserver
import sys

PORT = 8080
ROOT_DIR = Path(__file__).resolve().parent / "out" / "fake"


class ForensicReportHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT_DIR), **kwargs)

    def do_GET(self):
        # Redirect root directly to the interactive forensic report
        if self.path in ("/", ""):
            self.send_response(302)
            self.send_header("Location", "/report.html")
            self.end_headers()
            return
        return super().do_GET()

    def log_message(self, format, *args):
        # Keep logs clean
        sys.stdout.write(f"[Server] {self.address_string()} - {format % args}\n")
        sys.stdout.flush()


def run_server(host: str = "127.0.0.1", port: int = PORT):
    if not ROOT_DIR.is_dir():
        print(f"[*] Creating demo data directory at {ROOT_DIR}...")
        from harness.make_fake_extraction import generate_fake_extraction
        generate_fake_extraction(ROOT_DIR)

    # Allow immediate socket reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((host, port), ForensicReportHandler) as httpd:
        print("═" * 70)
        print(f" 🌐 Forensic Web Server Running at: http://{host}:{port}/")
        print(f" 📂 Serving Evidence & Reports From: {ROOT_DIR}")
        print(" 📄 Open your browser to view the Live Decrypted Evidence Explorer")
        print("═" * 70)
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server("127.0.0.1", port)
