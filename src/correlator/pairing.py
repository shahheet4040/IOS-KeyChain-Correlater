"""
Auto Pairing Record Scanner
============================
Discovers existing iOS lockdown pairing certificates on the forensic
workstation.  When a paired device is connected (even locked), the
pairing record lets the tool bypass the lock screen trust dialog.
"""

import os
import platform
import plistlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Standard pairing record locations by OS ─────────────────────────

def _lockdown_dirs() -> List[Path]:
    """Returns platform-specific directories that may contain pairing records."""
    system = platform.system().lower()
    dirs: List[Path] = []

    if system == "windows":
        # Primary: ProgramData
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        dirs.append(Path(pd) / "Apple" / "Lockdown")
        # Secondary: user-level
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            dirs.append(Path(appdata) / "Apple Computer" / "Lockdown")
        # Apple Devices app (Windows 11+)
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if localappdata:
            dirs.append(Path(localappdata) / "Apple" / "Lockdown")

    elif system == "darwin":
        dirs.append(Path("/var/db/lockdown"))
        home = Path.home()
        dirs.append(home / "Library" / "Lockdown")

    elif system == "linux":
        dirs.append(Path("/var/lib/lockdown"))
        dirs.append(Path("/var/run/usbmuxd"))

    return dirs


# ── Parse a single pairing record ───────────────────────────────────

def parse_pairing_record(plist_path: str | Path) -> Dict[str, Any]:
    """
    Parse a single lockdown pairing .plist file.

    Returns dict with:
      path, udid, host_id, system_buid, wifi_mac,
      has_escrow_bag, has_device_cert, has_host_cert,
      file_created, file_modified, file_size_bytes
    """
    p = Path(plist_path).resolve()
    record: Dict[str, Any] = {
        "path": str(p),
        "filename": p.name,
        "udid": p.stem,  # filename is typically the UDID
        "host_id": None,
        "system_buid": None,
        "wifi_mac": None,
        "has_escrow_bag": False,
        "has_device_cert": False,
        "has_host_cert": False,
        "has_root_cert": False,
        "file_created": None,
        "file_modified": None,
        "file_size_bytes": 0,
    }

    try:
        stat = p.stat()
        record["file_size_bytes"] = stat.st_size
        record["file_modified"] = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        record["file_created"] = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
    except OSError:
        pass

    try:
        with open(p, "rb") as f:
            data = plistlib.load(f)
    except Exception:
        record["parse_error"] = "Failed to parse plist"
        return record

    record["host_id"] = data.get("HostID")
    record["system_buid"] = data.get("SystemBUID")
    record["wifi_mac"] = data.get("WiFiMACAddress")
    record["has_escrow_bag"] = "EscrowBag" in data
    record["has_device_cert"] = "DeviceCertificate" in data
    record["has_host_cert"] = "HostCertificate" in data
    record["has_root_cert"] = "RootCertificate" in data

    # Extract readable fields from certificates if present
    if data.get("HostPrivateKey"):
        record["has_host_private_key"] = True

    return record


# ── Scan all pairing records ────────────────────────────────────────

def find_pairing_records() -> List[Dict[str, Any]]:
    """
    Scans all standard lockdown directories for iOS pairing certificates.

    Returns list of parsed pairing record dicts, sorted by modification date
    (newest first).
    """
    records: List[Dict[str, Any]] = []
    seen_paths: set = set()

    for lockdown_dir in _lockdown_dirs():
        if not lockdown_dir.is_dir():
            continue

        for f in lockdown_dir.iterdir():
            if not f.is_file():
                continue
            if f.suffix.lower() != ".plist":
                continue
            # Skip system-level plists that aren't device records
            if f.name.lower() in ("systembuid.plist", "systembuid"):
                continue

            real = f.resolve()
            if real in seen_paths:
                continue
            seen_paths.add(real)

            record = parse_pairing_record(f)
            record["lockdown_dir"] = str(lockdown_dir)
            records.append(record)

    # Sort by modification date, newest first
    records.sort(
        key=lambda r: r.get("file_modified") or "",
        reverse=True,
    )
    return records


# ── Match device to pairing record ──────────────────────────────────

def match_device_to_pairing(
    device_udid: str,
    records: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Find a matching pairing record for a device UDID.
    If records is None, scans the system automatically.
    """
    if records is None:
        records = find_pairing_records()

    device_udid_lower = device_udid.lower().strip()
    for r in records:
        if r.get("udid", "").lower().strip() == device_udid_lower:
            return r
    return None


# ── Summary for display ─────────────────────────────────────────────

def get_pairing_summary() -> str:
    """
    Returns a formatted text summary of all discovered pairing records.
    Suitable for terminal display or GUI log output.
    """
    records = find_pairing_records()
    lines = []
    lines.append("═" * 70)
    lines.append(" 🔑 iOS Lockdown Pairing Record Scanner")
    lines.append("═" * 70)

    dirs = _lockdown_dirs()
    lines.append(f" Scanned {len(dirs)} lockdown directories:")
    for d in dirs:
        exists = "✅" if d.is_dir() else "❌"
        lines.append(f"   {exists} {d}")

    lines.append("")

    if not records:
        lines.append(" ⚠️  No pairing records found on this system.")
        lines.append("     This means no iOS device has been trusted/paired with this computer.")
        lines.append("")
        lines.append(" To create a pairing record:")
        lines.append("   1. Connect iPhone via USB")
        lines.append("   2. Unlock the device")
        lines.append("   3. Tap 'Trust' when prompted")
        lines.append("   4. Enter the device passcode")
    else:
        lines.append(f" Found {len(records)} pairing record(s):")
        lines.append("")
        for i, r in enumerate(records, 1):
            status_parts = []
            if r.get("has_escrow_bag"):
                status_parts.append("Escrow ✓")
            if r.get("has_device_cert"):
                status_parts.append("DevCert ✓")
            if r.get("has_host_cert"):
                status_parts.append("HostCert ✓")
            status = " | ".join(status_parts) if status_parts else "Minimal"

            lines.append(f" [{i}] UDID: {r.get('udid', 'Unknown')}")
            lines.append(f"     WiFi MAC  : {r.get('wifi_mac') or 'N/A'}")
            lines.append(f"     Host ID   : {r.get('host_id') or 'N/A'}")
            lines.append(f"     Modified  : {r.get('file_modified') or 'N/A'}")
            lines.append(f"     Components: {status}")
            lines.append(f"     Path      : {r.get('path')}")
            lines.append("")

    lines.append("═" * 70)
    return "\n".join(lines)
