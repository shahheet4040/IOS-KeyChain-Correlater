"""
iOS Live USB Acquisition Engine
===============================
Provides live physical/logical acquisition over USB for iOS devices
using the usbmuxd protocol and pymobiledevice3 services.

Capabilities:
- Real-time USB device discovery & hardware profiling
- Forensic lockdown pairing verification
- Full Logical Backup extraction (Mobilebackup2)
- Automated Keychain extraction & normalization
- End-to-end "Acquire & Correlate" one-click workflow
"""

import asyncio
import inspect
import json
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# Gracefully import pymobiledevice3 components
try:
    from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception
    from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    from pymobiledevice3.usbmux import list_devices as usbmux_list_devices
    PYMOBILEDEVICE3_AVAILABLE = True
except ImportError:
    PYMOBILEDEVICE3_AVAILABLE = False


def is_acquisition_available() -> bool:
    """Checks whether pymobiledevice3 is installed and ready."""
    return PYMOBILEDEVICE3_AVAILABLE


def is_usbmuxd_running() -> bool:
    """Checks if Apple Mobile Device Service / usbmuxd is listening on port 27015."""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", 27015)) == 0
    except Exception:
        return False


def list_connected_devices() -> List[Dict[str, Any]]:
    """
    Scans USB bus for connected iOS devices via usbmuxd.
    Returns list of discovered device metadata dicts.
    """
    if not PYMOBILEDEVICE3_AVAILABLE:
        return []

    if not is_usbmuxd_running():
        return []

    devices = []
    try:
        res = usbmux_list_devices()
        if inspect.iscoroutine(res):
            raw_list = asyncio.run(asyncio.wait_for(res, timeout=3.0))
        else:
            raw_list = res

        for mux_dev in raw_list:
            udid = mux_dev.serial
            dev_info = {
                "udid": udid,
                "connection_type": getattr(mux_dev, "connection_type", "USB"),
                "paired": False,
                "device_name": "Unknown iOS Device",
                "product_type": "Unknown",
                "product_version": "Unknown",
                "build_version": "Unknown",
                "serial_number": udid,
            }

            # Try reading lockdown attributes if paired/authorized
            try:
                client = _get_lockdown_client(udid)
                dev_info["paired"] = True
                dev_info["device_name"] = client.device_name or dev_info["device_name"]
                dev_info["product_type"] = client.product_type or dev_info["product_type"]
                dev_info["product_version"] = client.product_version or dev_info["product_version"]
                dev_info["build_version"] = client.build_version or dev_info["build_version"]
                dev_info["serial_number"] = client.get_value(key="SerialNumber") or udid
            except Exception as e:
                dev_info["error"] = str(e)

            devices.append(dev_info)
    except Exception:
        pass

    return devices


def _get_lockdown_client(udid: Optional[str] = None):
    """Safely retrieves a LockdownClient handling both synchronous and async APIs."""
    client = create_using_usbmux(serial=udid)
    if inspect.iscoroutine(client):
        return asyncio.run(client)
    return client


def dump_device_profile(udid: Optional[str] = None, out_file: Optional[Path | str] = None) -> Dict[str, Any]:
    """
    Extracts an extensive forensic profile of the connected iOS device
    (Hardware model, OS, IMEI, MAC address, Baseband, Battery, Timezone).
    """
    if not PYMOBILEDEVICE3_AVAILABLE:
        raise RuntimeError("pymobiledevice3 is not installed.")

    client = _get_lockdown_client(udid)
    profile = {
        "DeviceName": client.device_name,
        "ProductType": client.product_type,
        "ProductVersion": client.product_version,
        "BuildVersion": client.build_version,
        "UniqueDeviceID": client.udid,
        "SerialNumber": client.get_value(key="SerialNumber"),
        "InternationalMobileEquipmentIdentity": client.get_value(key="InternationalMobileEquipmentIdentity"),
        "WiFiAddress": client.get_value(key="WiFiAddress"),
        "BluetoothAddress": client.get_value(key="BluetoothAddress"),
        "TimeIntervalSince1970": client.get_value(key="TimeIntervalSince1970"),
        "TimeZone": client.get_value(key="TimeZone"),
        "BatteryCurrentCapacity": client.get_value(domain="com.apple.mobile.battery", key="BatteryCurrentCapacity"),
    }

    if out_file:
        p = Path(out_file).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, default=str)

    return profile


def acquire_backup(
    out_dir: Path | str,
    udid: Optional[str] = None,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> Path:
    """
    Performs a logical forensic backup extraction of the connected iOS device over USB.
    Uses Mobilebackup2 protocol.
    """
    if not PYMOBILEDEVICE3_AVAILABLE:
        raise RuntimeError("pymobiledevice3 is not installed.")

    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    client = _get_lockdown_client(udid)
    service = Mobilebackup2Service(client)

    if progress_callback:
        progress_callback("Initiating Mobilebackup2 service handshake...", 0.1)

    # Perform unencrypted or standard backup
    service.backup(backup_directory=str(out_path), full=True)

    if progress_callback:
        progress_callback("Backup acquisition complete.", 1.0)

    # Find the generated backup folder (usually named after the device UDID)
    backup_subdirs = [d for d in out_path.iterdir() if d.is_dir() and len(d.name) >= 20]
    return backup_subdirs[0] if backup_subdirs else out_path


def acquire_live_pipeline(
    out_dir: Path | str,
    udid: Optional[str] = None,
    progress_callback: Optional[Callable[[str, float], None]] = None,
) -> Dict[str, Any]:
    """
    All-in-one forensic workflow:
    1. Detect and profile USB device
    2. Extract backup via Mobilebackup2
    3. Locate & parse keychain using Universal Importer
    4. Execute forensic correlation against app database containers
    5. Generate report.html with embedded Decrypted Evidence Explorer
    """
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    if progress_callback:
        progress_callback("Scanning USB bus for iOS device...", 0.05)

    profile = dump_device_profile(udid=udid, out_file=out_path / "device_profile.json")

    if progress_callback:
        progress_callback(f"Target: {profile.get('DeviceName')} ({profile.get('ProductType')}, iOS {profile.get('ProductVersion')})", 0.15)
        progress_callback("Beginning USB Logical Extraction...", 0.2)

    backup_folder = acquire_backup(out_path / "raw_backup", udid=udid, progress_callback=progress_callback)

    # Locate keychain within the backup
    from correlator.importer import import_keychain
    from correlator.pipeline import execute_pipeline

    keychain_file = None
    for cand in ["KeychainDomain/keychain-backup.plist", "keychain-backup.plist", "Manifest.db", "keychain.plist"]:
        p = backup_folder / cand
        if p.is_file():
            keychain_file = p
            break

    if not keychain_file:
        # Scan backup recursively for any plist or sqlite keychain files
        for f in backup_folder.rglob("*.plist"):
            if "keychain" in f.name.lower():
                keychain_file = f
                break

    if not keychain_file:
        raise FileNotFoundError(f"Keychain file not found inside backup: {backup_folder}")

    if progress_callback:
        progress_callback(f"Normalizing Keychain from {keychain_file.name}...", 0.7)

    norm_keychain = out_path / "keychain.json"
    import_keychain(keychain_file, output_json=norm_keychain)

    if progress_callback:
        progress_callback("Correlating keys and decrypting application databases...", 0.85)

    pipe_res = execute_pipeline(
        extraction=backup_folder,
        keychain=norm_keychain,
        out_dir=out_path,
        export_dir=out_path / "decrypted_exports",
    )

    if progress_callback:
        progress_callback("Acquisition, Decryption & Report Generation Complete!", 1.0)

    return {
        "profile": profile,
        "backup_folder": backup_folder,
        "keychain_path": norm_keychain,
        "pipeline_result": pipe_res,
        "report_html": out_path / "report.html",
        "decrypted_exports": out_path / "decrypted_exports",
    }
