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
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import inspect
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# Gracefully import pymobiledevice3 components
try:
    from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception
    from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
    from pymobiledevice3.services.afc import AfcService
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    from pymobiledevice3.usbmux import list_devices as usbmux_list_devices
    PYMOBILEDEVICE3_AVAILABLE = True
except ImportError:
    PYMOBILEDEVICE3_AVAILABLE = False


# ── Triage State Machine & Access Tiers ──────────────────────────────

class AccessTier(Enum):
    """What data domains are reachable given current pairing and lock state."""
    FULL_BACKUP = "full_backup"              # AFU + paired, no password set (or password known)
    ENCRYPTED_UNKNOWN = "encrypted_unknown"  # AFU + paired, backup password set (unknown)
    PARTIAL_AFC = "partial_afc"              # AFC accessible without password (photos, DCIM, crash logs)
    BFU_LOCKED = "bfu_locked"                # Before First Unlock - keybag sealed, data locked
    UNPAIRED = "unpaired"                    # No valid pairing record, requires passcode on device


@dataclass
class PairingContext:
    """Represents a lockdown pairing record and its authorization scope."""
    udid: str
    record_path: Path
    host_id: str = ""
    system_buid: str = ""
    cert_fingerprint: bytes = b""
    wifi_sync: bool = False


class LockdownPairingManager:
    """
    Manages discovery and validation of pairing records on the forensic workstation.
    A valid pairing record + AFU device = backup without passcode entry.
    """

    def __init__(self, udid: str):
        self.udid = udid
        self.record: Optional[PairingContext] = None

    def find_record(self) -> Optional[PairingContext]:
        """Locate and parse pairing record for this UDID."""
        from correlator.pairing import _lockdown_dirs
        for base in _lockdown_dirs():
            if not base.is_dir():
                continue
            candidate = base / f"{self.udid}.plist"
            if candidate.is_file():
                try:
                    with open(candidate, "rb") as f:
                        plist = plistlib.load(f)
                    self.record = PairingContext(
                        udid=self.udid,
                        record_path=candidate,
                        host_id=plist.get("HostID", ""),
                        system_buid=plist.get("SystemBUID", ""),
                        cert_fingerprint=plist.get("RootCertificateFingerprint", b""),
                        wifi_sync=plist.get("WiFiLinkPreferences", {}).get("AllowWifi", False),
                    )
                    return self.record
                except Exception:
                    continue
        return None

    def validate_against_device(self, lockdown_client) -> bool:
        """
        Validates pairing record against device. If device trusts this host cert,
        sessions can be opened without passcode interaction.
        """
        try:
            val = getattr(lockdown_client, "validate_pair", None)
            if callable(val):
                resp = val()
                if inspect.iscoroutine(resp):
                    resp = asyncio.run(resp)
                if isinstance(resp, dict):
                    return resp.get("Error") is None
                return True
            return True
        except Exception:
            return False


class BackupAccessResolver:
    """
    Forensic triage resolver. Determines what extraction path is available given:
    - pairing status
    - device lock state (BFU vs AFU)
    - whether a backup password is already set on the device
    """

    def __init__(self, udid: str, lockdown_client=None):
        self.udid = udid
        self.lockdown = lockdown_client
        self.pairing = LockdownPairingManager(udid)

    def _check_password_set(self) -> bool:
        """Queries lockdown for com.apple.mobile.backup password state."""
        if not self.lockdown:
            return False
        try:
            get_dom = getattr(self.lockdown, "get_value", None)
            if callable(get_dom):
                res = get_dom(domain="com.apple.mobile.backup", key="PasswordSet")
                if inspect.iscoroutine(res):
                    res = asyncio.run(res)
                return bool(res)
        except Exception:
            pass
        return False

    def _check_lock_state(self) -> str:
        """
        Query lockdown for device lock state. AFU (After First Unlock) means the user
        unlocked at least once since boot — keybag is in memory, data classes accessible.
        """
        if not self.lockdown:
            return "UNKNOWN"
        try:
            # Query PasswordProtected attribute
            get_val = getattr(self.lockdown, "get_value", None)
            if callable(get_val):
                res = get_val(key="PasswordProtected")
                if inspect.iscoroutine(res):
                    res = asyncio.run(res)
                # In AFU, PasswordProtected is False or device responds to services
                if res is False:
                    return "AFU"
                if res is True:
                    # Check if device was unlocked at least once by testing battery domain
                    bat = get_val(domain="com.apple.mobile.battery", key="BatteryCurrentCapacity")
                    if inspect.iscoroutine(bat):
                        bat = asyncio.run(bat)
                    return "AFU" if bat is not None else "BFU"
            return "AFU"
        except Exception:
            return "BFU"

    def resolve(self) -> Tuple[AccessTier, Dict[str, Any]]:
        """
        Main forensic decision algorithm. Returns (AccessTier, metadata_dict).
        """
        meta: Dict[str, Any] = {"udid": self.udid}

        # Step 1: Pairing record check
        record = self.pairing.find_record()
        if record is None:
            meta["paired"] = False
            meta["access_tier"] = AccessTier.UNPAIRED.value
            return AccessTier.UNPAIRED, meta

        # Step 2: Validate pairing against device
        if self.lockdown and not self.pairing.validate_against_device(self.lockdown):
            meta["paired"] = False
            meta["access_tier"] = AccessTier.UNPAIRED.value
            return AccessTier.UNPAIRED, meta

        meta["paired"] = True
        meta["host_id"] = record.host_id

        # Step 3: Lock state (AFU vs BFU)
        lock_state = self._check_lock_state()
        meta["lock_state"] = lock_state

        if lock_state == "BFU":
            meta["access_tier"] = AccessTier.BFU_LOCKED.value
            return AccessTier.BFU_LOCKED, meta

        # Step 4: Backup password state
        password_set = self._check_password_set()
        meta["password_set"] = password_set

        if not password_set:
            meta["access_tier"] = AccessTier.FULL_BACKUP.value
            return AccessTier.FULL_BACKUP, meta

        meta["access_tier"] = AccessTier.ENCRYPTED_UNKNOWN.value
        return AccessTier.ENCRYPTED_UNKNOWN, meta


class PasswordFreeBackup:
    """
    Executes backup or media pull operations using established pairing records.
    Does NOT require screen interaction or passcode entry if paired.
    """

    def __init__(self, lockdown_client, udid: str):
        self.lockdown = lockdown_client
        self.udid = udid

    def start_backup(
        self,
        output_dir: Path | str,
        own_password: Optional[str] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> Path:
        """
        Executes backup via Mobilebackup2 protocol.
        """
        out_p = Path(output_dir).resolve()
        out_p.mkdir(parents=True, exist_ok=True)
        return acquire_backup(out_p, udid=self.udid, progress_callback=progress_callback)

    def partial_afc_pull(
        self,
        output_dir: Path | str,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> Dict[str, int]:
        """
        Fallback for ENCRYPTED_UNKNOWN tier.
        AFC (Apple File Conduit) accesses photos (/DCIM), recordings, and crash logs
        without requiring the unknown backup password.
        """
        out_p = Path(output_dir).resolve() / "afc_extracted_media"
        out_p.mkdir(parents=True, exist_ok=True)
        pulled: Dict[str, int] = {}

        if not PYMOBILEDEVICE3_AVAILABLE or not self.lockdown:
            return pulled

        try:
            afc = AfcService(self.lockdown)
            if progress_callback:
                progress_callback("Scanning DCIM media directory over AFC...", 0.1)

            dcim_dir = "/DCIM"
            try:
                entries = afc.listdir(dcim_dir)
            except Exception:
                entries = []

            for idx, entry in enumerate(entries):
                if entry in (".", ".."):
                    continue
                sub_path = f"{dcim_dir}/{entry}"
                try:
                    sub_files = afc.listdir(sub_path)
                    for f_name in sub_files:
                        if f_name in (".", ".."):
                            continue
                        src = f"{sub_path}/{f_name}"
                        dest = out_p / entry / f_name
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        data = afc.get_file_contents(src)
                        dest.write_bytes(data)
                        pulled[f"{entry}/{f_name}"] = len(data)
                except Exception:
                    pass

                if progress_callback and len(entries) > 0:
                    pct = 0.1 + (0.9 * (idx + 1) / len(entries))
                    progress_callback(f"Extracted media: {entry}", pct)

        except Exception as e:
            if progress_callback:
                progress_callback(f"AFC pull notice: {e}", 1.0)

        return pulled


class BackupPasswordCracker:
    """
    Recovers weak or dictionary-based iOS backup passwords for ENCRYPTED_UNKNOWN tier.
    Evaluates candidates against the PBKDF2 hash stored in Manifest.plist.
    """

    def __init__(self, manifest_plist_path: Path | str):
        self.manifest_path = Path(manifest_plist_path).resolve()
        self.salt: bytes = b""
        self.expected_hash: bytes = b""
        self.rounds: int = 52
        self._load_manifest()

    def _load_manifest(self):
        if not self.manifest_path.is_file():
            return
        with open(self.manifest_path, "rb") as f:
            data = plistlib.load(f)

        lockdown_dict = data.get("Lockdown", {})
        self.salt = lockdown_dict.get("PasswordSalt", b"")
        self.expected_hash = lockdown_dict.get("PasswordHash", b"")

        # Check iterations (legacy is 52 rounds; iOS 10.2+ manifest has Iterations key)
        if "Iterations" in lockdown_dict:
            self.rounds = int(lockdown_dict["Iterations"])
        elif "PasswordRounds" in lockdown_dict:
            self.rounds = int(lockdown_dict["PasswordRounds"])

    def try_password(self, candidate: str) -> bool:
        """Tests a single password candidate against PBKDF2 hash."""
        if not self.salt or not self.expected_hash:
            return False

        # Test both 52 rounds (fast check) and configured rounds
        for r in [self.rounds, 52, 10000]:
            try:
                derived = hashlib.pbkdf2_hmac(
                    "sha256",
                    candidate.encode("utf-8"),
                    self.salt,
                    iterations=r,
                    dklen=len(self.expected_hash),
                )
                if derived == self.expected_hash:
                    return True
            except Exception:
                pass
        return False

    def dictionary_attack(
        self,
        wordlist_path: Path | str,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> Optional[str]:
        """Runs through a wordlist candidate file. Returns cracked password if found."""
        wp = Path(wordlist_path).resolve()
        if not wp.is_file():
            return None

        with open(wp, "r", encoding="utf-8", errors="ignore") as f:
            for count, line in enumerate(f, 1):
                candidate = line.strip()
                if not candidate:
                    continue
                if self.try_password(candidate):
                    if progress_callback:
                        progress_callback(f"Password cracked: {candidate}", count)
                    return candidate
                if progress_callback and count % 5000 == 0:
                    progress_callback(f"Tested {count} passwords...", count)

        return None


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
                "access_tier": AccessTier.UNPAIRED.value,
                "lock_state": "UNKNOWN",
                "password_set": False,
            }

            # Try reading lockdown attributes and resolving triage state
            client = None
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

            # Resolve forensic access tier
            try:
                resolver = BackupAccessResolver(udid, client)
                tier, meta = resolver.resolve()
                dev_info["access_tier"] = tier.value
                dev_info["lock_state"] = meta.get("lock_state", "UNKNOWN")
                dev_info["password_set"] = meta.get("password_set", False)
                dev_info["paired"] = meta.get("paired", dev_info["paired"])
            except Exception:
                pass

            devices.append(dev_info)
    except Exception:
        pass

    return devices


def _get_lockdown_client(udid: Optional[str] = None):
    """Safely retrieves a LockdownClient handling both synchronous and async APIs."""
    if not PYMOBILEDEVICE3_AVAILABLE or not is_usbmuxd_running():
        raise RuntimeError("usbmuxd service is not active on port 27015")
    client = create_using_usbmux(serial=udid)
    if inspect.iscoroutine(client):
        return asyncio.run(asyncio.wait_for(client, timeout=2.0))
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
