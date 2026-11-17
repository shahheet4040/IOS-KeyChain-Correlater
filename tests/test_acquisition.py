from pathlib import Path
import plistlib
import hashlib
from unittest.mock import MagicMock, patch
import pytest

from correlator.acquisition import (
    AccessTier,
    BackupAccessResolver,
    BackupPasswordCracker,
    LockdownPairingManager,
    PasswordFreeBackup,
    dump_device_profile,
    is_acquisition_available,
    list_connected_devices,
)


def test_acquisition_availability():
    # Function runs and returns boolean without exception
    res = is_acquisition_available()
    assert isinstance(res, bool)


def test_list_connected_devices_safe_when_no_usb():
    # When no physical iPhone is connected over USB, gracefully returns empty list
    devices = list_connected_devices()
    assert isinstance(devices, list)


@patch("correlator.acquisition.PYMOBILEDEVICE3_AVAILABLE", True)
@patch("correlator.acquisition._get_lockdown_client")
def test_dump_device_profile(mock_get_client, tmp_path):
    mock_client = MagicMock()
    mock_client.device_name = "Forensic iPhone 13"
    mock_client.product_type = "iPhone14,5"
    mock_client.product_version = "17.4.1"
    mock_client.build_version = "21E236"
    mock_client.udid = "00008110-001234567890001E"
    mock_client.get_value.side_effect = lambda domain=None, key=None: {
        "SerialNumber": "F17XABCD9999",
        "WiFiAddress": "AA:BB:CC:DD:EE:FF",
        "BatteryCurrentCapacity": 88,
    }.get(key, "dummy_val")
    mock_get_client.return_value = mock_client

    out_file = tmp_path / "profile.json"
    profile = dump_device_profile(out_file=out_file)

    assert profile["DeviceName"] == "Forensic iPhone 13"
    assert profile["ProductType"] == "iPhone14,5"
    assert profile["ProductVersion"] == "17.4.1"
    assert profile["SerialNumber"] == "F17XABCD9999"
    assert out_file.exists()


def test_backup_access_resolver_unpaired():
    resolver = BackupAccessResolver("nonexistent_udid_12345")
    tier, meta = resolver.resolve()
    assert tier == AccessTier.UNPAIRED
    assert meta["paired"] is False


@patch("correlator.acquisition.LockdownPairingManager.find_record")
@patch("correlator.acquisition.LockdownPairingManager.validate_against_device")
def test_backup_access_resolver_full_backup(mock_val, mock_find):
    from correlator.acquisition import PairingContext
    mock_find.return_value = PairingContext(
        udid="test-udid-1",
        record_path=Path("dummy.plist"),
        host_id="HOST-1234",
    )
    mock_val.return_value = True

    mock_lockdown = MagicMock()
    # AFU: PasswordProtected is False
    mock_lockdown.get_value.return_value = False

    resolver = BackupAccessResolver("test-udid-1", mock_lockdown)
    tier, meta = resolver.resolve()

    assert tier == AccessTier.FULL_BACKUP
    assert meta["paired"] is True
    assert meta["lock_state"] == "AFU"
    assert meta["password_set"] is False


@patch("correlator.acquisition.LockdownPairingManager.find_record")
@patch("correlator.acquisition.LockdownPairingManager.validate_against_device")
def test_backup_access_resolver_encrypted_unknown(mock_val, mock_find):
    from correlator.acquisition import PairingContext
    mock_find.return_value = PairingContext(
        udid="test-udid-2",
        record_path=Path("dummy.plist"),
        host_id="HOST-5678",
    )
    mock_val.return_value = True

    mock_lockdown = MagicMock()
    # AFU state, but PasswordSet domain returns True
    def _mock_get_val(domain=None, key=None):
        if domain == "com.apple.mobile.backup" and key == "PasswordSet":
            return True
        if key == "PasswordProtected":
            return False
        return None

    mock_lockdown.get_value.side_effect = _mock_get_val

    resolver = BackupAccessResolver("test-udid-2", mock_lockdown)
    tier, meta = resolver.resolve()

    assert tier == AccessTier.ENCRYPTED_UNKNOWN
    assert meta["paired"] is True
    assert meta["password_set"] is True


def test_backup_password_cracker(tmp_path):
    # Create realistic test Manifest.plist with PBKDF2 hash
    salt = b"test_forensic_salt_16b"
    pwd = "case_password_99"
    iterations = 52
    expected = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, iterations, 32)

    manifest_data = {
        "IsEncrypted": True,
        "Version": "10.0",
        "Lockdown": {
            "PasswordSalt": salt,
            "PasswordHash": expected,
            "Iterations": iterations,
        },
    }
    manifest_p = tmp_path / "Manifest.plist"
    with open(manifest_p, "wb") as f:
        plistlib.dump(manifest_data, f)

    cracker = BackupPasswordCracker(manifest_p)
    assert cracker.salt == salt
    assert cracker.expected_hash == expected
    assert cracker.rounds == iterations

    # Wrong password test
    assert cracker.try_password("wrong_guess") is False

    # Right password test
    assert cracker.try_password("case_password_99") is True

    # Wordlist test
    wl_file = tmp_path / "wordlist.txt"
    wl_file.write_text("admin\n123456\ncase_password_99\nsecret\n", encoding="utf-8")
    recovered = cracker.dictionary_attack(wl_file)
    assert recovered == "case_password_99"



# ── New tests for AFC improvements and BackupPasswordCracker additions ──────

def _make_manifest(tmp_path: Path, password: str, iterations: int = 52) -> Path:
    """Helper: create a minimal Manifest.plist for a given password."""
    salt = b"test_smart_salt_1"
    expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, 32)
    manifest_data = {
        "IsEncrypted": True,
        "Version": "10.0",
        "Lockdown": {
            "PasswordSalt": salt,
            "PasswordHash": expected,
            "Iterations": iterations,
        },
    }
    p = tmp_path / "Manifest.plist"
    with open(p, "wb") as f:
        plistlib.dump(manifest_data, f)
    return p


def test_afc_file_filter(tmp_path):
    """
    partial_afc_pull must only extract files whose extension is in MEDIA_EXTENSIONS.
    Non-media files should be skipped (skipped=True in metadata).
    """
    from unittest.mock import MagicMock, patch

    # Simulate /DCIM/100APPLE containing a mix of media and non-media files
    media_files = ["IMG_0001.jpg", "IMG_0002.heic", "VID_0001.mov", "audio.m4a"]
    non_media_files = ["Thumbs.db", "notes.txt", ".DS_Store", "config.xml"]
    all_files = media_files + non_media_files

    def _listdir(path):
        if path == "/DCIM":
            return ["100APPLE"]
        if path == "/DCIM/100APPLE":
            return all_files
        # Silently fail for other AFC roots that aren't set up
        raise Exception("not found")

    def _get_file_contents(path):
        # Return 10 bytes of dummy data for every file
        return b"\x00" * 10

    mock_afc = MagicMock()
    mock_afc.listdir.side_effect = _listdir
    mock_afc.get_file_contents.side_effect = _get_file_contents

    mock_lockdown = MagicMock()

    with patch("correlator.acquisition.PYMOBILEDEVICE3_AVAILABLE", True), \
         patch("correlator.acquisition.AfcService", return_value=mock_afc, create=True):
        pfb = PasswordFreeBackup(mock_lockdown, "test-udid")
        result = pfb.partial_afc_pull(tmp_path)

    # result is a list of metadata dicts
    assert isinstance(result, list), "partial_afc_pull should return a list"

    extracted = [r for r in result if not r["skipped"]]
    skipped = [r for r in result if r["skipped"]]

    extracted_names = {Path(r["path"]).name for r in extracted}
    skipped_names = {Path(r["path"]).name for r in skipped}

    # Every media file must be extracted (not skipped)
    for mf in media_files:
        assert mf in extracted_names, f"{mf} should have been extracted"

    # Every non-media file must be skipped
    for nmf in non_media_files:
        assert nmf in skipped_names, f"{nmf} should have been skipped"

    # Skip reasons for non-media files mention 'non-media'
    for r in skipped:
        if Path(r["path"]).name in non_media_files:
            assert r["skip_reason"] is not None
            assert "non-media" in r["skip_reason"]


def test_smart_attack_common_passwords(tmp_path):
    """
    smart_attack() should find a password that is in COMMON_PASSWORDS ("apple")
    without needing an external wordlist.
    """
    manifest_p = _make_manifest(tmp_path, "apple")
    cracker = BackupPasswordCracker(manifest_p)
    found = cracker.smart_attack()
    assert found == "apple", f"Expected 'apple', got {found!r}"


def test_tried_count(tmp_path):
    """
    tried_count must increment by exactly 1 for each candidate tested in smart_attack().
    If the password is not in COMMON_PASSWORDS, the whole list is exhausted.
    """
    # Use a password that is NOT in COMMON_PASSWORDS so the full list is searched
    manifest_p = _make_manifest(tmp_path, "this_is_not_in_common_list_xyz_99")
    cracker = BackupPasswordCracker(manifest_p)

    assert cracker.tried_count == 0

    # smart_attack with no extra candidates — exhausts COMMON_PASSWORDS
    result = cracker.smart_attack(candidate_list=None)
    assert result is None  # not found
    assert cracker.tried_count == len(BackupPasswordCracker.COMMON_PASSWORDS)

    # Second call with one extra candidate (also wrong) — tried_count keeps growing
    prev_count = cracker.tried_count
    cracker.smart_attack(candidate_list=["still_not_it"])
    assert cracker.tried_count == prev_count + len(BackupPasswordCracker.COMMON_PASSWORDS) + 1
