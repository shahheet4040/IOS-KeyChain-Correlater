from pathlib import Path
import plistlib
import pytest

from correlator.pairing import (
    find_pairing_records,
    get_pairing_summary,
    match_device_to_pairing,
    parse_pairing_record,
)


def test_find_pairing_records_no_crash():
    records = find_pairing_records()
    assert isinstance(records, list)


def test_parse_pairing_record(tmp_path: Path):
    plist_path = tmp_path / "00008030-001A2B3C4D5E6F7A.plist"
    mock_data = {
        "HostID": "mock-host-uuid-1234",
        "SystemBUID": "mock-system-buid-5678",
        "WiFiMACAddress": "aa:bb:cc:dd:ee:ff",
        "DeviceCertificate": b"MOCK_DEV_CERT",
        "HostCertificate": b"MOCK_HOST_CERT",
        "EscrowBag": b"MOCK_ESCROW",
    }
    with open(plist_path, "wb") as f:
        plistlib.dump(mock_data, f)

    parsed = parse_pairing_record(plist_path)
    assert parsed["udid"] == "00008030-001A2B3C4D5E6F7A"
    assert parsed["host_id"] == "mock-host-uuid-1234"
    assert parsed["wifi_mac"] == "aa:bb:cc:dd:ee:ff"
    assert parsed["has_escrow_bag"] is True
    assert parsed["has_device_cert"] is True
    assert parsed["has_host_cert"] is True


def test_match_device_to_pairing(tmp_path: Path):
    plist_path = tmp_path / "1234567890abcdef.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump({"HostID": "test"}, f)

    record = parse_pairing_record(plist_path)
    matched = match_device_to_pairing("1234567890abcdef", records=[record])
    assert matched is not None
    assert matched["udid"] == "1234567890abcdef"

    not_matched = match_device_to_pairing("different-udid", records=[record])
    assert not_matched is None


def test_get_pairing_summary():
    summary = get_pairing_summary()
    assert "iOS Lockdown Pairing Record Scanner" in summary
    assert isinstance(summary, str)
