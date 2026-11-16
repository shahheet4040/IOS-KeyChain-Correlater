from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from correlator.acquisition import (
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
