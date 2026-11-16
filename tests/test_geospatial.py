"""
Unit Tests for Forensic Geospatial & Photo EXIF Engine
======================================================
Verifies conversion of DMS rationals to decimal degrees,
binary EXIF parsing, and GPS coordinates extraction from media files.
"""

from pathlib import Path
from correlator.geospatial import (
    GeoPoint,
    _convert_dms_to_dd,
    scan_media_for_gps,
)


def test_convert_dms_to_dd():
    # 37 degrees, 46 minutes, 29.88 seconds North -> ~37.774967
    dms_lat = [(37, 1), (46, 1), (2988, 100)]
    lat = _convert_dms_to_dd(dms_lat, "N")
    assert lat is not None
    assert round(lat, 4) == 37.7750

    # 122 degrees, 25 minutes, 9.84 seconds West -> -122.4194
    dms_lon = [(122, 1), (25, 1), (984, 100)]
    lon = _convert_dms_to_dd(dms_lon, "W")
    assert lon is not None
    assert lon < 0
    assert round(lon, 4) == -122.4194

    # Invalid rationals gracefully handled
    assert _convert_dms_to_dd([(1, 0), (0, 0), (0, 0)], "N") == 0.0


def test_scan_media_for_gps_empty_dir(tmp_path):
    res = scan_media_for_gps(tmp_path)
    assert isinstance(res, list)
    assert len(res) == 0


def test_geopoint_to_dict():
    gp = GeoPoint(
        point_id="GEO-TEST",
        file_name="IMG_0001.JPG",
        file_path="/var/mobile/Media/DCIM/IMG_0001.JPG",
        file_size_bytes=2048000,
        latitude=40.7128,
        longitude=-74.0060,
        altitude_meters=10.5,
        timestamp_utc="2026-11-16 12:00:00 UTC",
        timestamp_epoch=1794800000.0,
        camera_make="Apple",
        camera_model="iPhone 14 Pro",
    )
    d = gp.to_dict()
    assert d["point_id"] == "GEO-TEST"
    assert d["latitude"] == 40.7128
    assert d["camera_model"] == "iPhone 14 Pro"
