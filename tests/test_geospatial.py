"""
Unit Tests for Forensic Geospatial & Photo EXIF Engine
======================================================
Verifies conversion of DMS rationals to decimal degrees,
binary EXIF parsing, database harvesting, route trail analysis,
and multi-format export (GeoJSON, KML, CSV, Interactive HTML Map).
"""

import json
from pathlib import Path
import sqlite3
from correlator.geospatial import (
    GeoPoint,
    _convert_dms_to_dd,
    analyze_movement_trail,
    export_csv,
    export_geojson,
    export_kml,
    generate_interactive_map_html,
    harvest_all_locations,
    harvest_apple_routined,
    harvest_photos_sqlite,
    harvest_whatsapp_locations,
    haversine_distance,
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


def test_haversine_distance():
    # Distance between New York (40.7128, -74.0060) and Philadelphia (39.9526, -75.1652) is ~130 km
    dist = haversine_distance(40.7128, -74.0060, 39.9526, -75.1652)
    assert 128000 < dist < 132000
    # Same point distance is 0
    assert haversine_distance(37.7749, -122.4194, 37.7749, -122.4194) == 0.0


def test_analyze_movement_trail():
    p1 = GeoPoint(
        point_id="P1",
        latitude=37.7749,
        longitude=-122.4194,
        timestamp_utc="2026-11-16 10:00:00 UTC",
        timestamp_epoch=1000.0,
    )
    # 1.5 km away, 300 seconds later (1500 m / 300 s = 5 m/s = 18 km/h -> Cycling/City Transit)
    p2 = GeoPoint(
        point_id="P2",
        latitude=37.7849,
        longitude=-122.4094,
        timestamp_utc="2026-11-16 10:05:00 UTC",
        timestamp_epoch=1300.0,
    )
    points, summary = analyze_movement_trail([p1, p2])
    assert len(points) == 2
    assert summary["total_points"] == 2
    assert summary["total_distance_km"] > 1.0
    assert points[1].speed_kmh is not None
    assert points[1].speed_kmh > 0
    assert "Transit" in points[1].inferred_mode or "Cycling" in points[1].inferred_mode


def test_export_geojson_and_kml_and_csv(tmp_path):
    pts = [
        GeoPoint(point_id="P1", latitude=40.7128, longitude=-74.0060, timestamp_utc="2026-11-16 10:00:00 UTC", timestamp_epoch=1000.0),
        GeoPoint(point_id="P2", latitude=40.7228, longitude=-74.0160, timestamp_utc="2026-11-16 10:10:00 UTC", timestamp_epoch=1600.0),
    ]
    geojson_path = tmp_path / "route.geojson"
    kml_path = tmp_path / "route.kml"
    csv_path = tmp_path / "route.csv"

    # 1. GeoJSON
    gj = export_geojson(pts, geojson_path)
    assert geojson_path.exists()
    assert gj["type"] == "FeatureCollection"
    assert len(gj["features"]) == 3  # 2 points + 1 LineString

    # 2. KML
    kml = export_kml(pts, kml_path, case_name="Case_123")
    assert kml_path.exists()
    assert "<kml" in kml
    assert "Case_123" in kml
    assert "Chronological Movement Trail" in kml

    # 3. CSV
    export_csv(pts, csv_path)
    assert csv_path.exists()
    content = csv_path.read_text(encoding="utf-8")
    assert "Point ID" in content
    assert "40.7128" in content


def test_generate_interactive_map_html(tmp_path):
    pts = [
        GeoPoint(point_id="P1", latitude=34.0522, longitude=-118.2437, timestamp_utc="2026-11-16 12:00:00 UTC", timestamp_epoch=1000.0),
    ]
    html_path = tmp_path / "map.html"
    code = generate_interactive_map_html(pts, out_path=html_path)
    assert html_path.exists()
    assert "<!DOCTYPE html>" in code
    assert "leaflet.js" in code
    assert "time-slider" in code
    assert "-118.2437" in code


def test_database_harvesters(tmp_path):
    # 1. Test Photos.sqlite harvesting
    photos_db = tmp_path / "Photos.sqlite"
    con = sqlite3.connect(photos_db)
    con.execute("""
        CREATE TABLE ZGENERICASSET (
            Z_PK INTEGER PRIMARY KEY,
            ZLATITUDE REAL,
            ZLONGITUDE REAL,
            ZALTITUDE REAL,
            ZDATECREATED REAL,
            ZDIRECTORY TEXT,
            ZFILENAME TEXT
        );
    """)
    # Add a photo location: Apple epoch 0 is 2001-01-01
    con.execute("INSERT INTO ZGENERICASSET VALUES (1, 37.7749, -122.4194, 15.0, 100000.0, 'DCIM/100APPLE', 'IMG_0001.JPG');")
    con.commit()
    con.close()

    photos_pts = harvest_photos_sqlite(tmp_path)
    assert len(photos_pts) == 1
    assert photos_pts[0].latitude == 37.7749
    assert photos_pts[0].source_type == "photos_sqlite"
    assert photos_pts[0].file_name == "IMG_0001.JPG"

    # 2. Test WhatsApp ChatStorage.sqlite harvesting
    wa_db = tmp_path / "ChatStorage.sqlite"
    con = sqlite3.connect(wa_db)
    con.execute("""
        CREATE TABLE ZWAMESSAGE (
            Z_PK INTEGER PRIMARY KEY,
            ZMESSAGEDATE REAL,
            ZLATITUDE REAL,
            ZLONGITUDE REAL,
            ZTEXT TEXT
        );
    """)
    con.execute("INSERT INTO ZWAMESSAGE VALUES (1, 100500.0, 37.7849, -122.4094, 'Meeting you here');")
    con.commit()
    con.close()

    wa_pts = harvest_whatsapp_locations(tmp_path)
    assert len(wa_pts) == 1
    assert wa_pts[0].latitude == 37.7849
    assert wa_pts[0].source_type == "whatsapp"

    # 3. Test harvest_all_locations
    all_pts, summary = harvest_all_locations(tmp_path)
    assert len(all_pts) == 2
    assert summary["total_points"] == 2
    assert summary["total_distance_km"] > 0.0
