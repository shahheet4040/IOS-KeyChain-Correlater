"""
Tests for export_formats.py
============================
Builds a minimal in-memory SQLite DB, populates it with sample rows using the
real schema from consolidated_db, then exercises all three export functions.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from correlator.consolidated_db import init_consolidated_schema
from correlator.export_formats import (
    export_to_geojson,
    export_to_jsonl,
    export_to_xlsx,
)

# ---------------------------------------------------------------------------
# Fixture: minimal populated database on disk
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_db(tmp_path: Path) -> Path:
    """Create a small SQLite DB with one row in each key table."""
    db_path = tmp_path / "test_evidence.sqlite"
    con = sqlite3.connect(str(db_path))
    init_consolidated_schema(con)
    cur = con.cursor()

    # messages
    cur.execute(
        """
        INSERT INTO messages
            (id, app, event_type, timestamp_utc, timestamp_epoch,
             sender, recipient, content, source_database, source_table, raw_metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "msg-001", "Signal", "message", "2024-01-15 10:30:00 UTC", 1705312200.0,
            "Alice", "Bob", "Meet me at the park at noon.",
            "signal.sqlite", "chat_messages",
            '{"delivered": true}',
        ),
    )

    # timeline_events
    cur.execute(
        """
        INSERT INTO timeline_events
            (event_id, timestamp_utc, timestamp_epoch, app, event_type,
             sender, recipient, content, source_database, source_table, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "evt-001", "2024-01-15 10:30:00 UTC", 1705312200.0,
            "Signal", "message", "Alice", "Bob",
            "Meet me at the park at noon.",
            "signal.sqlite", "chat_messages",
            '{"seq": 1}',
        ),
    )

    # locations  (two points so we can check bounding box)
    cur.executemany(
        """
        INSERT INTO locations
            (location_id, file_name, file_path, latitude, longitude, altitude,
             timestamp_utc, timestamp_epoch, camera_make, camera_model)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "loc-001", "IMG_0001.JPG", "/DCIM/IMG_0001.JPG",
                37.7749, -122.4194, 15.0,
                "2024-01-15 10:00:00 UTC", 1705309200.0,
                "Apple", "iPhone 14 Pro",
            ),
            (
                "loc-002", "IMG_0002.JPG", "/DCIM/IMG_0002.JPG",
                34.0522, -118.2437, 90.0,
                "2024-01-16 12:00:00 UTC", 1705406400.0,
                "Apple", "iPhone 14 Pro",
            ),
        ],
    )

    # keyword_alerts
    cur.execute(
        """
        INSERT INTO keyword_alerts
            (alert_id, category, matched_term, severity, database_name,
             table_name, column_name, context_snippet, row_data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "alert-001", "Crypto", "bitcoin", "HIGH",
            "signal.sqlite", "chat_messages", "content",
            "...send me 0.5 bitcoin...",
            '{"id": "msg-001"}',
        ),
    )

    # audit_trail
    cur.execute(
        """
        INSERT INTO audit_trail
            (step_number, phase, action, target, status, timestamp, details_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            1, "Acquisition", "Extracted keychain", "device-001",
            "success", "2024-01-15 09:00:00 UTC",
            '{"key": "abc123"}',
        ),
    )

    con.commit()
    con.close()
    return db_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestExportToXlsx:
    def test_file_created(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "report.xlsx"
        result = export_to_xlsx(sample_db, out)
        assert Path(result["path"]).exists(), "output file must exist"

    def test_file_size(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "report2.xlsx"
        result = export_to_xlsx(sample_db, out)
        size = Path(result["path"]).stat().st_size
        assert size > 500, f"file too small ({size} bytes)"

    def test_format_key(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "report3.xlsx"
        result = export_to_xlsx(sample_db, out)
        assert result["format"] in ("xlsx", "csv_zip")

    def test_row_counts_dict(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "report4.xlsx"
        result = export_to_xlsx(sample_db, out)
        rc = result["row_counts"]
        assert isinstance(rc, dict)
        # We inserted 1 message, 2 locations, 1 alert, 1 audit row
        assert rc.get("messages", 0) == 1
        assert rc.get("locations", 0) == 2
        assert rc.get("keyword_alerts", 0) == 1
        assert rc.get("audit_trail", 0) == 1


class TestExportToJsonl:
    def _load_lines(self, path: str):
        lines = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    lines.append(json.loads(line))
        return lines

    def test_file_created(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "export.jsonl"
        result = export_to_jsonl(sample_db, out)
        assert Path(result["path"]).exists()

    def test_file_size(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "export2.jsonl"
        result = export_to_jsonl(sample_db, out)
        size = Path(result["path"]).stat().st_size
        assert size > 500, f"file too small ({size} bytes)"

    def test_total_lines(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "export3.jsonl"
        result = export_to_jsonl(sample_db, out)
        # We inserted 1 msg + 1 timeline + 2 locations + 1 alert + 1 audit = 6 rows
        assert result["total_lines"] >= 6

    def test_table_key_in_every_line(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "export4.jsonl"
        result = export_to_jsonl(sample_db, out)
        lines = self._load_lines(result["path"])
        assert len(lines) > 0
        for obj in lines:
            assert "table" in obj, f"missing 'table' key: {obj}"
            assert "record" in obj, f"missing 'record' key: {obj}"

    def test_tables_list(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "export5.jsonl"
        result = export_to_jsonl(sample_db, out)
        assert isinstance(result["tables"], list)
        assert "messages" in result["tables"]
        assert "locations" in result["tables"]


class TestExportToGeojson:
    def _load_geojson(self, path: str) -> dict:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_file_created(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations.geojson"
        result = export_to_geojson(sample_db, out)
        assert Path(result["path"]).exists()

    def test_file_size(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations2.geojson"
        result = export_to_geojson(sample_db, out)
        size = Path(result["path"]).stat().st_size
        assert size > 500, f"file too small ({size} bytes)"

    def test_feature_collection_type(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations3.geojson"
        result = export_to_geojson(sample_db, out)
        gj = self._load_geojson(result["path"])
        assert gj["type"] == "FeatureCollection"

    def test_features_is_list(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations4.geojson"
        result = export_to_geojson(sample_db, out)
        gj = self._load_geojson(result["path"])
        assert isinstance(gj["features"], list)

    def test_feature_count(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations5.geojson"
        result = export_to_geojson(sample_db, out)
        gj = self._load_geojson(result["path"])
        assert result["feature_count"] == 2
        assert len(gj["features"]) == 2

    def test_bounding_box(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations6.geojson"
        result = export_to_geojson(sample_db, out)
        bb = result["bounding_box"]
        assert bb is not None
        assert len(bb) == 4
        min_lon, min_lat, max_lon, max_lat = bb
        assert min_lon <= max_lon
        assert min_lat <= max_lat

    def test_feature_geometry(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations7.geojson"
        result = export_to_geojson(sample_db, out)
        gj = self._load_geojson(result["path"])
        for feat in gj["features"]:
            assert feat["type"] == "Feature"
            geom = feat["geometry"]
            assert geom["type"] == "Point"
            coords = geom["coordinates"]
            assert len(coords) >= 2  # lon, lat [, alt]

    def test_feature_properties(self, sample_db: Path, tmp_path: Path):
        out = tmp_path / "locations8.geojson"
        result = export_to_geojson(sample_db, out)
        gj = self._load_geojson(result["path"])
        for feat in gj["features"]:
            props = feat["properties"]
            assert "file_name" in props
            assert "timestamp_utc" in props
            assert "camera_make" in props
            assert "camera_model" in props
