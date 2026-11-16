"""
Tests for case_compare.py
==========================
Creates two temporary SQLite databases via init_consolidated_schema,
inserts overlapping and unique evidence, and verifies all comparison methods.
"""

import math
import sqlite3
import tempfile
import uuid
from pathlib import Path

import pytest

from correlator.consolidated_db import init_consolidated_schema
from correlator.case_compare import CaseComparison, compare_two_cases


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path, suffix: str) -> Path:
    """Create a temporary consolidated evidence database."""
    db_path = tmp_path / f"case_{suffix}.sqlite"
    con = sqlite3.connect(str(db_path))
    init_consolidated_schema(con)
    return db_path, con


def _insert_messages(con: sqlite3.Connection, rows: list[dict]) -> None:
    for r in rows:
        con.execute(
            "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r.get("id", str(uuid.uuid4())),
                r.get("app", "Signal"),
                r.get("event_type", "message"),
                r.get("timestamp_utc", "2024-01-01 10:00:00 UTC"),
                r.get("timestamp_epoch", 1704067200.0),
                r.get("sender", "unknown"),
                r.get("recipient", "unknown"),
                r.get("content", ""),
                r.get("source_database", "test.sqlite"),
                r.get("source_table", "messages"),
                r.get("raw_metadata", "{}"),
            ),
        )
    con.commit()


def _insert_locations(con: sqlite3.Connection, rows: list[dict]) -> None:
    for r in rows:
        con.execute(
            "INSERT INTO locations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r.get("location_id", str(uuid.uuid4())),
                r.get("file_name", "photo.jpg"),
                r.get("file_path", "/media/photo.jpg"),
                r.get("latitude"),
                r.get("longitude"),
                r.get("altitude", 0.0),
                r.get("timestamp_utc", "2024-01-01 10:00:00 UTC"),
                r.get("timestamp_epoch", 1704067200.0),
                r.get("camera_make", "Apple"),
                r.get("camera_model", "iPhone 15"),
            ),
        )
    con.commit()


def _insert_alerts(con: sqlite3.Connection, rows: list[dict]) -> None:
    for r in rows:
        con.execute(
            "INSERT INTO keyword_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r.get("alert_id", str(uuid.uuid4())),
                r.get("category", "General"),
                r.get("matched_term", "term"),
                r.get("severity", "MEDIUM"),
                r.get("database_name", "test.sqlite"),
                r.get("table_name", "messages"),
                r.get("column_name", "content"),
                r.get("context_snippet", "...context..."),
                r.get("row_data_json", "{}"),
            ),
        )
    con.commit()


def _insert_timeline(con: sqlite3.Connection, rows: list[dict]) -> None:
    for r in rows:
        con.execute(
            "INSERT INTO timeline_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r.get("event_id", str(uuid.uuid4())),
                r.get("timestamp_utc", "2024-01-01 10:00:00 UTC"),
                r.get("timestamp_epoch", 1704067200.0),
                r.get("app", "Signal"),
                r.get("event_type", "message"),
                r.get("sender", "alice"),
                r.get("recipient", "bob"),
                r.get("content", "hello"),
                r.get("source_database", "test.sqlite"),
                r.get("source_table", "messages"),
                r.get("metadata_json", "{}"),
            ),
        )
    con.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCompareMessages:
    def test_shared_senders_non_empty(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        # Shared sender: alice
        _insert_messages(con_a, [
            {"sender": "alice", "id": "a1"},
            {"sender": "dave", "id": "a2"},
        ])
        _insert_messages(con_b, [
            {"sender": "alice", "id": "b1"},
            {"sender": "eve", "id": "b2"},
        ])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_messages()
        cc.close()

        assert "alice" in result["shared_senders"], "alice should be a shared sender"
        assert len(result["shared_senders"]) >= 1
        assert isinstance(result["unique_to_case_a"], int)
        assert isinstance(result["unique_to_case_b"], int)
        assert isinstance(result["overlap_count"], int)
        assert result["overlap_count"] >= 1

    def test_no_shared_senders(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        _insert_messages(con_a, [{"sender": "alice", "id": "a1"}])
        _insert_messages(con_b, [{"sender": "bob", "id": "b1"}])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_messages()
        cc.close()

        assert result["shared_senders"] == []
        assert result["overlap_count"] == 0

    def test_empty_databases(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_messages()
        cc.close()

        assert result["shared_senders"] == []
        assert result["unique_to_case_a"] == 0
        assert result["unique_to_case_b"] == 0


class TestCompareLocations:
    def test_proximity_matches_non_empty(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        # Very close locations (distance < 0.01 deg)
        _insert_locations(con_a, [{"latitude": 37.7749, "longitude": -122.4194, "file_name": "photo_a.jpg"}])
        _insert_locations(con_b, [{"latitude": 37.7750, "longitude": -122.4193, "file_name": "photo_b.jpg"}])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_locations()
        cc.close()

        assert result["total_locs_a"] == 1
        assert result["total_locs_b"] == 1
        assert len(result["proximity_matches"]) >= 1
        match = result["proximity_matches"][0]
        assert "lat_a" in match
        assert "lon_a" in match
        assert "lat_b" in match
        assert "lon_b" in match
        assert "distance_deg" in match
        assert match["distance_deg"] <= 0.01

    def test_no_proximity_match_when_far_apart(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        # Far apart locations
        _insert_locations(con_a, [{"latitude": 37.7749, "longitude": -122.4194}])
        _insert_locations(con_b, [{"latitude": 51.5074, "longitude": -0.1278}])  # London
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_locations()
        cc.close()

        assert result["proximity_matches"] == []


class TestCompareAlerts:
    def test_shared_categories_and_terms(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        _insert_alerts(con_a, [
            {"category": "Crypto", "matched_term": "bitcoin", "severity": "CRITICAL"},
            {"category": "Weapons", "matched_term": "firearm"},
        ])
        _insert_alerts(con_b, [
            {"category": "Crypto", "matched_term": "bitcoin", "severity": "CRITICAL"},
            {"category": "Narcotics", "matched_term": "fentanyl"},
        ])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_alerts()
        cc.close()

        assert "Crypto" in result["shared_alert_categories"]
        assert "bitcoin" in result["shared_matched_terms"]
        assert result["critical_in_both"] >= 1

    def test_no_shared_alerts(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        _insert_alerts(con_a, [{"category": "Crypto", "matched_term": "ethereum"}])
        _insert_alerts(con_b, [{"category": "Weapons", "matched_term": "rifle"}])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_alerts()
        cc.close()

        assert result["shared_alert_categories"] == []
        assert result["shared_matched_terms"] == []


class TestCompareTimelineOverlap:
    def test_overlap_exists_true(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        # Case A: Jan 1–Jan 10 2024
        # Case B: Jan 5–Jan 15 2024 -> overlap Jan 5–Jan 10
        import time
        from datetime import datetime, timezone

        t_jan1 = datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()
        t_jan5 = datetime(2024, 1, 5, tzinfo=timezone.utc).timestamp()
        t_jan10 = datetime(2024, 1, 10, tzinfo=timezone.utc).timestamp()
        t_jan15 = datetime(2024, 1, 15, tzinfo=timezone.utc).timestamp()

        _insert_timeline(con_a, [
            {"event_id": "a1", "timestamp_epoch": t_jan1, "timestamp_utc": "2024-01-01 00:00:00 UTC"},
            {"event_id": "a2", "timestamp_epoch": t_jan10, "timestamp_utc": "2024-01-10 00:00:00 UTC"},
        ])
        _insert_timeline(con_b, [
            {"event_id": "b1", "timestamp_epoch": t_jan5, "timestamp_utc": "2024-01-05 00:00:00 UTC"},
            {"event_id": "b2", "timestamp_epoch": t_jan15, "timestamp_utc": "2024-01-15 00:00:00 UTC"},
        ])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_timeline_overlap()
        cc.close()

        assert result["overlap_exists"] is True, "Time ranges should overlap"
        assert result["overlap_start"] is not None
        assert result["overlap_end"] is not None
        assert result["overlap_duration_hours"] is not None
        assert result["overlap_duration_hours"] > 0

    def test_no_overlap(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        from datetime import datetime, timezone
        t_jan1 = datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()
        t_jan5 = datetime(2024, 1, 5, tzinfo=timezone.utc).timestamp()
        t_feb1 = datetime(2024, 2, 1, tzinfo=timezone.utc).timestamp()
        t_feb15 = datetime(2024, 2, 15, tzinfo=timezone.utc).timestamp()

        _insert_timeline(con_a, [
            {"event_id": "a1", "timestamp_epoch": t_jan1},
            {"event_id": "a2", "timestamp_epoch": t_jan5},
        ])
        _insert_timeline(con_b, [
            {"event_id": "b1", "timestamp_epoch": t_feb1},
            {"event_id": "b2", "timestamp_epoch": t_feb15},
        ])
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_timeline_overlap()
        cc.close()

        assert result["overlap_exists"] is False
        assert result["overlap_start"] is None
        assert result["overlap_end"] is None
        assert result["overlap_duration_hours"] is None

    def test_empty_timeline(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")
        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        result = cc.compare_timeline_overlap()
        cc.close()

        assert result["overlap_exists"] is False


class TestFullComparisonReport:
    def test_full_report_has_all_sections(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")

        from datetime import datetime, timezone

        t1 = datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()
        t2 = datetime(2024, 1, 10, tzinfo=timezone.utc).timestamp()
        t3 = datetime(2024, 1, 5, tzinfo=timezone.utc).timestamp()
        t4 = datetime(2024, 1, 15, tzinfo=timezone.utc).timestamp()

        # Shared sender
        _insert_messages(con_a, [{"sender": "alice", "id": "fa1"}])
        _insert_messages(con_b, [{"sender": "alice", "id": "fb1"}])

        # Nearby locations
        _insert_locations(con_a, [{"latitude": 48.8566, "longitude": 2.3522}])
        _insert_locations(con_b, [{"latitude": 48.8567, "longitude": 2.3521}])

        # Shared alert
        _insert_alerts(con_a, [{"category": "Financial", "matched_term": "wire transfer"}])
        _insert_alerts(con_b, [{"category": "Financial", "matched_term": "wire transfer"}])

        # Overlapping timeline
        _insert_timeline(con_a, [
            {"event_id": "ft1", "timestamp_epoch": t1, "timestamp_utc": "2024-01-01 00:00:00 UTC"},
            {"event_id": "ft2", "timestamp_epoch": t2, "timestamp_utc": "2024-01-10 00:00:00 UTC"},
        ])
        _insert_timeline(con_b, [
            {"event_id": "ft3", "timestamp_epoch": t3, "timestamp_utc": "2024-01-05 00:00:00 UTC"},
            {"event_id": "ft4", "timestamp_epoch": t4, "timestamp_utc": "2024-01-15 00:00:00 UTC"},
        ])

        con_a.close()
        con_b.close()

        cc = CaseComparison(db_a_path, db_b_path)
        report = cc.full_comparison_report()
        cc.close()

        # Must have all four sections
        assert "messages" in report
        assert "locations" in report
        assert "alerts" in report
        assert "timeline" in report
        assert "metadata" in report

        # Metadata fields
        meta = report["metadata"]
        assert "compared_at" in meta
        assert "db_path_a" in meta
        assert "db_path_b" in meta

        # Messages section
        assert "alice" in report["messages"]["shared_senders"]

        # Locations section
        assert len(report["locations"]["proximity_matches"]) >= 1

        # Alerts section
        assert "Financial" in report["alerts"]["shared_alert_categories"]
        assert "wire transfer" in report["alerts"]["shared_matched_terms"]

        # Timeline section
        assert report["timeline"]["overlap_exists"] is True

    def test_convenience_function(self, tmp_path):
        db_a_path, con_a = _make_db(tmp_path, "a")
        db_b_path, con_b = _make_db(tmp_path, "b")
        con_a.close()
        con_b.close()

        result = compare_two_cases(db_a_path, db_b_path)
        assert isinstance(result, dict)
        assert "messages" in result
        assert "locations" in result
        assert "alerts" in result
        assert "timeline" in result
        assert "metadata" in result
