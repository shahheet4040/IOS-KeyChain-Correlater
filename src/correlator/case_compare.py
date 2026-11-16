"""
Case Comparison Module
======================
Compares two consolidated forensic evidence databases to identify shared
identifiers, geographic overlap, common keyword alerts, and temporal overlap.
"""

from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class CaseComparison:
    """Compares two consolidated evidence databases to find shared identifiers,
    overlap, and unique evidence."""

    def __init__(self, db_path_a: "str | Path", db_path_b: "str | Path") -> None:
        self.db_path_a = str(Path(db_path_a).resolve())
        self.db_path_b = str(Path(db_path_b).resolve())
        self._con_a = sqlite3.connect(
            f"{Path(db_path_a).resolve().as_uri()}?mode=ro", uri=True
        )
        self._con_a.row_factory = sqlite3.Row
        self._con_b = sqlite3.connect(
            f"{Path(db_path_b).resolve().as_uri()}?mode=ro", uri=True
        )
        self._con_b.row_factory = sqlite3.Row

    def close(self) -> None:
        """Close both database connections."""
        self._con_a.close()
        self._con_b.close()

    def __enter__(self) -> "CaseComparison":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------
    # compare_messages
    # ------------------------------------------------------------------

    def compare_messages(self) -> dict:
        """Find senders/recipients that appear in BOTH cases (shared contacts).

        Returns:
            {
                "shared_senders": [list of sender values in both],
                "unique_to_case_a": int (message count),
                "unique_to_case_b": int,
                "overlap_count": int
            }
        """
        def _senders(con: sqlite3.Connection) -> set:
            rows = con.execute(
                "SELECT DISTINCT sender FROM messages WHERE sender IS NOT NULL AND sender != ''"
            ).fetchall()
            return {r[0] for r in rows}

        def _msg_count(con: sqlite3.Connection) -> int:
            return con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

        senders_a = _senders(self._con_a)
        senders_b = _senders(self._con_b)
        shared = sorted(senders_a & senders_b)

        count_a = _msg_count(self._con_a)
        count_b = _msg_count(self._con_b)

        # Unique message counts: messages whose sender is NOT in the other case
        unique_senders_a = senders_a - senders_b
        unique_senders_b = senders_b - senders_a

        def _count_for_senders(con: sqlite3.Connection, senders: set) -> int:
            if not senders:
                return 0
            placeholders = ",".join("?" * len(senders))
            return con.execute(
                f"SELECT COUNT(*) FROM messages WHERE sender IN ({placeholders})",
                list(senders),
            ).fetchone()[0]

        unique_a = _count_for_senders(self._con_a, unique_senders_a)
        unique_b = _count_for_senders(self._con_b, unique_senders_b)

        # overlap_count: messages in A whose sender also appears in B
        overlap = 0
        if shared:
            placeholders = ",".join("?" * len(shared))
            overlap = self._con_a.execute(
                f"SELECT COUNT(*) FROM messages WHERE sender IN ({placeholders})",
                shared,
            ).fetchone()[0]

        return {
            "shared_senders": shared,
            "unique_to_case_a": unique_a,
            "unique_to_case_b": unique_b,
            "overlap_count": overlap,
        }

    # ------------------------------------------------------------------
    # compare_locations
    # ------------------------------------------------------------------

    def compare_locations(self) -> dict:
        """Find locations within 0.01 degree (~1 km) of each other between cases.

        Returns:
            {
                "proximity_matches": [{"lat_a", "lon_a", "lat_b", "lon_b",
                                       "distance_deg", "file_a", "file_b"}],
                "total_locs_a": int,
                "total_locs_b": int
            }
        """
        def _locs(con: sqlite3.Connection):
            return con.execute(
                "SELECT latitude, longitude, file_name FROM locations "
                "WHERE latitude IS NOT NULL AND longitude IS NOT NULL"
            ).fetchall()

        locs_a = _locs(self._con_a)
        locs_b = _locs(self._con_b)

        THRESHOLD = 0.01  # degrees (~1 km)
        proximity_matches = []

        for row_a in locs_a:
            lat_a, lon_a, file_a = row_a[0], row_a[1], row_a[2]
            for row_b in locs_b:
                lat_b, lon_b, file_b = row_b[0], row_b[1], row_b[2]
                # Euclidean distance in degree-space (sufficient for ~1 km threshold)
                dist = math.sqrt((lat_a - lat_b) ** 2 + (lon_a - lon_b) ** 2)
                if dist <= THRESHOLD:
                    proximity_matches.append({
                        "lat_a": lat_a,
                        "lon_a": lon_a,
                        "lat_b": lat_b,
                        "lon_b": lon_b,
                        "distance_deg": round(dist, 6),
                        "file_a": file_a or "",
                        "file_b": file_b or "",
                    })

        return {
            "proximity_matches": proximity_matches,
            "total_locs_a": len(locs_a),
            "total_locs_b": len(locs_b),
        }

    # ------------------------------------------------------------------
    # compare_alerts
    # ------------------------------------------------------------------

    def compare_alerts(self) -> dict:
        """Find matching alert categories and identical matched terms across cases.

        Returns:
            {
                "shared_alert_categories": [str],
                "shared_matched_terms": [str],
                "critical_in_both": int
            }
        """
        def _categories(con: sqlite3.Connection) -> set:
            rows = con.execute(
                "SELECT DISTINCT category FROM keyword_alerts WHERE category IS NOT NULL"
            ).fetchall()
            return {r[0] for r in rows}

        def _terms(con: sqlite3.Connection) -> set:
            rows = con.execute(
                "SELECT DISTINCT matched_term FROM keyword_alerts WHERE matched_term IS NOT NULL"
            ).fetchall()
            return {r[0] for r in rows}

        def _critical_count(con: sqlite3.Connection) -> int:
            return con.execute(
                "SELECT COUNT(*) FROM keyword_alerts WHERE severity = 'CRITICAL'"
            ).fetchone()[0]

        cats_a = _categories(self._con_a)
        cats_b = _categories(self._con_b)
        terms_a = _terms(self._con_a)
        terms_b = _terms(self._con_b)

        shared_cats = sorted(cats_a & cats_b)
        shared_terms = sorted(terms_a & terms_b)

        # critical_in_both: total CRITICAL alerts that exist in BOTH databases
        crit_a = _critical_count(self._con_a)
        crit_b = _critical_count(self._con_b)
        critical_in_both = min(crit_a, crit_b)

        return {
            "shared_alert_categories": shared_cats,
            "shared_matched_terms": shared_terms,
            "critical_in_both": critical_in_both,
        }

    # ------------------------------------------------------------------
    # compare_timeline_overlap
    # ------------------------------------------------------------------

    def compare_timeline_overlap(self) -> dict:
        """Find time range overlap between the two cases using timeline_events.

        Returns:
            {
                "case_a_range": {"start": str, "end": str},
                "case_b_range": {"start": str, "end": str},
                "overlap_exists": bool,
                "overlap_start": str or None,
                "overlap_end": str or None,
                "overlap_duration_hours": float or None
            }
        """
        def _range(con: sqlite3.Connection):
            row = con.execute(
                "SELECT MIN(timestamp_epoch), MAX(timestamp_epoch), "
                "MIN(timestamp_utc), MAX(timestamp_utc) "
                "FROM timeline_events WHERE timestamp_epoch IS NOT NULL"
            ).fetchone()
            if row is None or row[0] is None:
                return None, None, None, None
            return row[0], row[1], row[2], row[3]

        min_epoch_a, max_epoch_a, min_utc_a, max_utc_a = _range(self._con_a)
        min_epoch_b, max_epoch_b, min_utc_b, max_utc_b = _range(self._con_b)

        case_a_range = {"start": min_utc_a or "", "end": max_utc_a or ""}
        case_b_range = {"start": min_utc_b or "", "end": max_utc_b or ""}

        # Determine overlap
        if any(v is None for v in [min_epoch_a, max_epoch_a, min_epoch_b, max_epoch_b]):
            return {
                "case_a_range": case_a_range,
                "case_b_range": case_b_range,
                "overlap_exists": False,
                "overlap_start": None,
                "overlap_end": None,
                "overlap_duration_hours": None,
            }

        overlap_start_epoch = max(min_epoch_a, min_epoch_b)
        overlap_end_epoch = min(max_epoch_a, max_epoch_b)

        if overlap_start_epoch > overlap_end_epoch:
            return {
                "case_a_range": case_a_range,
                "case_b_range": case_b_range,
                "overlap_exists": False,
                "overlap_start": None,
                "overlap_end": None,
                "overlap_duration_hours": None,
            }

        # Convert epochs back to UTC strings
        def _epoch_to_utc(epoch: float) -> str:
            return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )

        overlap_duration_hours = (overlap_end_epoch - overlap_start_epoch) / 3600.0

        return {
            "case_a_range": case_a_range,
            "case_b_range": case_b_range,
            "overlap_exists": True,
            "overlap_start": _epoch_to_utc(overlap_start_epoch),
            "overlap_end": _epoch_to_utc(overlap_end_epoch),
            "overlap_duration_hours": round(overlap_duration_hours, 4),
        }

    # ------------------------------------------------------------------
    # full_comparison_report
    # ------------------------------------------------------------------

    def full_comparison_report(self) -> dict:
        """Call all four comparison methods and merge into a single report dict.

        Includes metadata: compared_at, db_path_a, db_path_b.
        """
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        report = {
            "metadata": {
                "compared_at": now_utc,
                "db_path_a": self.db_path_a,
                "db_path_b": self.db_path_b,
            },
            "messages": self.compare_messages(),
            "locations": self.compare_locations(),
            "alerts": self.compare_alerts(),
            "timeline": self.compare_timeline_overlap(),
        }
        return report


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def compare_two_cases(path_a: "str | Path", path_b: "str | Path") -> dict:
    """Convenience wrapper: open two databases, run full comparison, close, return report."""
    with CaseComparison(path_a, path_b) as cc:
        return cc.full_comparison_report()
