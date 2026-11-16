"""
Export Formats
==============
Three export functions that read from a consolidated_case_evidence.sqlite
database (schema defined in consolidated_db.py) and produce:
  - XLSX (multi-sheet) or CSV-in-ZIP fallback
  - JSONL (one line per row, all tables)
  - GeoJSON FeatureCollection (locations table)
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Tables to export (in this order)
EXPORT_TABLES = [
    "messages",
    "timeline_events",
    "locations",
    "keyword_alerts",
    "audit_trail",
    "decrypted_databases",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_openpyxl() -> bool:
    """Return True if openpyxl is importable."""
    try:
        import openpyxl  # noqa: F401
        return True
    except ImportError:
        return False


def _table_columns(cur: sqlite3.Cursor, table: str) -> List[str]:
    cur.execute(f"PRAGMA table_info(\"{table}\")")
    return [row[1] for row in cur.fetchall()]


def _iter_rows(cur: sqlite3.Cursor, table: str):
    """Yield dicts for every row in *table*. Skip missing tables silently."""
    try:
        cols = _table_columns(cur, table)
        cur.execute(f'SELECT * FROM "{table}"')
        for row in cur:
            yield dict(zip(cols, row))
    except sqlite3.OperationalError:
        return


def _row_count(cur: sqlite3.Cursor, table: str) -> int:
    try:
        cur.execute(f'SELECT COUNT(*) FROM "{table}"')
        result = cur.fetchone()
        return result[0] if result else 0
    except sqlite3.OperationalError:
        return 0


# ---------------------------------------------------------------------------
# 1. export_to_xlsx
# ---------------------------------------------------------------------------

def export_to_xlsx(db_path: str | Path, output_path: str | Path) -> Dict[str, Any]:
    """
    Export all tables to an XLSX file (one sheet per table).
    If openpyxl is not installed, fall back to a ZIP archive of CSV files.

    Returns:
        {
            "path": str,
            "format": "xlsx" | "csv_zip",
            "row_counts": {table: int},
        }
    """
    db_path = Path(db_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(str(db_path))
    cur = con.cursor()

    row_counts: Dict[str, int] = {}

    if _check_openpyxl():
        import openpyxl
        from openpyxl.styles import Font

        wb = openpyxl.Workbook()
        # Remove default sheet
        if wb.active is not None and wb.active.title == "Sheet":
            wb.remove(wb.active)

        for table in EXPORT_TABLES:
            cols = _table_columns(cur, table)
            if not cols:
                row_counts[table] = 0
                continue

            ws = wb.create_sheet(title=table[:31])  # Excel sheet name limit

            # Bold header row
            bold = Font(bold=True)
            for col_idx, col_name in enumerate(cols, start=1):
                cell = ws.cell(row=1, column=col_idx, value=col_name)
                cell.font = bold

            count = 0
            for row_dict in _iter_rows(cur, table):
                count += 1
                ws.append([row_dict.get(c) for c in cols])

            row_counts[table] = count

        con.close()

        # Ensure .xlsx extension
        if output_path.suffix.lower() != ".xlsx":
            output_path = output_path.with_suffix(".xlsx")
        wb.save(str(output_path))

        return {
            "path": str(output_path),
            "format": "xlsx",
            "row_counts": row_counts,
        }

    else:
        # Fallback: ZIP of CSVs (stdlib only)
        if output_path.suffix.lower() != ".zip":
            output_path = output_path.with_suffix(".zip")

        with zipfile.ZipFile(str(output_path), "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for table in EXPORT_TABLES:
                cols = _table_columns(cur, table)
                if not cols:
                    row_counts[table] = 0
                    continue

                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(cols)

                count = 0
                for row_dict in _iter_rows(cur, table):
                    count += 1
                    writer.writerow([row_dict.get(c) for c in cols])

                row_counts[table] = count
                zf.writestr(f"{table}.csv", buf.getvalue())

        con.close()

        return {
            "path": str(output_path),
            "format": "csv_zip",
            "row_counts": row_counts,
        }


# ---------------------------------------------------------------------------
# 2. export_to_jsonl
# ---------------------------------------------------------------------------

def export_to_jsonl(db_path: str | Path, output_path: str | Path) -> Dict[str, Any]:
    """
    Stream every row from every table as one JSON object per line.
    Format: {"table": "<name>", "record": {<column>: <value>, ...}}

    Returns:
        {
            "path": str,
            "total_lines": int,
            "tables": [str],
        }
    """
    db_path = Path(db_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(str(db_path))
    cur = con.cursor()

    total_lines = 0
    tables_written: List[str] = []

    with output_path.open("w", encoding="utf-8") as fh:
        for table in EXPORT_TABLES:
            cols = _table_columns(cur, table)
            if not cols:
                continue

            table_had_rows = False
            for row_dict in _iter_rows(cur, table):
                line = json.dumps({"table": table, "record": row_dict}, default=str)
                fh.write(line + "\n")
                total_lines += 1
                table_had_rows = True

            if table_had_rows:
                tables_written.append(table)

    con.close()

    return {
        "path": str(output_path),
        "total_lines": total_lines,
        "tables": tables_written,
    }


# ---------------------------------------------------------------------------
# 3. export_to_geojson
# ---------------------------------------------------------------------------

def export_to_geojson(db_path: str | Path, output_path: str | Path) -> Dict[str, Any]:
    """
    Read the locations table and produce an RFC 7946 GeoJSON FeatureCollection.

    Each row becomes a Feature with:
      geometry: Point([longitude, latitude, altitude])
      properties: {file_name, timestamp_utc, camera_make, camera_model}

    Returns:
        {
            "path": str,
            "feature_count": int,
            "bounding_box": [minLon, minLat, maxLon, maxLat] or None,
        }
    """
    db_path = Path(db_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(str(db_path))
    cur = con.cursor()

    features: List[Dict[str, Any]] = []
    lons: List[float] = []
    lats: List[float] = []

    for row in _iter_rows(cur, "locations"):
        lat = row.get("latitude")
        lon = row.get("longitude")
        alt = row.get("altitude")

        # Skip rows without valid coordinates
        if lat is None or lon is None:
            continue

        try:
            lat = float(lat)
            lon = float(lon)
        except (TypeError, ValueError):
            continue

        coordinates: List = [lon, lat]
        if alt is not None:
            try:
                coordinates.append(float(alt))
            except (TypeError, ValueError):
                pass

        feature: Dict[str, Any] = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": coordinates,
            },
            "properties": {
                "file_name": row.get("file_name"),
                "timestamp_utc": row.get("timestamp_utc"),
                "camera_make": row.get("camera_make"),
                "camera_model": row.get("camera_model"),
            },
        }
        features.append(feature)
        lons.append(lon)
        lats.append(lat)

    con.close()

    collection: Dict[str, Any] = {
        "type": "FeatureCollection",
        "features": features,
    }

    bounding_box: Optional[List[float]] = None
    if lons and lats:
        bounding_box = [min(lons), min(lats), max(lons), max(lats)]
        collection["bbox"] = bounding_box

    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(collection, fh, indent=2, default=str)

    return {
        "path": str(output_path),
        "feature_count": len(features),
        "bounding_box": bounding_box,
    }
