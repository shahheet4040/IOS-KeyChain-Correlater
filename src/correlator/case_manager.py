"""
Multi-Case / Multi-Device Evidence Management System
====================================================
Allows forensic examiners to organize multiple cases, each containing
multiple devices.  Tracks analysis results, enables cross-device
searching, and generates consolidated case reports.
"""

import json
import shutil
import sqlite3
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class CaseManager:
    """Manages forensic cases, devices, and analysis results."""

    def __init__(self, workspace_dir: str | Path):
        self.workspace = Path(workspace_dir).resolve()
        self.cases_dir = self.workspace / "cases"
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    # ── Case Operations ─────────────────────────────────────────────

    def create_case(
        self,
        case_name: str,
        case_number: str,
        examiner: str,
        description: str = "",
    ) -> str:
        """
        Create a new forensic case.
        Returns case_id (UUID string).
        """
        case_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        case_dir = self.cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        meta = {
            "case_id": case_id,
            "case_name": case_name,
            "case_number": case_number,
            "examiner": examiner,
            "description": description,
            "created_at": now,
            "updated_at": now,
            "status": "active",
            "devices": [],
        }

        self._write_case_meta(case_id, meta)
        return case_id

    def list_cases(self) -> List[Dict[str, Any]]:
        """List all cases with summary info."""
        cases = []
        for d in sorted(self.cases_dir.iterdir()):
            if d.is_dir():
                meta_file = d / "case_meta.json"
                if meta_file.is_file():
                    meta = self._read_case_meta(d.name)
                    cases.append({
                        "case_id": meta["case_id"],
                        "case_name": meta["case_name"],
                        "case_number": meta["case_number"],
                        "examiner": meta["examiner"],
                        "status": meta["status"],
                        "created_at": meta["created_at"],
                        "device_count": len(meta.get("devices", [])),
                    })
        return cases

    def get_case(self, case_id: str) -> Dict[str, Any]:
        """Get full case metadata."""
        meta = self._read_case_meta(case_id)
        if meta is None:
            raise ValueError(f"Case not found: {case_id}")
        return meta

    def update_case_status(self, case_id: str, status: str) -> None:
        """Update case status (active, closed, archived)."""
        meta = self.get_case(case_id)
        meta["status"] = status
        meta["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._write_case_meta(case_id, meta)

    def delete_case(self, case_id: str) -> None:
        """Permanently delete a case and all its data."""
        case_dir = self.cases_dir / case_id
        if case_dir.is_dir():
            shutil.rmtree(case_dir, ignore_errors=True)

    # ── Device Operations ───────────────────────────────────────────

    def add_device(
        self,
        case_id: str,
        device_name: str,
        device_model: str,
        os_version: str,
        serial_number: str,
        source_type: str,
        source_path: str = "",
    ) -> str:
        """
        Add a device to a case.
        source_type: 'cellebrite', 'graykey', 'itunes', 'live_usb', 'manual'
        Returns device_id (UUID string).
        """
        meta = self.get_case(case_id)
        device_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        device_dir = self.cases_dir / case_id / "devices" / device_id
        device_dir.mkdir(parents=True, exist_ok=True)

        device_info = {
            "device_id": device_id,
            "device_name": device_name,
            "device_model": device_model,
            "os_version": os_version,
            "serial_number": serial_number,
            "source_type": source_type,
            "source_path": source_path,
            "added_at": now,
            "analysis_count": 0,
        }

        # Save device info
        with open(device_dir / "device_info.json", "w", encoding="utf-8") as f:
            json.dump(device_info, f, indent=2)

        meta["devices"].append(device_info)
        meta["updated_at"] = now
        self._write_case_meta(case_id, meta)

        return device_id

    def list_devices(self, case_id: str) -> List[Dict[str, Any]]:
        """List all devices in a case."""
        meta = self.get_case(case_id)
        return meta.get("devices", [])

    # ── Analysis Results ────────────────────────────────────────────

    def add_analysis_result(
        self,
        case_id: str,
        device_id: str,
        result_data: Dict[str, Any],
    ) -> str:
        """
        Store a pipeline analysis result for a device.
        Returns result_id.
        """
        result_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        device_dir = self.cases_dir / case_id / "devices" / device_id
        results_dir = device_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        result_entry = {
            "result_id": result_id,
            "timestamp": now,
            "data": result_data,
        }

        with open(results_dir / f"{result_id}.json", "w", encoding="utf-8") as f:
            json.dump(result_entry, f, indent=2, default=str)

        # Update device analysis count
        meta = self.get_case(case_id)
        for dev in meta.get("devices", []):
            if dev["device_id"] == device_id:
                dev["analysis_count"] = dev.get("analysis_count", 0) + 1
                break
        meta["updated_at"] = now
        self._write_case_meta(case_id, meta)

        return result_id

    def get_analysis_results(
        self,
        case_id: str,
        device_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get analysis results, optionally filtered by device_id.
        """
        results = []
        devices_dir = self.cases_dir / case_id / "devices"
        if not devices_dir.is_dir():
            return results

        for dev_dir in devices_dir.iterdir():
            if not dev_dir.is_dir():
                continue
            if device_id and dev_dir.name != device_id:
                continue

            results_dir = dev_dir / "results"
            if results_dir.is_dir():
                for f in sorted(results_dir.glob("*.json")):
                    with open(f, "r", encoding="utf-8") as fh:
                        entry = json.load(fh)
                        entry["device_id"] = dev_dir.name
                        results.append(entry)

        return results

    # ── Cross-Device Search ─────────────────────────────────────────

    def cross_device_search(
        self,
        case_id: str,
        keyword: str,
    ) -> List[Dict[str, Any]]:
        """
        Search across all devices' decrypted databases for a keyword.
        Returns list of hit dicts with device_id, db_name, table, column, matched_value.
        """
        hits: List[Dict[str, Any]] = []
        devices_dir = self.cases_dir / case_id / "devices"
        if not devices_dir.is_dir():
            return hits

        keyword_lower = keyword.lower()

        for dev_dir in devices_dir.iterdir():
            if not dev_dir.is_dir():
                continue
            device_id = dev_dir.name

            # Search all SQLite files under the device directory
            for db_file in dev_dir.rglob("*"):
                if not db_file.is_file():
                    continue
                if db_file.suffix.lower() not in (".sqlite", ".db", ".sqlite3"):
                    continue

                try:
                    con = sqlite3.connect(f"file:{db_file.resolve().as_posix()}?mode=ro", uri=True)
                    cur = con.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r[0] for r in cur.fetchall()]

                    for table in tables:
                        try:
                            cur.execute(f'SELECT * FROM "{table}" LIMIT 500')
                            col_names = [d[0] for d in cur.description]
                            for row in cur.fetchall():
                                for col_idx, cell in enumerate(row):
                                    if cell is not None and keyword_lower in str(cell).lower():
                                        hits.append({
                                            "device_id": device_id,
                                            "db_path": str(db_file.relative_to(dev_dir)),
                                            "db_name": db_file.name,
                                            "table": table,
                                            "column": col_names[col_idx],
                                            "matched_value": str(cell),
                                            "row": {col_names[i]: str(v) if v is not None else None for i, v in enumerate(row)},
                                        })
                        except Exception:
                            continue

                    con.close()
                except Exception:
                    continue

        return hits

    # ── Case Report ─────────────────────────────────────────────────

    def generate_case_report(self, case_id: str) -> Dict[str, Any]:
        """
        Generate a consolidated report summarizing the entire case
        across all devices and their analysis results.
        """
        meta = self.get_case(case_id)
        all_results = self.get_analysis_results(case_id)

        total_dbs = 0
        total_decrypted = 0
        total_plain = 0
        total_locked = 0

        device_summaries = []
        for dev in meta.get("devices", []):
            dev_results = [r for r in all_results if r.get("device_id") == dev["device_id"]]
            dev_dbs = 0
            dev_decrypted = 0
            dev_plain = 0
            dev_locked = 0

            for r in dev_results:
                data = r.get("data", {})
                dev_dbs += data.get("total_databases", 0)
                dev_decrypted += data.get("decrypted_count", 0)
                dev_plain += data.get("plain_count", 0)
                dev_locked += data.get("locked_count", 0)

            total_dbs += dev_dbs
            total_decrypted += dev_decrypted
            total_plain += dev_plain
            total_locked += dev_locked

            device_summaries.append({
                **dev,
                "total_databases": dev_dbs,
                "decrypted_count": dev_decrypted,
                "plain_count": dev_plain,
                "locked_count": dev_locked,
                "analysis_runs": len(dev_results),
            })

        return {
            "case_id": meta["case_id"],
            "case_name": meta["case_name"],
            "case_number": meta["case_number"],
            "examiner": meta["examiner"],
            "status": meta["status"],
            "created_at": meta["created_at"],
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_devices": len(meta.get("devices", [])),
                "total_databases": total_dbs,
                "total_decrypted": total_decrypted,
                "total_plain": total_plain,
                "total_locked": total_locked,
            },
            "devices": device_summaries,
        }

    # ── Export ───────────────────────────────────────────────────────

    def export_case(self, case_id: str, export_path: str | Path) -> Path:
        """Export entire case folder as a ZIP archive."""
        case_dir = self.cases_dir / case_id
        if not case_dir.is_dir():
            raise ValueError(f"Case not found: {case_id}")

        export_p = Path(export_path).resolve()
        export_p.parent.mkdir(parents=True, exist_ok=True)

        # Remove .zip extension if provided (shutil adds it)
        base_name = str(export_p).removesuffix(".zip")
        result_path = shutil.make_archive(base_name, "zip", case_dir)
        return Path(result_path)

    # ── Internal helpers ────────────────────────────────────────────

    def _read_case_meta(self, case_id: str) -> Optional[Dict[str, Any]]:
        meta_file = self.cases_dir / case_id / "case_meta.json"
        if not meta_file.is_file():
            return None
        with open(meta_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write_case_meta(self, case_id: str, meta: Dict[str, Any]) -> None:
        meta_file = self.cases_dir / case_id / "case_meta.json"
        meta_file.parent.mkdir(parents=True, exist_ok=True)
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
