"""
Universal Keyword & Pattern Search Engine Across All Decrypted Evidence
=======================================================================
Enables forensic examiners and scientific officers to perform deep, multi-table,
multi-database searches for phone numbers, suspect names, crypto addresses,
and keywords across every decrypted SQLite database and artifact simultaneously.
"""

from dataclasses import asdict, dataclass
import csv
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SearchHit:
    db_path: str
    db_name: str
    table_name: str
    column_name: str
    row_data: Dict[str, Any]
    matched_value: str
    match_context: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _extract_context(text: str, match_term: str, context_len: int = 50) -> str:
    """Extracts a snippet of text surrounding the match term."""
    idx = text.lower().find(match_term.lower())
    if idx == -1:
        return text[: context_len * 2]
    start = max(0, idx - context_len)
    end = min(len(text), idx + len(match_term) + context_len)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end]}{suffix}"


def search_sqlite_files(
    directory: str | Path,
    keyword: str,
    case_insensitive: bool = True,
    max_results: int = 2000,
) -> List[SearchHit]:
    """
    Recursively scans directory for SQLite databases and searches all text columns
    across all tables for the given keyword.
    """
    root_dir = Path(directory).resolve()
    hits: List[SearchHit] = []
    if not root_dir.exists() or not keyword.strip():
        return hits

    search_term = keyword.lower() if case_insensitive else keyword

    db_extensions = {".sqlite", ".db", ".sqlite3", ".sqlitedb"}
    db_files = [f for f in root_dir.rglob("*") if f.is_file() and f.suffix.lower() in db_extensions]

    for db_path in sorted(db_files):
        if len(hits) >= max_results:
            break

        rel_path = str(db_path.relative_to(root_dir))
        try:
            con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [r[0] for r in cur.fetchall()]

            for tbl in tables:
                if len(hits) >= max_results:
                    break
                try:
                    cur.execute(f'SELECT * FROM "{tbl}" LIMIT 1000')
                    cols = [d[0] for d in cur.description] if cur.description else []
                    if not cols:
                        continue
                    rows = cur.fetchall()

                    for row in rows:
                        row_dict = {cols[i]: row[i] for i in range(len(cols))}
                        for col_idx, val in enumerate(row):
                            if val is None:
                                continue
                            val_str = str(val)
                            check_str = val_str.lower() if case_insensitive else val_str
                            if search_term in check_str:
                                hits.append(
                                    SearchHit(
                                        db_path=rel_path,
                                        db_name=db_path.name,
                                        table_name=tbl,
                                        column_name=cols[col_idx],
                                        row_data={k: str(v) if v is not None else None for k, v in row_dict.items()},
                                        matched_value=val_str,
                                        match_context=_extract_context(val_str, keyword),
                                    )
                                )
                                if len(hits) >= max_results:
                                    break
                except Exception:
                    continue
            con.close()
        except Exception:
            continue

    return hits


def search_with_patterns(
    directory: str | Path,
    patterns: List[str],
    case_insensitive: bool = True,
) -> Dict[str, List[SearchHit]]:
    """Searches across all databases for a list of target keywords/patterns."""
    results: Dict[str, List[SearchHit]] = {}
    for p in patterns:
        results[p] = search_sqlite_files(directory, p, case_insensitive=case_insensitive)
    return results


def search_by_date_range(
    directory: str | Path,
    start_date: datetime,
    end_date: datetime,
    max_results: int = 2000,
) -> List[SearchHit]:
    """
    Searches databases for dates / timestamps falling within [start_date, end_date].
    Handles both Unix timestamps (seconds & milliseconds) and ISO string representations.
    """
    root_dir = Path(directory).resolve()
    hits: List[SearchHit] = []
    if not root_dir.exists():
        return hits

    start_ts = start_date.timestamp()
    end_ts = end_date.timestamp()
    date_indicators = ("date", "time", "timestamp", "created", "modified", "sent", "received")

    db_extensions = {".sqlite", ".db", ".sqlite3"}
    db_files = [f for f in root_dir.rglob("*") if f.is_file() and f.suffix.lower() in db_extensions]

    for db_path in sorted(db_files):
        if len(hits) >= max_results:
            break
        rel_path = str(db_path.relative_to(root_dir))
        try:
            con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [r[0] for r in cur.fetchall()]

            for tbl in tables:
                if len(hits) >= max_results:
                    break
                try:
                    cur.execute(f'SELECT * FROM "{tbl}" LIMIT 1000')
                    cols = [d[0] for d in cur.description] if cur.description else []
                    rows = cur.fetchall()

                    for row in rows:
                        row_dict = {cols[i]: row[i] for i in range(len(cols))}
                        for col_idx, col_name in enumerate(cols):
                            val = row[col_idx]
                            if val is None:
                                continue
                            
                            is_date_col = any(ind in col_name.lower() for ind in date_indicators)
                            matched = False
                            dt_str = ""

                            # Check numeric timestamp
                            if isinstance(val, (int, float)):
                                num_val = float(val)
                                # Could be in milliseconds (e.g. 13-digit timestamp)
                                if num_val > 10000000000:
                                    num_val /= 1000.0
                                # Could be Cocoa CoreData timestamp (seconds since 2001-01-01)
                                if is_date_col and num_val < 1000000000:
                                    num_val += 978307200.0
                                
                                if start_ts <= num_val <= end_ts:
                                    matched = True
                                    try:
                                        dt_str = datetime.fromtimestamp(num_val, tz=timezone.utc).isoformat()
                                    except Exception:
                                        dt_str = str(val)

                            # Check ISO string timestamp
                            elif isinstance(val, str) and is_date_col:
                                try:
                                    cleaned = val.replace("Z", "+00:00")
                                    parsed_dt = datetime.fromisoformat(cleaned)
                                    parsed_ts = parsed_dt.timestamp()
                                    if start_ts <= parsed_ts <= end_ts:
                                        matched = True
                                        dt_str = val
                                except Exception:
                                    pass

                            if matched:
                                hits.append(
                                    SearchHit(
                                        db_path=rel_path,
                                        db_name=db_path.name,
                                        table_name=tbl,
                                        column_name=col_name,
                                        row_data={k: str(v) if v is not None else None for k, v in row_dict.items()},
                                        matched_value=str(val),
                                        match_context=f"Timestamp: {dt_str} ({col_name})",
                                    )
                                )
                                if len(hits) >= max_results:
                                    break
                except Exception:
                    continue
            con.close()
        except Exception:
            continue

    return hits


def export_search_results(
    hits: List[SearchHit],
    output_path: str | Path,
    fmt: str = "json",
) -> Path:
    """Exports search results to JSON or CSV."""
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    if fmt.lower() == "csv":
        with open(out_p, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Database", "Table", "Column", "Matched Value", "Context", "Relative Path"])
            for h in hits:
                writer.writerow([h.db_name, h.table_name, h.column_name, h.matched_value, h.match_context, h.db_path])
    else:
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump([h.to_dict() for h in hits], f, indent=2)

    return out_p


def generate_search_report_html(
    hits: List[SearchHit],
    keyword: str,
    output_path: str | Path,
) -> str:
    """Generates an interactive, standalone HTML report for keyword search hits."""
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    rows_html = []
    for h in hits:
        esc_val = html.escape(h.matched_value)
        # Highlight match in context
        esc_ctx = html.escape(h.match_context)
        if keyword:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            esc_ctx = pattern.sub(lambda m: f"<mark>{m.group(0)}</mark>", esc_ctx)

        rows_html.append(
            f"<tr>"
            f"<td><strong>{html.escape(h.db_name)}</strong><br><small style='color:#8b949e'>{html.escape(h.db_path)}</small></td>"
            f"<td><code>{html.escape(h.table_name)}</code></td>"
            f"<td><code>{html.escape(h.column_name)}</code></td>"
            f"<td>{esc_ctx}</td>"
            f"</tr>"
        )

    rows_joined = "\n".join(rows_html) if rows_html else "<tr><td colspan='4' style='text-align:center;padding:24px;color:#8b949e;'>No matches found.</td></tr>"

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Search Results: {html.escape(keyword)}</title>
    <style>
        body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #ffffff; margin-bottom: 4px; }}
        .meta {{ color: #8b949e; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 10px 14px; border-bottom: 1px solid #30363d; text-align: left; font-size: 0.9em; }}
        th {{ background: #21262d; color: #ffffff; }}
        mark {{ background: #e3b341; color: #000; font-weight: bold; border-radius: 2px; padding: 1px 4px; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Forensic Evidence Search Report</h1>
        <div class="meta">Target Keyword: <strong>{html.escape(keyword)}</strong> | Total Hits: <strong>{len(hits)}</strong> | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        <table>
            <thead>
                <tr>
                    <th>Database</th>
                    <th>Table</th>
                    <th>Column</th>
                    <th>Match Preview</th>
                </tr>
            </thead>
            <tbody>
                {rows_joined}
            </tbody>
        </table>
    </div>
</body>
</html>"""

    with open(out_p, "w", encoding="utf-8") as f:
        f.write(content)

    return content
