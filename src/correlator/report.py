from datetime import datetime, timezone
import html
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from correlator.engine import CorrelationResult
from correlator.evaluate import evaluate_report
from correlator.wal import inspect_database_wal


def _read_sqlite_evidence(export_dir: Path) -> List[Dict]:
    """
    Scans export_dir recursively for *.sqlite / *.db files.
    For each readable file, reads all tables (up to 500 rows each).
    Returns a list of dicts: {name, relpath, tables: [{name, columns, rows}]}
    """
    evidence = []
    if not export_dir or not export_dir.is_dir():
        return evidence

    db_files = list(export_dir.rglob("*.sqlite")) + list(export_dir.rglob("*.db"))
    for db_path in sorted(db_files):
        rel = str(db_path.relative_to(export_dir))
        tables_data = []
        try:
            con = sqlite3.connect(str(db_path))
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
            table_names = [r[0] for r in cur.fetchall()]
            for tname in table_names:
                try:
                    cur.execute(f"SELECT * FROM [{tname}] LIMIT 500;")
                    rows_raw = cur.fetchall()
                    if rows_raw:
                        columns = list(rows_raw[0].keys())
                        rows = [list(r) for r in rows_raw]
                    else:
                        cur.execute(f"PRAGMA table_info([{tname}]);")
                        cols_info = cur.fetchall()
                        columns = [c[1] for c in cols_info]
                        rows = []
                    tables_data.append({"name": tname, "columns": columns, "rows": rows})
                except Exception:
                    tables_data.append({"name": tname, "columns": [], "rows": [], "error": "Could not read table"})
            con.close()
        except Exception as e:
            tables_data.append({"name": "__error__", "columns": [], "rows": [], "error": str(e)})

        # Carve deleted rows & slack space records
        try:
            from correlator.carver import carve_sqlite_database
            carved_items = carve_sqlite_database(db_path)
            if carved_items:
                c_cols = ["Status", "Record ID", "Source Type", "Page/Offset", "Confidence", "Carved Content Preview"]
                c_rows = []
                for c in carved_items:
                    c_rows.append([
                        "🚨 DELETED / CARVED",
                        c.record_id,
                        c.source_type,
                        f"Page {c.page_num} (off {c.offset_in_page})",
                        f"{int(c.confidence * 100)}%",
                        c.raw_text,
                    ])
                tables_data.insert(0, {
                    "name": "🚨 RECOVERED_DELETED_DATA",
                    "columns": c_cols,
                    "rows": c_rows,
                })
        except Exception:
            pass

        if tables_data:
            evidence.append({
                "name": db_path.name,
                "relpath": rel,
                "tables": tables_data,
            })
    return evidence


def generate_json_report(
    results: List[CorrelationResult],
    extraction_path: str | Path,
    keychain_path: str | Path,
    out_file: Optional[str | Path] = None,
    provenance: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Builds a comprehensive structured JSON report enriched with WAL analysis and metadata.
    """
    extraction_root = Path(extraction_path).resolve()

    decrypted_count = sum(1 for r in results if r.status == "decrypted")
    plain_count = sum(1 for r in results if r.status == "plain")
    locked_count = sum(1 for r in results if r.status == "not_decrypted")

    db_entries = []
    for r in results:
        entry = r.to_dict()
        db_full_path = extraction_root / r.relpath
        wal_res = inspect_database_wal(db_full_path)
        entry["wal_info"] = wal_res.to_dict() if wal_res else None
        db_entries.append(entry)

    report_data = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "extraction_root": str(extraction_root),
            "keychain_path": str(Path(keychain_path).resolve()),
            "total_databases": len(results),
            "decrypted_count": decrypted_count,
            "plain_count": plain_count,
            "locked_count": locked_count,
        },
        "databases": db_entries,
        "provenance_map": provenance or [],
    }

    if out_file:
        p = Path(out_file).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    return report_data


def generate_html_report(
    results: List[CorrelationResult],
    extraction_path: str | Path,
    keychain_path: str | Path,
    out_file: Optional[str | Path] = None,
    export_dir: Optional[str | Path] = None,
    provenance: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Generates a standalone, self-contained forensic HTML report with embedded CSS.
    If export_dir is given, embeds an interactive Evidence Explorer showing all
    decrypted database rows directly inside the HTML — no external tools needed.
    """
    decrypted_count = sum(1 for r in results if r.status == "decrypted")
    plain_count = sum(1 for r in results if r.status == "plain")
    locked_count = sum(1 for r in results if r.status == "not_decrypted")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # If provenance is not explicitly passed, construct default from results
    if not provenance:
        from correlator.provenance import build_default_provenance_map
        tracker = build_default_provenance_map(results, extraction_path, keychain_path, export_dir=export_dir)
        provenance = tracker.get_timeline()

    provenance_rows = []
    for s in provenance:
        status_badge = '<span class="badge badge-decrypted">SUCCESS</span>' if s.get("status") == "success" else '<span class="badge badge-locked">WARNING</span>'
        provenance_rows.append(f"""
            <tr>
                <td><strong>#{s.get('step_number')}</strong></td>
                <td><span style="color:#58a6ff;font-weight:600;">{html.escape(str(s.get('phase')))}</span></td>
                <td><code>{html.escape(str(s.get('target', '-')))}</code></td>
                <td>{html.escape(str(s.get('action')))}</td>
                <td style="font-size:0.85em;color:#8b949e;">{s.get('timestamp')}</td>
                <td>{status_badge}</td>
            </tr>
        """)
    prov_tbody = "\\n".join(provenance_rows)

    # Load evidence data from exported databases
    evidence_list = _read_sqlite_evidence(Path(export_dir) if export_dir else None)
    evidence_json = json.dumps(evidence_list, default=str)

    table_rows = []
    for r in results:
        status_class = {
            "decrypted": "badge-decrypted",
            "plain": "badge-plain",
            "not_decrypted": "badge-locked",
        }.get(r.status, "badge-locked")

        status_text = {
            "decrypted": "DECRYPTED",
            "plain": "PLAIN",
            "not_decrypted": "LOCKED",
        }.get(r.status, r.status.upper())

        bundle_text = r.bundle_id or (f"UUID: {r.container_uuid}" if r.container_uuid else "N/A")
        fp_text = f"<code>{r.key_fingerprint}</code>" if r.key_fingerprint else "&mdash;"
        prof_text = r.profile or "&mdash;"
        wal_text = "Yes" if r.has_wal else "No"
        sha_text = f"<span class='hash' title='{r.sha256}'>{r.sha256[:16]}...</span>" if r.sha256 else "&mdash;"

        row_html = f"""
        <tr>
            <td><span class="badge {status_class}">{status_text}</span></td>
            <td><strong>{html.escape(r.name)}</strong></td>
            <td><code>{html.escape(r.relpath)}</code></td>
            <td>{html.escape(bundle_text)}</td>
            <td>{fp_text}</td>
            <td>{html.escape(prof_text)}</td>
            <td>{wal_text}</td>
            <td>{sha_text}</td>
        </tr>
        """
        table_rows.append(row_html.strip())

    rows_joined = "\n".join(table_rows)

    geo_banner_html = ""
    if out_file:
        out_p = Path(out_file).resolve().parent
        map_p = out_p / "route_map.html"
        geojson_p = out_p / "route.geojson"
        kml_p = out_p / "route.kml"

        if map_p.exists() or geojson_p.exists():
            geo_banner_html = f"""
        <div style="margin-top:32px; background:#161b22; border:1px solid #30363d; border-radius:10px; padding:20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px;">
                <div>
                    <h2 style="color:#ffffff; margin:0 0 6px 0; font-size:1.25em;">🌍 Forensic Geospatial &amp; Movement Timeline Map</h2>
                    <p style="color:#8b949e; margin:0; font-size:0.9em;">Interactive GPS route reconstructed from photo EXIF tags, Apple Significant Locations, and messaging shares.</p>
                </div>
                <div style="display:flex; gap:8px;">
                    <a href="{html.escape(map_p.name)}" target="_blank" style="background:#238636; color:#ffffff; text-decoration:none; padding:8px 16px; border-radius:6px; font-weight:bold; font-size:0.9em;">🌐 Open Interactive Map</a>
                    <a href="{html.escape(kml_p.name)}" download style="background:#21262d; border:1px solid #30363d; color:#c9d1d9; text-decoration:none; padding:8px 12px; border-radius:6px; font-size:0.85em;">📥 Google Earth KML</a>
                    <a href="{html.escape(geojson_p.name)}" download style="background:#21262d; border:1px solid #30363d; color:#c9d1d9; text-decoration:none; padding:8px 12px; border-radius:6px; font-size:0.85em;">📥 GeoJSON</a>
                </div>
            </div>
        </div>
            """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iOS Keychain Correlator Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-bright: #ffffff;
            --accent: #58a6ff;
            --success: #238636;
            --warning: #d29922;
            --danger: #da3633;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: var(--text-bright);
            margin-bottom: 4px;
        }}
        .meta {{
            color: #8b949e;
            font-size: 0.9em;
            margin-bottom: 24px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }}
        .card-title {{
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #8b949e;
            margin-bottom: 8px;
        }}
        .card-value {{
            font-size: 2em;
            font-weight: bold;
            color: var(--text-bright);
        }}
        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95em;
            text-align: left;
        }}
        th, td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: #21262d;
            color: var(--text-bright);
            font-weight: 600;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        code {{
            background: #21262d;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            letter-spacing: 0.5px;
        }}
        .badge-decrypted {{
            background: #238636;
            color: #ffffff;
        }}
        .badge-plain {{
            background: #1f6feb;
            color: #ffffff;
        }}
        .badge-locked {{
            background: #da3633;
            color: #ffffff;
        }}
        .hash {{
            font-family: monospace;
            color: #8b949e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>iOS Keychain Correlator Forensic Report</h1>
        <div class="meta">
            Extraction: <code>{html.escape(str(extraction_path))}</code><br>
            Keychain: <code>{html.escape(str(keychain_path))}</code><br>
            Generated: {timestamp}
        </div>

        <div class="stats-grid">
            <div class="card">
                <div class="card-title">Total Databases</div>
                <div class="card-value">{len(results)}</div>
            </div>
            <div class="card">
                <div class="card-title">Decrypted</div>
                <div class="card-value" style="color: #3fb950;">{decrypted_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Plain SQLite</div>
                <div class="card-value" style="color: #58a6ff;">{plain_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Locked</div>
                <div class="card-value" style="color: #f85149;">{locked_count}</div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Database</th>
                        <th>Path</th>
                        <th>Container / Bundle ID</th>
                        <th>Key Fingerprint</th>
                        <th>Profile</th>
                        <th>WAL</th>
                        <th>SHA-256</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_joined}
                </tbody>
            </table>
        </div>

        {geo_banner_html}

        <!-- ═══════════════════════════════════════════════════════
             FORENSIC PROVENANCE & STEP-BY-STEP PROCESS MAP
             ═══════════════════════════════════════════════════════ -->
        <div style="margin-top:40px;">
            <h2 style="color:#ffffff;border-bottom:1px solid #30363d;padding-bottom:8px;">
                🗺️ Forensic Execution &amp; Provenance Process Map
            </h2>
            <p style="color:#8b949e;font-size:0.9em;margin-bottom:16px;">
                Sequential chain-of-custody audit trail showing every automated step executed from initial acquisition to key derivation, cryptographic profile matching, and evidence export.
            </p>
            <div style="display:flex;gap:8px;overflow-x:auto;padding-bottom:12px;margin-bottom:16px;">
                <div style="background:#161b22;border:1px solid #30363d;padding:8px 12px;border-radius:6px;min-width:130px;text-align:center;">
                    <div style="font-size:0.75em;color:#8b949e;">Phase 1</div>
                    <div style="font-weight:600;font-size:0.85em;color:#58a6ff;">Triage &amp; Discovery</div>
                </div>
                <div style="display:flex;align-items:center;color:#8b949e;">➔</div>
                <div style="background:#161b22;border:1px solid #30363d;padding:8px 12px;border-radius:6px;min-width:130px;text-align:center;">
                    <div style="font-size:0.75em;color:#8b949e;">Phase 2</div>
                    <div style="font-weight:600;font-size:0.85em;color:#58a6ff;">SHA-256 Baseline</div>
                </div>
                <div style="display:flex;align-items:center;color:#8b949e;">➔</div>
                <div style="background:#161b22;border:1px solid #30363d;padding:8px 12px;border-radius:6px;min-width:130px;text-align:center;">
                    <div style="font-size:0.75em;color:#8b949e;">Phase 3</div>
                    <div style="font-weight:600;font-size:0.85em;color:#58a6ff;">Keychain Ingestion</div>
                </div>
                <div style="display:flex;align-items:center;color:#8b949e;">➔</div>
                <div style="background:#161b22;border:1px solid #30363d;padding:8px 12px;border-radius:6px;min-width:130px;text-align:center;">
                    <div style="font-size:0.75em;color:#8b949e;">Phase 4</div>
                    <div style="font-weight:600;font-size:0.85em;color:#3fb950;">Cryptographic Match</div>
                </div>
                <div style="display:flex;align-items:center;color:#8b949e;">➔</div>
                <div style="background:#161b22;border:1px solid #30363d;padding:8px 12px;border-radius:6px;min-width:130px;text-align:center;">
                    <div style="font-size:0.75em;color:#8b949e;">Phase 5</div>
                    <div style="font-weight:600;font-size:0.85em;color:#3fb950;">WAL Merge &amp; Decrypt</div>
                </div>
                <div style="display:flex;align-items:center;color:#8b949e;">➔</div>
                <div style="background:#161b22;border:1px solid #30363d;padding:8px 12px;border-radius:6px;min-width:130px;text-align:center;">
                    <div style="font-size:0.75em;color:#8b949e;">Phase 6</div>
                    <div style="font-weight:600;font-size:0.85em;color:#a371f7;">Evidence Verified</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width:50px;">Step</th>
                        <th style="width:160px;">Phase</th>
                        <th style="width:140px;">Target Object</th>
                        <th>Forensic Action &amp; Parameters</th>
                        <th style="width:140px;">Timestamp</th>
                        <th style="width:80px;">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {prov_tbody}
                </tbody>
            </table>
        </div>

        <!-- ═══════════════════════════════════════════════════════
             DECRYPTED EVIDENCE EXPLORER — inline data, no server
             ═══════════════════════════════════════════════════════ -->
        <div id="evidence-section" style="margin-top:40px;">
        <h2 style="color:#ffffff;border-bottom:1px solid #30363d;padding-bottom:8px;">
            🔓 Decrypted Evidence &amp; Table Explorer
        </h2>
        <p style="color:#8b949e;font-size:0.9em;">
            All readable rows from decrypted and plain databases are embedded below.
            Use the tabs to switch databases, the search box to filter rows, and the
            CSV button to download any table.
        </p>
        <div id="evidence-root"></div>
        </div>

        <script>
        (function() {{
            var EVIDENCE = {evidence_json};

            var root = document.getElementById('evidence-root');
            if (!EVIDENCE || EVIDENCE.length === 0) {{
                root.innerHTML = '<p style="color:#8b949e;font-style:italic;">No exported/decrypted databases found. Re-run the pipeline with an export directory to populate this section.</p>';
                return;
            }}

            // --- styles injected by JS so the main <style> block stays a simple f-string ---
            var style = document.createElement('style');
            style.textContent = `
                .ev-tabs {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }}
                .ev-tab {{ padding:6px 14px; border-radius:6px; border:1px solid #30363d;
                           background:#161b22; color:#c9d1d9; cursor:pointer; font-size:0.85em; }}
                .ev-tab.active {{ background:#1f6feb; color:#fff; border-color:#1f6feb; }}
                .ev-panel {{ display:none; }}
                .ev-panel.active {{ display:block; }}
                .ev-table-tabs {{ display:flex; gap:6px; flex-wrap:wrap; margin-bottom:10px; }}
                .ev-ttab {{ padding:4px 12px; border-radius:4px; border:1px solid #30363d;
                            background:#0d1117; color:#8b949e; cursor:pointer; font-size:0.8em; }}
                .ev-ttab.active {{ background:#238636; color:#fff; border-color:#238636; }}
                .ev-search {{ background:#0d1117; border:1px solid #30363d; border-radius:6px;
                              color:#c9d1d9; padding:6px 12px; font-size:0.85em; width:240px;
                              margin-bottom:10px; }}
                .ev-toolbar {{ display:flex; align-items:center; gap:12px; margin-bottom:8px; }}
                .ev-csv-btn {{ padding:5px 12px; border-radius:5px; border:1px solid #30363d;
                               background:#21262d; color:#c9d1d9; cursor:pointer; font-size:0.8em; }}
                .ev-csv-btn:hover {{ background:#30363d; }}
                .ev-tbl {{ width:100%; border-collapse:collapse; font-size:0.85em; }}
                .ev-tbl th {{ background:#21262d; color:#fff; padding:8px 12px;
                              text-align:left; border-bottom:1px solid #30363d; position:sticky; top:0; }}
                .ev-tbl td {{ padding:7px 12px; border-bottom:1px solid #21262d;
                              color:#c9d1d9; word-break:break-word; max-width:300px; }}
                .ev-tbl tr:hover td {{ background:#161b22; }}
                .ev-tbl-wrap {{ overflow:auto; max-height:400px; border:1px solid #30363d;
                                border-radius:6px; background:#0d1117; }}
                .ev-rowcount {{ color:#8b949e; font-size:0.8em; margin-left:auto; }}
                .ev-empty {{ color:#8b949e; font-style:italic; padding:12px; }}
            `;
            document.head.appendChild(style);

            // --- build DB tabs ---
            var tabBar = document.createElement('div');
            tabBar.className = 'ev-tabs';

            var panels = [];

            EVIDENCE.forEach(function(db, di) {{
                var tab = document.createElement('button');
                tab.className = 'ev-tab' + (di === 0 ? ' active' : '');
                tab.textContent = db.name;
                tab.title = db.relpath;
                tab.onclick = function() {{
                    document.querySelectorAll('.ev-tab').forEach(function(t){{ t.classList.remove('active'); }});
                    tab.classList.add('active');
                    panels.forEach(function(p){{ p.classList.remove('active'); }});
                    panels[di].classList.add('active');
                }};
                tabBar.appendChild(tab);

                var panel = document.createElement('div');
                panel.className = 'ev-panel' + (di === 0 ? ' active' : '');

                // --- path info ---
                var pathInfo = document.createElement('p');
                pathInfo.style.cssText = 'color:#8b949e;font-size:0.8em;font-family:monospace;margin:0 0 10px 0;';
                pathInfo.textContent = db.relpath;
                panel.appendChild(pathInfo);

                // --- table tabs ---
                var ttabBar = document.createElement('div');
                ttabBar.className = 'ev-table-tabs';
                var tPanels = [];

                db.tables.forEach(function(tbl, ti) {{
                    var ttab = document.createElement('button');
                    ttab.className = 'ev-ttab' + (ti === 0 ? ' active' : '');
                    ttab.textContent = tbl.name + ' (' + tbl.rows.length + ')';
                    ttab.onclick = function() {{
                        ttabBar.querySelectorAll('.ev-ttab').forEach(function(t){{ t.classList.remove('active'); }});
                        ttab.classList.add('active');
                        tPanels.forEach(function(p){{ p.style.display='none'; }});
                        tPanels[ti].style.display='block';
                    }};
                    ttabBar.appendChild(ttab);

                    var tPanel = document.createElement('div');
                    tPanel.style.display = ti === 0 ? 'block' : 'none';

                    if (tbl.error && tbl.columns.length === 0) {{
                        var err = document.createElement('p');
                        err.className = 'ev-empty';
                        err.textContent = 'Error: ' + (tbl.error || 'Could not read table.');
                        tPanel.appendChild(err);
                    }} else if (tbl.rows.length === 0) {{
                        var empty = document.createElement('p');
                        empty.className = 'ev-empty';
                        empty.textContent = 'Table is empty.';
                        tPanel.appendChild(empty);
                    }} else {{
                        // toolbar
                        var toolbar = document.createElement('div');
                        toolbar.className = 'ev-toolbar';

                        var search = document.createElement('input');
                        search.type = 'text';
                        search.className = 'ev-search';
                        search.placeholder = 'Search rows…';
                        toolbar.appendChild(search);

                        var csvBtn = document.createElement('button');
                        csvBtn.className = 'ev-csv-btn';
                        csvBtn.textContent = '⬇ Download CSV';
                        toolbar.appendChild(csvBtn);

                        var rowCount = document.createElement('span');
                        rowCount.className = 'ev-rowcount';
                        toolbar.appendChild(rowCount);

                        tPanel.appendChild(toolbar);

                        var wrap = document.createElement('div');
                        wrap.className = 'ev-tbl-wrap';
                        var table = document.createElement('table');
                        table.className = 'ev-tbl';

                        // header
                        var thead = document.createElement('thead');
                        var hrow = document.createElement('tr');
                        tbl.columns.forEach(function(col) {{
                            var th = document.createElement('th');
                            th.textContent = col;
                            hrow.appendChild(th);
                        }});
                        thead.appendChild(hrow);
                        table.appendChild(thead);

                        // body
                        var tbody = document.createElement('tbody');
                        var allRows = tbl.rows;

                        function renderRows(filter) {{
                            tbody.innerHTML = '';
                            var shown = 0;
                            allRows.forEach(function(row) {{
                                var rowStr = row.map(function(v){{ return v === null ? 'NULL' : String(v); }}).join(' ').toLowerCase();
                                if (filter && rowStr.indexOf(filter.toLowerCase()) === -1) return;
                                var tr = document.createElement('tr');
                                row.forEach(function(cell) {{
                                    var td = document.createElement('td');
                                    td.textContent = cell === null ? 'NULL' : String(cell);
                                    if (cell === null) td.style.color = '#6e7681';
                                    tr.appendChild(td);
                                }});
                                tbody.appendChild(tr);
                                shown++;
                            }});
                            rowCount.textContent = shown + ' / ' + allRows.length + ' rows';
                        }}

                        renderRows('');
                        table.appendChild(tbody);
                        wrap.appendChild(table);
                        tPanel.appendChild(wrap);

                        search.oninput = function() {{ renderRows(search.value); }};

                        // CSV download
                        csvBtn.onclick = function() {{
                            var lines = [tbl.columns.map(function(c){{ return '"'+String(c).replace(/"/g,'""')+'"'; }}).join(',')];
                            allRows.forEach(function(row) {{
                                lines.push(row.map(function(v){{
                                    var s = v === null ? '' : String(v);
                                    return '"' + s.replace(/"/g,'""') + '"';
                                }}).join(','));
                            }});
                            var blob = new Blob([lines.join('\\n')], {{type:'text/csv'}});
                            var a = document.createElement('a');
                            a.href = URL.createObjectURL(blob);
                            a.download = db.name + '_' + tbl.name + '.csv';
                            a.click();
                        }};
                    }}
                    tPanels.push(tPanel);
                    panel.appendChild(tPanel);
                }});

                panel.insertBefore(ttabBar, panel.children[1]);
                panels.push(panel);
                root.appendChild(panel);
            }});

            root.insertBefore(tabBar, root.firstChild);
        }})();
        </script>
    </div>
</body>
</html>
"""

    if out_file:
        p = Path(out_file).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(html_content)

    return html_content


def write_json(data: Any, path: str | Path) -> None:
    """Writes data to a JSON file with indent=2 and sort_keys=True."""
    p = Path(path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def write_html(data: Any, path: str | Path) -> None:
    """
    Writes a self-contained HTML report with a table.
    Every value is escaped through html.escape.
    Does not load any external or internet resources.
    """
    p = Path(path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    dbs = data.get("databases", data) if isinstance(data, dict) else data
    if isinstance(dbs, list):
        for item in dbs:
            if isinstance(item, dict):
                status = html.escape(str(item.get("status", "-")))
                relpath = html.escape(str(item.get("relpath", "-")))
                bundle = html.escape(str(item.get("bundle_id") or item.get("container_uuid") or "-"))
                fp = html.escape(str(item.get("key_fingerprint") or "-"))
                prof = html.escape(str(item.get("profile") or "-"))
                rows.append(
                    f"<tr><td>{status}</td><td>{relpath}</td><td>{bundle}</td><td>{fp}</td><td>{prof}</td></tr>"
                )
    rows_html = "\n".join(rows)

    content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Forensic Correlation Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; background: #f8fafc; color: #1e293b; }}
        table {{ border-collapse: collapse; width: 100%; background: #ffffff; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
        th {{ background: #f1f5f9; }}
        tr:nth-child(even) {{ background: #f8fafc; }}
    </style>
</head>
<body>
    <h1>Keychain-Database Correlation Report</h1>
    <table>
        <thead>
            <tr><th>Status</th><th>Relative Path</th><th>Bundle / Container</th><th>Key Fingerprint</th><th>Profile</th></tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</body>
</html>"""
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)

