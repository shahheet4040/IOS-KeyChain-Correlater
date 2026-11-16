from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
import sqlite3

from correlator.search_engine import (
    export_search_results,
    generate_search_report_html,
    search_by_date_range,
    search_sqlite_files,
    search_with_patterns,
)


@pytest.fixture
def mock_evidence_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "chat_evidence.sqlite"
    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("CREATE TABLE messages (id INT, sender TEXT, body TEXT, timestamp REAL);")
    cur.execute("INSERT INTO messages VALUES (1, 'Alice', 'Transfer funds to Swiss account', 1672531200.0);")
    cur.execute("INSERT INTO messages VALUES (2, 'Bob', 'Confirmed receipt of 50 BTC', 1672617600.0);")
    cur.execute("INSERT INTO messages VALUES (3, 'Charlie', 'Meeting at forensic lab on Monday', 1672704000.0);")
    con.commit()
    con.close()
    return tmp_path


def test_search_sqlite_files(mock_evidence_db: Path):
    hits = search_sqlite_files(mock_evidence_db, "Swiss account")
    assert len(hits) == 1
    assert hits[0].table_name == "messages"
    assert hits[0].column_name == "body"
    assert "Swiss account" in hits[0].matched_value

    # Case insensitive check
    hits_lower = search_sqlite_files(mock_evidence_db, "swiss account", case_insensitive=True)
    assert len(hits_lower) == 1


def test_search_with_patterns(mock_evidence_db: Path):
    patterns = ["Swiss", "50 BTC", "NonExistentWord"]
    results = search_with_patterns(mock_evidence_db, patterns)
    assert len(results["Swiss"]) == 1
    assert len(results["50 BTC"]) == 1
    assert len(results["NonExistentWord"]) == 0


def test_search_by_date_range(mock_evidence_db: Path):
    # 2023-01-01 to 2023-01-02
    start = datetime(2023, 1, 1, tzinfo=timezone.utc)
    end = datetime(2023, 1, 2, 23, 59, 59, tzinfo=timezone.utc)

    hits = search_by_date_range(mock_evidence_db, start, end)
    assert len(hits) >= 2


def test_export_and_html_report(mock_evidence_db: Path, tmp_path: Path):
    hits = search_sqlite_files(mock_evidence_db, "BTC")
    
    # Export JSON
    json_path = tmp_path / "hits.json"
    export_search_results(hits, json_path, fmt="json")
    assert json_path.is_file()
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(loaded) == 1

    # Export CSV
    csv_path = tmp_path / "hits.csv"
    export_search_results(hits, csv_path, fmt="csv")
    assert csv_path.is_file()

    # Generate HTML
    html_path = tmp_path / "search_report.html"
    html_content = generate_search_report_html(hits, "BTC", html_path)
    assert html_path.is_file()
    assert "BTC" in html_content
    assert "<mark>" in html_content
