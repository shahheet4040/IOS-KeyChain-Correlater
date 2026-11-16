from pathlib import Path
import sqlite3
import pytest
from correlator.network_graph import build_network_graph, NetworkNode, NetworkEdge


def test_network_graph_empty():
    res = build_network_graph(search_dirs=[], consolidated_db_path=None)
    assert res["total_nodes"] == 0
    assert res["total_edges"] == 0
    assert res["nodes"] == []
    assert res["links"] == []


def test_network_graph_from_consolidated_db(tmp_path: Path):
    db_path = tmp_path / "test_consolidated.sqlite"
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE messages (
            message_id TEXT,
            app TEXT,
            sender TEXT,
            recipient TEXT,
            timestamp_utc TEXT,
            timestamp_epoch INTEGER,
            content TEXT
        )
    """)
    # Insert communications:
    # Target <-> Alice (15 msgs)
    # Target <-> Bob (5 msgs)
    # Alice <-> Charlie (2 msgs)
    # Bob <-> Charlie (3 msgs)
    # Charlie is a bridge / middleman
    msgs = [
        ("m1", "Signal", "Target (Owner)", "+15550001", "2026-11-10 10:00:00", 1700000000, "Hello Alice"),
        ("m2", "Signal", "+15550001", "Target (Owner)", "2026-11-10 10:05:00", 1700000300, "Hi Target"),
        ("m3", "Signal", "Target (Owner)", "+15550002", "2026-11-10 11:00:00", 1700003600, "Hey Bob"),
        ("m4", "WhatsApp", "+15550001", "+15550003", "2026-11-10 12:00:00", 1700007200, "Alice to Charlie"),
        ("m5", "WhatsApp", "+15550002", "+15550003", "2026-11-10 13:00:00", 1700010800, "Bob to Charlie"),
    ]
    for m in msgs:
        cur.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)", m)
    con.commit()
    con.close()

    res = build_network_graph(consolidated_db_path=db_path, min_interactions=1)
    assert res["total_nodes"] >= 4
    assert res["total_edges"] >= 4

    nodes_by_id = {n["id"]: n for n in res["nodes"]}
    assert "Target (Owner)" in nodes_by_id
    assert nodes_by_id["Target (Owner)"]["role"] == "Target (Device Owner)"

    # Check edges
    links = res["links"]
    assert any(
        (l["source"] == "+15550001" and l["target"] == "Target (Owner)") or
        (l["source"] == "Target (Owner)" and l["target"] == "+15550001")
        for l in links
    )


def test_network_graph_min_interactions(tmp_path: Path):
    db_path = tmp_path / "test_filter.sqlite"
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE messages (
            message_id TEXT,
            app TEXT,
            sender TEXT,
            recipient TEXT,
            timestamp_utc TEXT,
            timestamp_epoch INTEGER,
            content TEXT
        )
    """)
    # 3 messages between UserA and UserB, 1 message between UserA and UserC
    for i in range(3):
        cur.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)", (f"m{i}", "Signal", "UserA", "UserB", "2026-11-10", 1000 + i, "Msg"))
    cur.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)", ("m_single", "Signal", "UserA", "UserC", "2026-11-10", 2000, "Solo"))
    con.commit()
    con.close()

    # Filter >= 2 interactions: UserA <-> UserC should be excluded
    res = build_network_graph(consolidated_db_path=db_path, min_interactions=2)
    assert res["total_edges"] == 1
    edge = res["links"][0]
    assert edge["weight"] == 3
    assert {edge["source"], edge["target"]} == {"UserA", "UserB"}
