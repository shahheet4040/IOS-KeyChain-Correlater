"""
Contact Network Graph & Social Graph Analysis Engine
=====================================================
Analyzes communication relationships, message frequency, and interaction
patterns across decrypted communications (Signal, WhatsApp, WeChat, etc.).

Computes:
- Nodes (Participants, phone numbers, aliases, handles)
- Edges (Directional and bi-directional communications with weight/frequency)
- Graph Metrics (Degree centrality, top communicators, key middlemen)
- Cluster detection and cross-app communication bridges
"""

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from correlator.timeline import TimelineEvent, extract_unified_timeline


@dataclass
class NetworkNode:
    id: str
    label: str
    app: str
    message_count: int
    degree: int
    role: str  # "Target", "Frequent Contact", "Occasional Contact", "Bridge"
    first_seen: str
    last_seen: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkEdge:
    source: str
    target: str
    weight: int  # Total communication count
    app: str
    first_seen: str
    last_seen: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_network_graph(
    search_dirs: Optional[List[Path | str]] = None,
    consolidated_db_path: Optional[Path | str] = None,
    min_interactions: int = 1,
) -> Dict[str, Any]:
    """
    Extracts participants and communication interactions to build a social network graph.
    Can read from either a consolidated_case_evidence.sqlite or directories containing
    decrypted databases (Signal, WhatsApp, WeChat).
    """
    interactions: Dict[Tuple[str, str, str], Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "first_seen": None, "last_seen": None}
    )
    node_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "apps": set(), "first_seen": None, "last_seen": None}
    )

    # 1. Try reading from consolidated database if provided
    if consolidated_db_path and Path(consolidated_db_path).is_file():
        con = sqlite3.connect(f"{Path(consolidated_db_path).resolve().as_uri()}?mode=ro", uri=True)
        cur = con.cursor()
        try:
            cur.execute("""
                SELECT sender, recipient, app, timestamp_utc, timestamp_epoch
                FROM messages
                WHERE sender IS NOT NULL AND recipient IS NOT NULL
                ORDER BY timestamp_epoch ASC
            """)
            for sender, recipient, app, ts_utc, ts_epoch in cur.fetchall():
                s = str(sender).strip()
                r = str(recipient).strip()
                a = str(app or "Chat").strip()
                if not s or not r:
                    continue

                pair = tuple(sorted([s, r])) + (a,)
                interactions[pair]["count"] += 1
                if not interactions[pair]["first_seen"]:
                    interactions[pair]["first_seen"] = ts_utc
                interactions[pair]["last_seen"] = ts_utc

                for participant in (s, r):
                    node_stats[participant]["count"] += 1
                    node_stats[participant]["apps"].add(a)
                    if not node_stats[participant]["first_seen"]:
                        node_stats[participant]["first_seen"] = ts_utc
                    node_stats[participant]["last_seen"] = ts_utc
        finally:
            con.close()

    # 2. Extract from decrypted directories if available
    if search_dirs:
        dirs = [Path(d).resolve() for d in search_dirs if Path(d).is_dir()]
        events: List[TimelineEvent] = []
        for d in dirs:
            events.extend(extract_unified_timeline(d))

        for ev in events:
            if ev.event_type not in ("chat_message", "message"):
                continue
            s = ev.sender.strip()
            r = ev.recipient.strip()
            a = ev.app.strip()
            if not s or not r or s == r:
                continue

            pair = tuple(sorted([s, r])) + (a,)
            interactions[pair]["count"] += 1
            if not interactions[pair]["first_seen"]:
                interactions[pair]["first_seen"] = ev.timestamp_utc
            interactions[pair]["last_seen"] = ev.timestamp_utc

            for participant in (s, r):
                node_stats[participant]["count"] += 1
                node_stats[participant]["apps"].add(a)
                if not node_stats[participant]["first_seen"]:
                    node_stats[participant]["first_seen"] = ev.timestamp_utc
                node_stats[participant]["last_seen"] = ev.timestamp_utc

    # 3. Filter and construct Edges
    edges: List[NetworkEdge] = []
    degree_counter: Dict[str, int] = defaultdict(int)

    for (node_a, node_b, app), data in interactions.items():
        if data["count"] >= min_interactions:
            edges.append(NetworkEdge(
                source=node_a,
                target=node_b,
                weight=data["count"],
                app=app,
                first_seen=data["first_seen"] or "",
                last_seen=data["last_seen"] or "",
            ))
            degree_counter[node_a] += 1
            degree_counter[node_b] += 1

    # 4. Construct Nodes with roles and metrics
    nodes: List[NetworkNode] = []
    for node_id, stats in node_stats.items():
        deg = degree_counter[node_id]
        if deg == 0 and len(interactions) > 0:
            continue

        # Determine forensic role
        if "Target" in node_id or "Owner" in node_id:
            role = "Target (Device Owner)"
        elif deg >= 4 or stats["count"] >= 50:
            role = "Primary Hub / Middleman"
        elif deg >= 2 or stats["count"] >= 10:
            role = "Frequent Associate"
        else:
            role = "Occasional Contact"

        nodes.append(NetworkNode(
            id=node_id,
            label=node_id,
            app=", ".join(sorted(stats["apps"])) if stats["apps"] else "Multiple",
            message_count=stats["count"],
            degree=deg,
            role=role,
            first_seen=stats["first_seen"] or "",
            last_seen=stats["last_seen"] or "",
        ))

    # Sort nodes by message count
    nodes.sort(key=lambda n: n.message_count, reverse=True)
    edges.sort(key=lambda e: e.weight, reverse=True)

    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes": [n.to_dict() for n in nodes],
        "links": [e.to_dict() for e in edges],
    }
