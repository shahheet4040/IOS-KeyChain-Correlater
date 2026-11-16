"""
Unified Forensic Timeline Engine
================================
Extracts, normalizes, and aggregates chronological events across disparate iOS applications:
- Signal Messenger (SQLCipher v4)
- WhatsApp Messenger (Plain SQLite / Crypt)
- WeChat (WCDB HMAC-SHA1 64k)
- Safari Browser History & Bookmarks
- Generic message/event stores
Produces a single, unified, cross-application event stream for investigative chronologies.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional


APPLE_EPOCH_OFFSET = 978307200  # Seconds between 1970-01-01 and 2001-01-01


@dataclass
class TimelineEvent:
    event_id: str
    timestamp_utc: str
    timestamp_epoch: float
    app: str
    app_icon: str
    event_type: str  # chat_message, web_visit, media_exchange, call_log
    sender: str
    recipient: str
    content: str
    source_database: str
    source_table: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _safe_float(val: Any) -> Optional[float]:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _format_epoch(epoch_seconds: float) -> str:
    try:
        dt = datetime.fromtimestamp(epoch_seconds, timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "1970-01-01 00:00:00 UTC"


def extract_whatsapp_events(db_path: Path) -> List[TimelineEvent]:
    events = []
    try:
        con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        # Check if ZWAMESSAGE exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZWAMESSAGE';")
        if not cur.fetchone():
            con.close()
            return events

        # Query messages: ZMESSAGEDATE is Apple Cocoa epoch
        cur.execute("""
            SELECT Z_PK, ZTEXT, ZMESSAGEDATE, ZFROMJID, ZTOJID, ZISFROMME
            FROM ZWAMESSAGE
            WHERE ZTEXT IS NOT NULL AND ZTEXT != ''
            ORDER BY ZMESSAGEDATE ASC
            LIMIT 2000;
        """)

        for row in cur.fetchall():
            raw_date = _safe_float(row["ZMESSAGEDATE"]) or 0.0
            epoch_sec = raw_date + APPLE_EPOCH_OFFSET if raw_date < 1000000000 else raw_date
            is_from_me = bool(row["ZISFROMME"]) if "ZISFROMME" in row.keys() else False
            sender = "Target (Device Owner)" if is_from_me else str(row["ZFROMJID"] or "Contact")
            recipient = str(row["ZTOJID"] or "Chat")

            events.append(TimelineEvent(
                event_id=f"WA-{row['Z_PK']}",
                timestamp_utc=_format_epoch(epoch_sec),
                timestamp_epoch=epoch_sec,
                app="WhatsApp",
                app_icon="🟢",
                event_type="chat_message",
                sender=sender,
                recipient=recipient,
                content=str(row["ZTEXT"] or ""),
                source_database=db_path.name,
                source_table="ZWAMESSAGE",
                metadata={"is_from_me": is_from_me, "raw_date": raw_date},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_signal_events(db_path: Path) -> List[TimelineEvent]:
    events = []
    try:
        con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        # Check for Signal message tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name='messages' OR name='model_messages');")
        match = cur.fetchone()
        if not match:
            con.close()
            return events

        table_name = match[0]
        cur.execute(f"PRAGMA table_info([{table_name}]);")
        cols = {c["name"] for c in cur.fetchall()}

        body_col = "body" if "body" in cols else "text"
        time_col = "dateSent" if "dateSent" in cols else ("date" if "date" in cols else None)

        if not time_col:
            con.close()
            return events

        cur.execute(f"SELECT rowid, * FROM [{table_name}] WHERE [{body_col}] IS NOT NULL LIMIT 2000;")
        for row in cur.fetchall():
            raw_time = _safe_float(row[time_col]) or 0.0
            # Signal timestamps are typically milliseconds since Unix epoch
            epoch_sec = raw_time / 1000.0 if raw_time > 100000000000 else raw_time
            body_text = str(row[body_col] or "")
            if not body_text.strip():
                continue

            author = str(row["author_id"]) if "author_id" in cols else (str(row["sender"]) if "sender" in cols else "Participant")
            recipient = str(row["conversation_id"]) if "conversation_id" in cols else "Chat"

            events.append(TimelineEvent(
                event_id=f"SIG-{row['rowid']}",
                timestamp_utc=_format_epoch(epoch_sec),
                timestamp_epoch=epoch_sec,
                app="Signal",
                app_icon="💬",
                event_type="chat_message",
                sender=author,
                recipient=recipient,
                content=body_text,
                source_database=db_path.name,
                source_table=table_name,
                metadata={"raw_time": raw_time},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_wechat_events(db_path: Path) -> List[TimelineEvent]:
    events = []
    try:
        con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'Chat_%' OR name='message');")
        tables = [r[0] for r in cur.fetchall()]
        for tbl in tables[:5]:
            cur.execute(f"PRAGMA table_info([{tbl}]);")
            cols = {c["name"] for c in cur.fetchall()}
            time_col = "CreateTime" if "CreateTime" in cols else ("time" if "time" in cols else None)
            msg_col = "Message" if "Message" in cols else ("msg" if "msg" in cols else None)

            if not time_col or not msg_col:
                continue

            cur.execute(f"SELECT rowid, * FROM [{tbl}] WHERE [{msg_col}] IS NOT NULL LIMIT 1000;")
            for row in cur.fetchall():
                raw_time = _safe_float(row[time_col]) or 0.0
                epoch_sec = raw_time if raw_time > 1000000 else (raw_time + APPLE_EPOCH_OFFSET)
                msg_val = str(row[msg_col] or "").strip()
                if not msg_val:
                    continue

                events.append(TimelineEvent(
                    event_id=f"WC-{tbl}-{row['rowid']}",
                    timestamp_utc=_format_epoch(epoch_sec),
                    timestamp_epoch=epoch_sec,
                    app="WeChat",
                    app_icon="💬",
                    event_type="chat_message",
                    sender=str(row["Des"]) if "Des" in cols else "Sender",
                    recipient=tbl,
                    content=msg_val,
                    source_database=db_path.name,
                    source_table=tbl,
                    metadata={"table": tbl},
                ))

        con.close()
    except Exception:
        pass
    return events


def extract_safari_events(db_path: Path) -> List[TimelineEvent]:
    events = []
    try:
        con = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table' AND name IN ('history_visits', 'history_items');
        """)
        found = {r[0] for r in cur.fetchall()}
        if "history_visits" in found and "history_items" in found:
            cur.execute("""
                SELECT v.id, v.visit_time, v.title, i.url
                FROM history_visits v
                LEFT JOIN history_items i ON v.history_item = i.id
                ORDER BY v.visit_time ASC
                LIMIT 1500;
            """)
            for row in cur.fetchall():
                raw_time = _safe_float(row["visit_time"]) or 0.0
                epoch_sec = raw_time + APPLE_EPOCH_OFFSET if raw_time < 1000000000 else raw_time
                title = str(row["title"] or "")
                url = str(row["url"] or "")
                content = f"{title} ({url})" if title else url

                events.append(TimelineEvent(
                    event_id=f"SAF-{row['id']}",
                    timestamp_utc=_format_epoch(epoch_sec),
                    timestamp_epoch=epoch_sec,
                    app="Safari",
                    app_icon="🌐",
                    event_type="web_visit",
                    sender="Target Device User",
                    recipient="Web Navigation",
                    content=content,
                    source_database=db_path.name,
                    source_table="history_visits",
                    metadata={"url": url, "title": title},
                ))

        con.close()
    except Exception:
        pass
    return events


def extract_unified_timeline(
    evidence_directory: Path | str,
    max_records: int = 5000,
) -> List[TimelineEvent]:
    """
    Scans any directory containing decrypted databases (Signal, WhatsApp, WeChat, Safari)
    and aggregates all communications and web visits into a single chronological stream.
    """
    p = Path(evidence_directory).resolve()
    all_events: List[TimelineEvent] = []

    if not p.is_dir():
        return all_events

    for db_file in p.rglob("*"):
        if not db_file.is_file() or db_file.suffix.lower() not in (".sqlite", ".db", ".sqlite3"):
            continue

        name_lower = db_file.name.lower()
        if "chatstorage" in name_lower or "whatsapp" in name_lower:
            all_events.extend(extract_whatsapp_events(db_file))
        elif "signal" in name_lower or "messenger" in name_lower:
            all_events.extend(extract_signal_events(db_file))
        elif "wechat" in name_lower or "wcdb" in name_lower:
            all_events.extend(extract_wechat_events(db_file))
        elif "history" in name_lower or "safari" in name_lower or "browser" in name_lower:
            all_events.extend(extract_safari_events(db_file))
        else:
            # Try generic inspections
            all_events.extend(extract_whatsapp_events(db_file))
            all_events.extend(extract_signal_events(db_file))
            all_events.extend(extract_safari_events(db_file))

    # Sort strictly by timestamp_epoch ascending
    all_events.sort(key=lambda x: x.timestamp_epoch)
    return all_events[:max_records]
