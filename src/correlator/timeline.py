"""
Forensic Master Cross-Application Timeline & Correlation Engine
==============================================================
Fuses disparate iOS evidence sources into a single, unified, chronologically
synchronized investigative event stream:
- Messaging: Signal, WhatsApp, SMS/iMessage, WeChat
- Telephony: Cellular & FaceTime Audio/Video Calls (CallHistory)
- Media: Camera roll photos, videos & EXIF locations (Photos.sqlite)
- Activity: Safari browser navigation & search queries (History.db)
- Personal Data: Apple Notes snippets & memos (NoteStore.sqlite)
- Mobility: Geospatial waypoint movement fixes (routined / EXIF)
- Residual: Carved deleted SQLite records & slack space fragments

Performs automated cross-application correlation:
- Cross-app participant identity disambiguation (phone, email, JID)
- Temporal burst & multi-channel cluster detection
- Encrypted communication migration pattern detection
- Standalone interactive HTML master timeline visualization & Plaso/CSV export
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple


APPLE_EPOCH_OFFSET = 978307200  # Seconds between 1970-01-01 and 2001-01-01


@dataclass
class TimelineEvent:
    event_id: str
    timestamp_utc: str
    timestamp_epoch: float
    app: str
    app_icon: str
    event_type: str  # chat_message, call_log, web_visit, photo_capture, location_fix, note_entry, deleted_carved
    sender: str
    recipient: str
    content: str
    source_database: str
    source_table: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_deleted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationCluster:
    cluster_id: str
    start_time_utc: str
    end_time_utc: str
    duration_minutes: float
    apps_involved: List[str]
    participants: List[str]
    event_count: int
    significance_score: float = 1.0
    events: List[TimelineEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "start_time_utc": self.start_time_utc,
            "end_time_utc": self.end_time_utc,
            "duration_minutes": round(self.duration_minutes, 1),
            "apps_involved": self.apps_involved,
            "participants": self.participants,
            "event_count": self.event_count,
            "significance_score": round(self.significance_score, 2),
            "events": [e.to_dict() for e in self.events],
        }


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


def normalize_timestamp(raw_val: Any) -> Tuple[float, str]:
    """
    Normalizes any iOS raw timestamp (Apple Cocoa nanoseconds, Cocoa seconds,
    Unix milliseconds, Unix seconds) into (epoch_seconds, formatted_utc_str).
    """
    raw = _safe_float(raw_val)
    if raw is None or raw <= 0:
        return 0.0, "1970-01-01 00:00:00 UTC"

    # Cocoa nanoseconds (> 1e15)
    if raw > 1e15:
        epoch_sec = (raw / 1e9) + APPLE_EPOCH_OFFSET
    # Unix milliseconds (> 1e11)
    elif raw > 1e11:
        epoch_sec = raw / 1000.0
    # Unix seconds (> 1e9)
    elif raw >= 1e9:
        epoch_sec = raw
    # Apple Cocoa seconds (< 1e9)
    else:
        epoch_sec = raw + APPLE_EPOCH_OFFSET

    return epoch_sec, _format_epoch(epoch_sec)


def normalize_contact_identifier(raw_id: str) -> str:
    """
    Normalizes phone numbers, JIDs, and email addresses into canonical form.
    E.g. '15550199234@s.whatsapp.net' -> '+15550199234'
         '+1 (555) 019-9234' -> '+15550199234'
    """
    if not raw_id:
        return ""
    s = str(raw_id).strip()
    if "@s.whatsapp.net" in s or "@c.us" in s or "@g.us" in s:
        s = s.split("@")[0]
    elif "@" in s:
        return s.lower()

    # Check for phone numbers
    digits = re.sub(r"[^\d+]", "", s)
    if digits:
        if digits.startswith("+"):
            return digits
        if len(digits) == 10:
            return f"+1{digits}"
        if len(digits) == 11 and digits.startswith("1"):
            return f"+{digits}"
        return f"+{digits}"
    return s


# ==============================================================================
# Evidence Extractors: Messaging, Telephony, Media, Notes, Safari
# ==============================================================================

def extract_whatsapp_events(db_path: Path) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZWAMESSAGE';")
        if not cur.fetchone():
            con.close()
            return events

        cur.execute("""
            SELECT Z_PK, ZTEXT, ZMESSAGEDATE, ZFROMJID, ZTOJID, ZISFROMME
            FROM ZWAMESSAGE
            WHERE ZTEXT IS NOT NULL AND ZTEXT != ''
            ORDER BY ZMESSAGEDATE ASC
            LIMIT 5000;
        """)

        for row in cur.fetchall():
            epoch_sec, dt_str = normalize_timestamp(row["ZMESSAGEDATE"])
            is_from_me = bool(row["ZISFROMME"]) if "ZISFROMME" in row.keys() else False
            sender = "Target (Device Owner)" if is_from_me else str(row["ZFROMJID"] or "Contact")
            recipient = str(row["ZTOJID"] or "Chat")

            events.append(TimelineEvent(
                event_id=f"WA-{row['Z_PK']}",
                timestamp_utc=dt_str,
                timestamp_epoch=epoch_sec,
                app="WhatsApp",
                app_icon="🟢",
                event_type="chat_message",
                sender=sender,
                recipient=recipient,
                content=str(row["ZTEXT"] or ""),
                source_database=db_path.name,
                source_table="ZWAMESSAGE",
                metadata={"is_from_me": is_from_me, "raw_date": row["ZMESSAGEDATE"]},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_signal_events(db_path: Path) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

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

        cur.execute(f"SELECT rowid, * FROM [{table_name}] WHERE [{body_col}] IS NOT NULL LIMIT 5000;")
        for row in cur.fetchall():
            epoch_sec, dt_str = normalize_timestamp(row[time_col])
            body_text = str(row[body_col] or "").strip()
            if not body_text:
                continue

            author = str(row["author_id"]) if "author_id" in cols else (str(row["sender"]) if "sender" in cols else "Participant")
            recipient = str(row["conversation_id"]) if "conversation_id" in cols else "Chat"

            events.append(TimelineEvent(
                event_id=f"SIG-{row['rowid']}",
                timestamp_utc=dt_str,
                timestamp_epoch=epoch_sec,
                app="Signal",
                app_icon="💬",
                event_type="chat_message",
                sender=author,
                recipient=recipient,
                content=body_text,
                source_database=db_path.name,
                source_table=table_name,
                metadata={"time_col": time_col, "raw_time": row[time_col]},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_sms_events(db_path: Path) -> List[TimelineEvent]:
    """Extracts SMS and iMessage conversations from iOS sms.db."""
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='message';")
        if not cur.fetchone():
            con.close()
            return events

        # Query messages with handle joins
        cur.execute("PRAGMA table_info(message);")
        m_cols = {c["name"] for c in cur.fetchall()}

        text_col = "text" if "text" in m_cols else "attributedBody"
        has_handle = "handle_id" in m_cols

        query = f"""
            SELECT m.ROWID as msg_id, m.{text_col} as msg_text, m.date, m.is_from_me,
                   m.service, m.date_read, m.date_delivered
                   {', h.id as handle_contact' if has_handle else ''}
            FROM message m
            {'LEFT JOIN handle h ON m.handle_id = h.ROWID' if has_handle else ''}
            WHERE m.{text_col} IS NOT NULL
            ORDER BY m.date ASC
            LIMIT 5000;
        """
        cur.execute(query)

        for row in cur.fetchall():
            epoch_sec, dt_str = normalize_timestamp(row["date"])
            is_from_me = bool(row["is_from_me"]) if "is_from_me" in row.keys() else False
            handle = str(row["handle_contact"]) if has_handle and row["handle_contact"] else "Unknown Contact"
            svc = str(row["service"] or "SMS")

            sender = "Target (Device Owner)" if is_from_me else handle
            recipient = handle if is_from_me else "Target (Device Owner)"
            content = str(row["msg_text"] or "").strip()
            if not content:
                continue

            events.append(TimelineEvent(
                event_id=f"SMS-{row['msg_id']}",
                timestamp_utc=dt_str,
                timestamp_epoch=epoch_sec,
                app=f"Messages ({svc})",
                app_icon="📱",
                event_type="chat_message",
                sender=sender,
                recipient=recipient,
                content=content,
                source_database=db_path.name,
                source_table="message",
                metadata={"service": svc, "is_from_me": is_from_me, "raw_date": row["date"]},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_call_history_events(db_path: Path) -> List[TimelineEvent]:
    """Extracts cellular and FaceTime calls from iOS CallHistory.storedata / CallHistory.sqlite."""
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ZCALLRECORD';")
        if not cur.fetchone():
            con.close()
            return events

        cur.execute("PRAGMA table_info(ZCALLRECORD);")
        cols = {c["name"] for c in cur.fetchall()}

        addr_col = "ZADDRESS" if "ZADDRESS" in cols else "ZORIGINATED"
        dur_col = "ZDURATION" if "ZDURATION" in cols else None
        date_col = "ZDATE" if "ZDATE" in cols else None

        if not date_col:
            con.close()
            return events

        cur.execute(f"SELECT Z_PK, * FROM ZCALLRECORD WHERE {date_col} IS NOT NULL ORDER BY {date_col} ASC LIMIT 2500;")
        for row in cur.fetchall():
            epoch_sec, dt_str = normalize_timestamp(row[date_col])
            address = str(row[addr_col] or "Unknown") if addr_col else "Unknown"
            duration = int(_safe_float(row[dur_col]) or 0) if dur_col else 0

            originated = bool(row["ZORIGINATED"]) if "ZORIGINATED" in cols else False
            answered = bool(row["ZANSWERED"]) if "ZANSWERED" in cols else False
            call_type = row["ZCALLTYPE"] if "ZCALLTYPE" in cols else 1

            # Infer call type label
            type_label = "Cellular Call"
            if call_type in (8, 16):
                type_label = "FaceTime Video" if call_type == 16 else "FaceTime Audio"

            direction = "Outgoing" if originated else ("Incoming" if answered else "Missed")
            name = str(row["ZNAME"] or "") if "ZNAME" in cols and row["ZNAME"] else address

            sender = "Target (Device Owner)" if originated else f"{name} ({address})"
            recipient = f"{name} ({address})" if originated else "Target (Device Owner)"
            content = f"{direction} {type_label} with {name} (Duration: {duration}s)"

            events.append(TimelineEvent(
                event_id=f"CALL-{row['Z_PK']}",
                timestamp_utc=dt_str,
                timestamp_epoch=epoch_sec,
                app="Phone / Calls",
                app_icon="📞",
                event_type="call_log",
                sender=sender,
                recipient=recipient,
                content=content,
                source_database=db_path.name,
                source_table="ZCALLRECORD",
                metadata={"duration_sec": duration, "direction": direction, "call_type": type_label, "raw_date": row[date_col]},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_notes_events(db_path: Path) -> List[TimelineEvent]:
    """Extracts Apple Notes memos, snippets, and modification events from NoteStore.sqlite."""
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ZICCLOUDOBJECT', 'ZNOTE');")
        match = cur.fetchone()
        if not match:
            con.close()
            return events

        tbl = match[0]
        cur.execute(f"PRAGMA table_info([{tbl}]);")
        cols = {c["name"] for c in cur.fetchall()}

        date_col = "ZCREATIONDATE" if "ZCREATIONDATE" in cols else ("ZDATE" if "ZDATE" in cols else None)
        title_col = "ZTITLE" if "ZTITLE" in cols else ("ZNAME" if "ZNAME" in cols else None)
        snippet_col = "ZSNIPPET" if "ZSNIPPET" in cols else ("ZBODY" if "ZBODY" in cols else None)

        if not date_col:
            con.close()
            return events

        select_cols = f"Z_PK, {date_col}"
        if title_col:
            select_cols += f", {title_col}"
        if snippet_col:
            select_cols += f", {snippet_col}"

        cur.execute(f"SELECT {select_cols} FROM [{tbl}] WHERE {date_col} IS NOT NULL LIMIT 1500;")
        for row in cur.fetchall():
            epoch_sec, dt_str = normalize_timestamp(row[date_col])
            title = str(row[title_col] or "").strip() if title_col else "Note"
            snippet = str(row[snippet_col] or "").strip() if snippet_col else ""
            content = f"{title}: {snippet}" if (title and snippet) else (title or snippet or "Note entry")

            events.append(TimelineEvent(
                event_id=f"NOTE-{row['Z_PK']}",
                timestamp_utc=dt_str,
                timestamp_epoch=epoch_sec,
                app="Apple Notes",
                app_icon="📝",
                event_type="note_entry",
                sender="Target (Device Owner)",
                recipient="Local Storage",
                content=content,
                source_database=db_path.name,
                source_table=tbl,
                metadata={"title": title, "raw_date": row[date_col]},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_photos_events(db_path: Path) -> List[TimelineEvent]:
    """Extracts photo and video capture events from iOS Photos.sqlite."""
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ZASSET', 'ZGENERICASSET');")
        match = cur.fetchone()
        if not match:
            con.close()
            return events

        tbl = match[0]
        cur.execute(f"PRAGMA table_info([{tbl}]);")
        cols = {c["name"] for c in cur.fetchall()}

        date_col = "ZDATECREATED" if "ZDATECREATED" in cols else ("ZADDEDDATE" if "ZADDEDDATE" in cols else None)
        fn_col = "ZFILENAME" if "ZFILENAME" in cols else None
        lat_col = "ZLATITUDE" if "ZLATITUDE" in cols else None
        lon_col = "ZLONGITUDE" if "ZLONGITUDE" in cols else None

        if not date_col:
            con.close()
            return events

        cur.execute(f"SELECT Z_PK, * FROM [{tbl}] WHERE {date_col} IS NOT NULL ORDER BY {date_col} ASC LIMIT 2500;")
        for row in cur.fetchall():
            epoch_sec, dt_str = normalize_timestamp(row[date_col])
            fname = str(row[fn_col] or "IMG_Asset") if fn_col else "IMG_Asset"
            lat = _safe_float(row[lat_col]) if lat_col else None
            lon = _safe_float(row[lon_col]) if lon_col else None

            # Ignore 0.0 or default invalid coordinates
            if lat == 0.0 and lon == 0.0:
                lat, lon = None, None

            loc_str = f" [GPS: {lat:.4f}, {lon:.4f}]" if (lat and lon) else ""
            content = f"Captured photo/media asset: {fname}{loc_str}"

            events.append(TimelineEvent(
                event_id=f"PHOTO-{row['Z_PK']}",
                timestamp_utc=dt_str,
                timestamp_epoch=epoch_sec,
                app="Photos / Camera",
                app_icon="📷",
                event_type="photo_capture",
                sender="Camera Hardware",
                recipient="Media Library",
                content=content,
                source_database=db_path.name,
                source_table=tbl,
                latitude=lat,
                longitude=lon,
                metadata={"filename": fname, "raw_date": row[date_col]},
            ))

        con.close()
    except Exception:
        pass
    return events


def extract_safari_events(db_path: Path) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('history_visits', 'history_items');")
        found = {r[0] for r in cur.fetchall()}
        if "history_visits" in found and "history_items" in found:
            cur.execute("""
                SELECT v.id, v.visit_time, v.title, i.url
                FROM history_visits v
                LEFT JOIN history_items i ON v.history_item = i.id
                ORDER BY v.visit_time ASC
                LIMIT 2500;
            """)
            for row in cur.fetchall():
                epoch_sec, dt_str = normalize_timestamp(row["visit_time"])
                title = str(row["title"] or "")
                url = str(row["url"] or "")
                content = f"{title} ({url})" if title else url

                events.append(TimelineEvent(
                    event_id=f"SAF-{row['id']}",
                    timestamp_utc=dt_str,
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


def extract_wechat_events(db_path: Path) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    try:
        con = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
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
                epoch_sec, dt_str = normalize_timestamp(row[time_col])
                msg_val = str(row[msg_col] or "").strip()
                if not msg_val:
                    continue

                events.append(TimelineEvent(
                    event_id=f"WC-{tbl}-{row['rowid']}",
                    timestamp_utc=dt_str,
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


def convert_geopoints_to_timeline(geo_points: List[Any]) -> List[TimelineEvent]:
    """Converts GeoPoint instances from geospatial.py into timeline movement events."""
    events: List[TimelineEvent] = []
    for i, pt in enumerate(geo_points):
        epoch_sec = getattr(pt, "timestamp_epoch", 0.0)
        dt_str = getattr(pt, "timestamp_utc", "")
        if not dt_str:
            _, dt_str = normalize_timestamp(epoch_sec)

        lat = getattr(pt, "latitude", None)
        lon = getattr(pt, "longitude", None)
        mode = getattr(pt, "inferred_mode", "Movement")
        src = getattr(pt, "source_type", "GPS Fix")
        spd = getattr(pt, "speed_kmh", 0.0) or 0.0

        content = f"Location waypoint fix [{mode}]: {lat:.5f}, {lon:.5f} ({spd:.1f} km/h via {src})"

        events.append(TimelineEvent(
            event_id=f"GEO-{getattr(pt, 'point_id', i+1)}",
            timestamp_utc=dt_str,
            timestamp_epoch=epoch_sec,
            app="Location (GPS)",
            app_icon="📍",
            event_type="location_fix",
            sender="GPS / Location Core",
            recipient="Movement Trail",
            content=content,
            source_database=str(getattr(pt, "file_name", "routined")),
            source_table=src,
            latitude=lat,
            longitude=lon,
            metadata={"speed_kmh": spd, "mode": mode, "source": src},
        ))
    return events


def convert_carved_records_to_timeline(carved_records: List[Any]) -> List[TimelineEvent]:
    """Converts DeletedRecord instances from carver.py into timeline events."""
    events: List[TimelineEvent] = []
    for i, rec in enumerate(carved_records):
        raw_text = getattr(rec, "raw_text", "")
        if not raw_text.strip():
            continue

        db = getattr(rec, "database", "database.sqlite")
        src = getattr(rec, "source_type", "slack")
        page = getattr(rec, "page_num", 0)
        off = getattr(rec, "offset_in_page", 0)

        # Inspect if raw text contains an ISO timestamp
        match = re.search(r"20\d\d-[01]\d-[0-3]\d[ T][0-2]\d:[0-5]\d:[0-5]\d", raw_text)
        if match:
            try:
                dt_clean = match.group(0).replace("T", " ")
                dt = datetime.strptime(dt_clean, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                epoch_sec = dt.timestamp()
                dt_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                epoch_sec, dt_str = 0.0, "1970-01-01 00:00:00 UTC"
        else:
            epoch_sec, dt_str = 0.0, "1970-01-01 00:00:00 UTC"

        content = f"🚨 [CARVED / DELETED] (Pg {page}, Off 0x{off:04X}, {src}): {raw_text}"

        events.append(TimelineEvent(
            event_id=f"CARVED-{getattr(rec, 'record_id', i+1)}",
            timestamp_utc=dt_str,
            timestamp_epoch=epoch_sec,
            app=f"Carver ({Path(db).stem})",
            app_icon="🚨",
            event_type="deleted_carved",
            sender="Residual Storage Slack",
            recipient="Forensic Investigator",
            content=content,
            source_database=str(db),
            source_table=f"slack_{src}",
            is_deleted=True,
            metadata={"page": page, "offset": off, "carve_source": src},
        ))
    return events


# ==============================================================================
# Cross-Application Correlation & Burst Detection
# ==============================================================================

def detect_cross_app_bursts(
    events: List[TimelineEvent],
    window_minutes: int = 15,
    min_apps: int = 2,
) -> List[CorrelationCluster]:
    """
    Sliding window burst detection: Identifies high-intensity multi-channel
    communication clusters where activity occurred across 2+ distinct apps
    within a short time window (e.g. suspect texted on SMS, sent a WhatsApp message,
    and took a photo within 15 minutes).
    """
    # Filter to events with valid timestamps
    valid_events = [e for e in events if e.timestamp_epoch > 10000000]
    if not valid_events:
        return []

    valid_events.sort(key=lambda x: x.timestamp_epoch)
    clusters: List[CorrelationCluster] = []
    window_sec = window_minutes * 60

    i = 0
    cluster_num = 1
    while i < len(valid_events):
        current_event = valid_events[i]
        t_start = current_event.timestamp_epoch
        t_end = t_start + window_sec

        # Collect events in window
        window_events = [current_event]
        j = i + 1
        while j < len(valid_events) and valid_events[j].timestamp_epoch <= t_end:
            window_events.append(valid_events[j])
            j += 1

        distinct_apps = list(set(e.app for e in window_events))
        if len(distinct_apps) >= min_apps and len(window_events) >= 3:
            participants = list(set(
                normalize_contact_identifier(e.sender) for e in window_events if e.sender != "Target (Device Owner)"
            ) | set(
                normalize_contact_identifier(e.recipient) for e in window_events if e.recipient != "Target (Device Owner)"
            ))

            actual_duration = (window_events[-1].timestamp_epoch - window_events[0].timestamp_epoch) / 60.0
            significance = len(distinct_apps) * 1.5 + len(window_events) * 0.2

            clusters.append(CorrelationCluster(
                cluster_id=f"BURST-{cluster_num:03d}",
                start_time_utc=window_events[0].timestamp_utc,
                end_time_utc=window_events[-1].timestamp_utc,
                duration_minutes=actual_duration,
                apps_involved=distinct_apps,
                participants=[p for p in participants if p],
                event_count=len(window_events),
                significance_score=significance,
                events=window_events,
            ))
            cluster_num += 1
            i = j  # advance past this cluster to avoid duplicate overlapping clusters
        else:
            i += 1

    return clusters


def correlate_cross_app_identities(events: List[TimelineEvent]) -> Dict[str, Dict[str, Any]]:
    """
    Disambiguates and aggregates contacts across WhatsApp, Signal, SMS, and Calls.
    Returns a unified participant dictionary showing multi-app presence.
    """
    identities: Dict[str, Dict[str, Any]] = {}

    for ev in events:
        for raw_person in (ev.sender, ev.recipient):
            if not raw_person or "Target" in raw_person or "Device Owner" in raw_person or "Unknown" in raw_person:
                continue

            canonical = normalize_contact_identifier(raw_person)
            if not canonical or len(canonical) < 3:
                continue

            if canonical not in identities:
                identities[canonical] = {
                    "canonical_id": canonical,
                    "raw_aliases": set(),
                    "apps": set(),
                    "total_events": 0,
                    "first_seen": ev.timestamp_utc,
                    "last_seen": ev.timestamp_utc,
                }

            identities[canonical]["raw_aliases"].add(raw_person)
            identities[canonical]["apps"].add(ev.app)
            identities[canonical]["total_events"] += 1
            identities[canonical]["last_seen"] = ev.timestamp_utc

    # Clean sets for serialization
    out: Dict[str, Dict[str, Any]] = {}
    for k, v in identities.items():
        out[k] = {
            "canonical_id": v["canonical_id"],
            "raw_aliases": list(v["raw_aliases"]),
            "apps": sorted(list(v["apps"])),
            "total_events": v["total_events"],
            "first_seen": v["first_seen"],
            "last_seen": v["last_seen"],
            "is_cross_app": len(v["apps"]) > 1,
        }
    return out


def detect_app_switching(events: List[TimelineEvent], max_gap_hours: int = 2) -> List[Dict[str, Any]]:
    """
    Identifies when communication with a contact migrated from unencrypted
    channels (SMS / Cellular Call) to encrypted channels (Signal / WhatsApp)
    within a short time window.
    """
    switches = []
    unenc_events = [e for e in events if "SMS" in e.app or "Calls" in e.app]
    enc_events = [e for e in events if "Signal" in e.app or "WhatsApp" in e.app]

    max_gap_sec = max_gap_hours * 3600

    for u_ev in unenc_events:
        u_contact = normalize_contact_identifier(u_ev.sender if "Target" not in u_ev.sender else u_ev.recipient)
        if not u_contact:
            continue

        for e_ev in enc_events:
            e_contact = normalize_contact_identifier(e_ev.sender if "Target" not in e_ev.sender else e_ev.recipient)
            if u_contact == e_contact and 0 < (e_ev.timestamp_epoch - u_ev.timestamp_epoch) <= max_gap_sec:
                switches.append({
                    "contact": u_contact,
                    "unencrypted_event": u_ev.to_dict(),
                    "encrypted_event": e_ev.to_dict(),
                    "time_gap_minutes": round((e_ev.timestamp_epoch - u_ev.timestamp_epoch) / 60.0, 1),
                    "switch_description": f"Switched from {u_ev.app} to {e_ev.app} with {u_contact}",
                })
    return switches


# ==============================================================================
# Master Timeline Aggregation Orchestrator
# ==============================================================================

def extract_unified_timeline(
    evidence_directory: Path | str,
    max_records: int = 15000,
) -> List[TimelineEvent]:
    """
    Backwards-compatible API for consolidated_db and entity_recognition.
    Extracts all messaging, calls, notes, photos, and web visits into a sorted list.
    """
    res = extract_master_timeline(evidence_directory, max_records=max_records)
    return res.get("events", [])


def extract_master_timeline(
    evidence_directory: Path | str,
    geo_points: Optional[List[Any]] = None,
    carved_records: Optional[List[Any]] = None,
    max_records: int = 25000,
) -> Dict[str, Any]:
    """
    Primary orchestrator for Option 4:
    Scans directory for all supported iOS SQLite databases, incorporates
    geospatial waypoints and carved deleted records, and runs cross-application
    correlation and multi-channel burst detection.
    """
    p = Path(evidence_directory).resolve()
    all_events: List[TimelineEvent] = []

    if p.is_dir():
        db_files = list(p.rglob("*.sqlite")) + list(p.rglob("*.db")) + list(p.rglob("*.storedata"))
        for db in db_files:
            name_lower = db.name.lower()
            if name_lower.endswith(("-wal", "-shm")):
                continue

            if "chatstorage" in name_lower or "whatsapp" in name_lower:
                all_events.extend(extract_whatsapp_events(db))
            elif "signal" in name_lower:
                all_events.extend(extract_signal_events(db))
            elif "sms.db" in name_lower or (name_lower.startswith("sms") and name_lower.endswith(".db")):
                all_events.extend(extract_sms_events(db))
            elif "callhistory" in name_lower:
                all_events.extend(extract_call_history_events(db))
            elif "notestore" in name_lower or "notes.sqlite" in name_lower:
                all_events.extend(extract_notes_events(db))
            elif "photos.sqlite" in name_lower:
                all_events.extend(extract_photos_events(db))
            elif "wechat" in name_lower or "wcdb" in name_lower:
                all_events.extend(extract_wechat_events(db))
            elif "history" in name_lower or "safari" in name_lower:
                all_events.extend(extract_safari_events(db))

    # Incorporate geospatial waypoints if provided
    if geo_points:
        all_events.extend(convert_geopoints_to_timeline(geo_points))

    # Incorporate carved deleted records if provided
    if carved_records:
        all_events.extend(convert_carved_records_to_timeline(carved_records))

    # Sort strictly by timestamp_epoch ascending (carved with 0.0 epoch go to bottom or top)
    all_events.sort(key=lambda x: (x.timestamp_epoch > 0, x.timestamp_epoch))

    truncated = all_events[:max_records]

    # Run cross-app burst detection and identity correlation
    clusters = detect_cross_app_bursts(truncated)
    identities = correlate_cross_app_identities(truncated)
    switches = detect_app_switching(truncated)

    # Compute summary metrics
    apps_found = sorted(list(set(e.app for e in truncated)))
    valid_epochs = [e.timestamp_epoch for e in truncated if e.timestamp_epoch > 10000000]
    time_span = "N/A"
    if valid_epochs:
        min_dt = _format_epoch(min(valid_epochs))
        max_dt = _format_epoch(max(valid_epochs))
        time_span = f"{min_dt[:10]} -> {max_dt[:10]}"

    return {
        "events": truncated,
        "total_events": len(truncated),
        "clusters": clusters,
        "identities": identities,
        "app_switches": switches,
        "summary": {
            "total_events": len(truncated),
            "applications": apps_found,
            "app_count": len(apps_found),
            "time_span": time_span,
            "burst_count": len(clusters),
            "unique_identities": len(identities),
            "deleted_events": sum(1 for e in truncated if e.is_deleted),
        }
    }


# ==============================================================================
# Interactive Master Timeline HTML Dashboard Generator
# ==============================================================================

def generate_master_timeline_html(
    events: List[TimelineEvent],
    clusters: Optional[List[CorrelationCluster]] = None,
    out_path: Optional[Path | str] = None,
    title: str = "iOS Forensic Master Cross-Application Timeline",
) -> str:
    """
    Generates a standalone, rich, responsive HTML interactive master timeline.
    Works 100% offline with zero external dependencies.
    """
    events_json = json.dumps([e.to_dict() for e in events])
    clusters_json = json.dumps([c.to_dict() for c in (clusters or [])])

    app_list = sorted(list(set(e.app for e in events)))
    app_badges_html = " ".join([f'<span class="app-pill" onclick="filterApp(\'{html.escape(a)}\')">{html.escape(a)}</span>' for a in app_list])

    valid_epochs = [e.timestamp_epoch for e in events if e.timestamp_epoch > 10000000]
    start_t = _format_epoch(min(valid_epochs)) if valid_epochs else "N/A"
    end_t = _format_epoch(max(valid_epochs)) if valid_epochs else "N/A"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #131b2e;
            --surface-card: #1a243c;
            --border: #233152;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-purple: #8b5cf6;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
        }}
        * {{ box-sizing: border-box; margin:0; padding:0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            padding: 20px;
            font-size: 14px;
        }}
        header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        h1 {{ font-size: 1.4rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }}
        .hud {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }}
        .hud-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 18px;
        }}
        .hud-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
        .hud-val {{ font-size: 1.4rem; font-weight: 700; color: var(--accent-blue); margin-top: 4px; }}
        .controls-bar {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 240px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-main);
            outline: none;
            font-size: 0.9rem;
        }}
        .search-box:focus {{ border-color: var(--accent-blue); }}
        .app-pills {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
        .app-pill {{
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 4px 12px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .app-pill.active, .app-pill:hover {{
            background: var(--accent-blue);
            color: #ffffff;
            border-color: var(--accent-blue);
        }}
        .stream-container {{
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        .event-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 4px solid var(--accent-blue);
            border-radius: 8px;
            padding: 14px 18px;
            display: grid;
            grid-template-columns: 140px 180px 1fr 120px;
            gap: 16px;
            align-items: center;
            transition: background 0.15s;
            cursor: pointer;
        }}
        .event-card:hover {{
            background: var(--surface-card);
        }}
        .event-card.deleted {{
            border-left-color: var(--accent-red);
            background: rgba(239, 68, 68, 0.05);
        }}
        .event-card.burst {{
            border-left-color: var(--accent-amber);
        }}
        .col-app {{ font-weight: 600; display: flex; align-items: center; gap: 6px; }}
        .col-time {{ color: var(--text-muted); font-size: 0.85rem; font-family: monospace; }}
        .col-content {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .col-parties {{ font-size: 0.8rem; color: var(--text-muted); }}
        .badge {{
            display: inline-block;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-del {{ background: #dc2626; color: #fff; }}
        .badge-geo {{ background: #059669; color: #fff; }}
        .badge-burst {{ background: #d97706; color: #fff; }}

        /* Modal Inspector */
        .modal-bg {{
            display: none;
            position: fixed;
            top:0; left:0; width:100%; height:100%;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .modal {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            max-width: 680px;
            width: 90%;
            max-height: 85vh;
            overflow-y: auto;
            padding: 24px;
            position: relative;
        }}
        .modal-close {{
            position: absolute;
            top: 16px; right: 18px;
            cursor: pointer;
            font-size: 1.4rem;
            color: var(--text-muted);
        }}
        .modal pre {{
            background: var(--bg);
            padding: 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.85rem;
            margin-top: 10px;
        }}
    </style>
</head>
<body>

    <header>
        <div>
            <h1>⏱️ {html.escape(title)}</h1>
            <p style="color:var(--text-muted); font-size:0.9rem; margin-top:4px;">
                Unified chronological evidence stream fusing WhatsApp, Signal, SMS/iMessage, Calls, Photos, and GPS fixes.
            </p>
        </div>
        <div style="display:flex; gap:8px;">
            <button onclick="exportCSV()" style="background:var(--surface-card); border:1px solid var(--border); color:#fff; padding:8px 14px; border-radius:6px; cursor:pointer; font-weight:600;">📊 Export CSV</button>
            <button onclick="exportJSON()" style="background:var(--accent-blue); border:none; color:#fff; padding:8px 14px; border-radius:6px; cursor:pointer; font-weight:600;">📥 Export JSON</button>
        </div>
    </header>

    <div class="hud">
        <div class="hud-card">
            <div class="hud-title">Total Chronological Events</div>
            <div class="hud-val">{len(events):,}</div>
        </div>
        <div class="hud-card">
            <div class="hud-title">Disparate Applications</div>
            <div class="hud-val" style="color:var(--accent-green);">{len(app_list)}</div>
        </div>
        <div class="hud-card">
            <div class="hud-title">Multi-App Bursts</div>
            <div class="hud-val" style="color:var(--accent-amber);">{len(clusters or []):,}</div>
        </div>
        <div class="hud-card">
            <div class="hud-title">Investigation Time Range</div>
            <div class="hud-val" style="font-size:0.95rem; line-height:1.4; color:var(--text-main); margin-top:8px;">
                {start_t[:10]} &rarr; {end_t[:10]}
            </div>
        </div>
    </div>

    <div class="controls-bar">
        <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search messages, participants, URLs, content, or coordinates..." oninput="filterEvents()">
        <div class="app-pills">
            <span class="app-pill active" onclick="filterApp('ALL')">ALL APPS</span>
            {app_badges_html}
        </div>
        <label style="color:var(--text-muted); font-size:0.85rem; display:flex; align-items:center; gap:6px; cursor:pointer; margin-left:auto;">
            <input type="checkbox" id="burstOnlyCheck" onchange="filterEvents()"> 🔥 Bursts Only
        </label>
        <label style="color:var(--text-muted); font-size:0.85rem; display:flex; align-items:center; gap:6px; cursor:pointer;">
            <input type="checkbox" id="deletedOnlyCheck" onchange="filterEvents()"> 🚨 Carved Only
        </label>
    </div>

    <div id="streamList" class="stream-container">
        <!-- Rendered dynamically -->
    </div>

    <div id="eventModalBg" class="modal-bg" onclick="closeModal(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h2 id="modalTitle" style="margin-bottom:12px; font-size:1.2rem;"></h2>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        const rawEvents = {events_json};
        const rawClusters = {clusters_json};
        let activeApp = 'ALL';

        function renderEvents(items) {{
            const container = document.getElementById('streamList');
            container.innerHTML = '';

            if (items.length === 0) {{
                container.innerHTML = '<div style="text-align:center; padding:40px; color:var(--text-muted);">No forensic events match the selected criteria.</div>';
                return;
            }}

            const maxRender = 1000;
            const slice = items.slice(0, maxRender);

            slice.forEach((ev, idx) => {{
                const card = document.createElement('div');
                card.className = 'event-card' + (ev.is_deleted ? ' deleted' : '');
                card.onclick = () => openModal(ev);

                let badgeHtml = '';
                if (ev.is_deleted) badgeHtml += '<span class="badge badge-del">CARVED</span> ';
                if (ev.latitude && ev.longitude) badgeHtml += '<span class="badge badge-geo">GPS</span> ';

                card.innerHTML = `
                    <div class="col-app">${{ev.app_icon}} ${{escapeHtml(ev.app)}}</div>
                    <div class="col-time">${{escapeHtml(ev.timestamp_utc)}}</div>
                    <div class="col-content">
                        ${{badgeHtml}}
                        <span style="font-weight:600;">${{escapeHtml(ev.sender)}} &rarr; ${{escapeHtml(ev.recipient)}}:</span>
                        ${{escapeHtml(ev.content)}}
                    </div>
                    <div class="col-parties" style="text-align:right;">${{escapeHtml(ev.event_type)}}</div>
                `;
                container.appendChild(card);
            }});

            if (items.length > maxRender) {{
                const note = document.createElement('div');
                note.style = 'text-align:center; padding:12px; color:var(--text-muted); font-size:0.85rem;';
                note.textContent = `Showing first ${{maxRender}} of ${{items.length}} events. Filter to narrow down.`;
                container.appendChild(note);
            }}
        }}

        function filterApp(app) {{
            activeApp = app;
            document.querySelectorAll('.app-pill').forEach(el => {{
                el.classList.toggle('active', el.textContent.trim().toUpperCase() === app.toUpperCase() || (app === 'ALL' && el.textContent.trim() === 'ALL APPS'));
            }});
            filterEvents();
        }}

        function filterEvents() {{
            const q = document.getElementById('searchInput').value.toLowerCase().trim();
            const burstOnly = document.getElementById('burstOnlyCheck').checked;
            const delOnly = document.getElementById('deletedOnlyCheck').checked;

            const filtered = rawEvents.filter(ev => {{
                if (activeApp !== 'ALL' && ev.app !== activeApp) return false;
                if (delOnly && !ev.is_deleted) return false;
                if (q) {{
                    const full = (ev.sender + ' ' + ev.recipient + ' ' + ev.content + ' ' + ev.app + ' ' + ev.source_database).toLowerCase();
                    if (!full.includes(q)) return false;
                }}
                return true;
            }});

            renderEvents(filtered);
        }}

        function openModal(ev) {{
            document.getElementById('modalTitle').innerHTML = `${{ev.app_icon}} ${{escapeHtml(ev.app)}} Event: ${{escapeHtml(ev.event_id)}}`;
            const body = document.getElementById('modalBody');
            body.innerHTML = `
                <table style="width:100%; border-collapse:collapse; margin-bottom:14px; font-size:0.9rem;">
                    <tr><td style="color:var(--text-muted); padding:4px 0; width:130px;">Timestamp (UTC):</td><td><b>${{escapeHtml(ev.timestamp_utc)}}</b> (Epoch: ${{ev.timestamp_epoch}})</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Event Type:</td><td>${{escapeHtml(ev.event_type)}}</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Sender:</td><td>${{escapeHtml(ev.sender)}}</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Recipient:</td><td>${{escapeHtml(ev.recipient)}}</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Source Database:</td><td><code>${{escapeHtml(ev.source_database)}}</code> (Table: <code>${{escapeHtml(ev.source_table)}}</code>)</td></tr>
                    ${{ev.latitude ? `<tr><td style="color:var(--text-muted); padding:4px 0;">GPS Coordinates:</td><td>${{ev.latitude.toFixed(6)}}, ${{ev.longitude.toFixed(6)}}</td></tr>` : ''}}
                </table>
                <div style="margin-top:10px;">
                    <div style="font-weight:600; margin-bottom:4px;">Full Message / Content:</div>
                    <div style="background:var(--bg); border:1px solid var(--border); padding:10px; border-radius:6px; font-family:monospace; white-space:pre-wrap;">${{escapeHtml(ev.content)}}</div>
                </div>
                <div style="margin-top:14px;">
                    <div style="font-weight:600; margin-bottom:4px;">Metadata & Forensic Evidence:</div>
                    <pre>${{JSON.stringify(ev.metadata, null, 2)}}</pre>
                </div>
            `;
            document.getElementById('eventModalBg').style.display = 'flex';
        }}

        function closeModal() {{
            document.getElementById('eventModalBg').style.display = 'none';
        }}

        function escapeHtml(s) {{
            if (!s) return '';
            return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }}

        function exportCSV() {{
            window.location.href = 'timeline.csv';
        }}

        function exportJSON() {{
            window.location.href = 'timeline.json';
        }}

        // Initial render
        renderEvents(rawEvents);
    </script>
</body>
</html>
"""
    if out_path:
        out_file = Path(out_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html_content)

    return html_content


# ==============================================================================
# Multi-Format Forensic Exporters
# ==============================================================================

def export_timeline_json(
    events: List[TimelineEvent],
    out_path: Path | str,
    clusters: Optional[List[CorrelationCluster]] = None,
) -> None:
    """Exports the unified timeline and correlation clusters to a structured JSON file."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "total_events": len(events),
        "total_clusters": len(clusters or []),
        "events": [e.to_dict() for e in events],
        "clusters": [c.to_dict() for c in (clusters or [])],
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_timeline_csv(events: List[TimelineEvent], out_path: Path | str) -> None:
    """Exports events to a Plaso / Log2Timeline compatible CSV file."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "Event ID",
        "Timestamp (UTC)",
        "Timestamp (Epoch)",
        "Application",
        "Event Type",
        "Sender",
        "Recipient",
        "Content",
        "Source Database",
        "Source Table",
        "Latitude",
        "Longitude",
        "Is Deleted",
    ]

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for e in events:
            lat = f"{e.latitude:.6f}" if e.latitude is not None else ""
            lon = f"{e.longitude:.6f}" if e.longitude is not None else ""
            clean_content = str(e.content).replace('"', '""').replace("\n", " ")
            row = [
                f'"{e.event_id}"',
                f'"{e.timestamp_utc}"',
                str(e.timestamp_epoch),
                f'"{e.app}"',
                f'"{e.event_type}"',
                f'"{e.sender}"',
                f'"{e.recipient}"',
                f'"{clean_content}"',
                f'"{e.source_database}"',
                f'"{e.source_table}"',
                lat,
                lon,
                "YES" if e.is_deleted else "NO",
            ]
            f.write(",".join(row) + "\n")
