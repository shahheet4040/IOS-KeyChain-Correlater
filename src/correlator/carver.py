"""
Forensic SQLite Deleted Data, Freelist & Slack Space Carver
===========================================================
Recovers deleted records, unlinked cells, and residual evidence from:
- SQLite Leaf B-Tree Freeblocks (internal deleted cell linked list)
- Unallocated Page Slack Space (gaps between cell pointers and cell content)
- Database Freelist Trunk and Leaf Pages (deallocated tables and rows)
- Companion WAL Files (superseded and orphaned historical write frames)

Uses a hybrid forensic approach:
1. Low-level structured B-Tree record parsing for intact deleted cells.
2. Slack space and unallocated page artifact carving for partially overwritten cells.
Filters out active live rows to prevent false positive deletion flags.
"""

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class DeletedRecord:
    record_id: str
    database: str
    page_num: int
    offset_in_page: int
    source_type: str  # "freeblock", "unallocated_slack", "freelist", "wal_frame"
    table_hint: Optional[str] = None
    rowid_hint: Optional[int] = None
    columns: List[Any] = field(default_factory=list)
    raw_text: str = ""
    confidence: float = 0.85
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# Low-Level SQLite Varint & Record Decoding
# ==============================================================================

def read_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Reads a variable-length integer (1 to 9 bytes) according to the SQLite specification."""
    val = 0
    for i in range(8):
        if offset >= len(data):
            return val, offset
        b = data[offset]
        offset += 1
        val = (val << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            return val, offset

    if offset < len(data):
        b = data[offset]
        offset += 1
        val = (val << 8) | b
    return val, offset


def parse_sqlite_record(data: bytes, offset: int = 0) -> Optional[Tuple[List[Any], int]]:
    """
    Attempts to decode a SQLite Record Header and its column values starting at offset.
    Returns (columns_list, bytes_consumed) on success, or None if invalid.
    """
    if offset >= len(data) - 2:
        return None

    orig_offset = offset
    hdr_size, cur = read_varint(data, offset)
    if hdr_size < 2 or hdr_size > 512 or cur + hdr_size - (cur - orig_offset) > len(data):
        return None

    hdr_end = orig_offset + hdr_size
    serial_types = []

    # Read serial types from header
    while cur < hdr_end:
        st, cur = read_varint(data, cur)
        serial_types.append(st)

    if not serial_types or len(serial_types) > 100:
        return None

    columns = []
    val_cur = hdr_end

    for st in serial_types:
        if st == 0:
            columns.append(None)
        elif st == 1:
            if val_cur + 1 > len(data):
                return None
            val = struct.unpack(">b", data[val_cur:val_cur + 1])[0]
            columns.append(val)
            val_cur += 1
        elif st == 2:
            if val_cur + 2 > len(data):
                return None
            val = struct.unpack(">h", data[val_cur:val_cur + 2])[0]
            columns.append(val)
            val_cur += 2
        elif st == 3:
            if val_cur + 3 > len(data):
                return None
            val_bytes = data[val_cur:val_cur + 3]
            val = int.from_bytes(val_bytes, byteorder="big", signed=True)
            columns.append(val)
            val_cur += 3
        elif st == 4:
            if val_cur + 4 > len(data):
                return None
            val = struct.unpack(">i", data[val_cur:val_cur + 4])[0]
            columns.append(val)
            val_cur += 4
        elif st == 5:
            if val_cur + 6 > len(data):
                return None
            val_bytes = data[val_cur:val_cur + 6]
            val = int.from_bytes(val_bytes, byteorder="big", signed=True)
            columns.append(val)
            val_cur += 6
        elif st == 6:
            if val_cur + 8 > len(data):
                return None
            val = struct.unpack(">q", data[val_cur:val_cur + 8])[0]
            columns.append(val)
            val_cur += 8
        elif st == 7:
            if val_cur + 8 > len(data):
                return None
            val = struct.unpack(">d", data[val_cur:val_cur + 8])[0]
            columns.append(val)
            val_cur += 8
        elif st == 8:
            columns.append(0)
        elif st == 9:
            columns.append(1)
        elif st in (10, 11):
            return None
        elif st >= 12 and st % 2 == 0:
            blob_len = (st - 12) // 2
            if val_cur + blob_len > len(data):
                return None
            columns.append(f"<BLOB {blob_len}B>")
            val_cur += blob_len
        elif st >= 13 and st % 2 == 1:
            text_len = (st - 13) // 2
            if val_cur + text_len > len(data):
                return None
            try:
                text_bytes = data[val_cur:val_cur + text_len]
                text_str = text_bytes.decode("utf-8")
                columns.append(text_str)
            except Exception:
                return None
            val_cur += text_len

    bytes_consumed = val_cur - orig_offset
    return columns, bytes_consumed


def carve_regex_artifacts(data: bytes, min_len: int = 5) -> List[Dict[str, Any]]:
    """Carves phone numbers, URLs, email addresses, and UTF-8 chat messages from raw unparsed slack."""
    artifacts = []
    text_pattern = re.compile(rb"[\x20-\x7E\r\n\t]{" + str(min_len).encode() + rb",}")
    email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    phone_pattern = re.compile(r"\+?[1-9]\d{1,14}")

    for match in text_pattern.finditer(data):
        raw_val = match.group(0).decode("latin-1", errors="ignore").strip()
        # Clean leading control characters / remnants of serial headers
        cleaned = re.sub(r"^[\x00-\x1F\x7F]+", "", raw_val).strip()
        if len(cleaned) >= min_len:
            art_type = "string"
            if email_pattern.search(cleaned):
                art_type = "email"
            elif phone_pattern.search(cleaned):
                art_type = "phone"
            elif "http://" in cleaned or "https://" in cleaned:
                art_type = "url"

            artifacts.append({
                "offset": match.start(),
                "type": art_type,
                "content": cleaned[:200],
            })
    return artifacts


# ==============================================================================
# Page Freeblock & Slack Space Carving
# ==============================================================================

def extract_page_freeblocks(page_bytes: bytes, page_num: int, db_name: str) -> List[DeletedRecord]:
    """Traverses freeblocks inside a B-Tree page."""
    records = []
    if len(page_bytes) < 8:
        return records

    hdr_offset = 100 if page_num == 1 else 0
    if len(page_bytes) < hdr_offset + 8:
        return records

    page_type = page_bytes[hdr_offset]
    if page_type not in (0x0D, 0x05, 0x0A, 0x02):
        return records

    first_freeblock = struct.unpack(">H", page_bytes[hdr_offset + 1:hdr_offset + 3])[0]
    cur_fb = first_freeblock
    visited = set()

    while cur_fb > 0 and cur_fb < len(page_bytes) - 4:
        if cur_fb in visited:
            break
        visited.add(cur_fb)

        next_fb, fb_size = struct.unpack(">HH", page_bytes[cur_fb:cur_fb + 4])
        if fb_size < 4 or cur_fb + fb_size > len(page_bytes):
            break

        fb_payload = page_bytes[cur_fb + 4:cur_fb + fb_size]
        found_structured = False

        # 1. Try structured record parsing
        for off in range(max(0, len(fb_payload) - 6)):
            rec_res = parse_sqlite_record(fb_payload, off)
            if rec_res:
                cols, _ = rec_res
                has_text = any(isinstance(c, str) and len(c.strip("\x00 \t\r\n")) > 1 and any(ch.isalnum() for ch in c) for c in cols)
                if has_text:
                    preview = " | ".join(str(c) for c in cols if c is not None)
                    records.append(DeletedRecord(
                        record_id=f"CARVED-FB-P{page_num}-OFF{cur_fb + 4 + off}",
                        database=db_name,
                        page_num=page_num,
                        offset_in_page=cur_fb + 4 + off,
                        source_type="freeblock",
                        columns=cols,
                        raw_text=preview[:180],
                        confidence=0.90,
                        metadata={"freeblock_size": fb_size},
                    ))
                    found_structured = True

        # 2. Slack text fallback
        if not found_structured:
            arts = carve_regex_artifacts(fb_payload, min_len=6)
            for a in arts:
                records.append(DeletedRecord(
                    record_id=f"CARVED-FB-STR-P{page_num}-OFF{cur_fb + 4 + a['offset']}",
                    database=db_name,
                    page_num=page_num,
                    offset_in_page=cur_fb + 4 + a["offset"],
                    source_type="freeblock",
                    columns=[a["content"]],
                    raw_text=a["content"],
                    confidence=0.80,
                    metadata={"artifact_type": a["type"]},
                ))

        cur_fb = next_fb

    return records


def extract_unallocated_slack(page_bytes: bytes, page_num: int, db_name: str) -> List[DeletedRecord]:
    """Carves deleted data from the unallocated gap between the cell pointer array and cell content area."""
    records = []
    hdr_offset = 100 if page_num == 1 else 0
    if len(page_bytes) < hdr_offset + 8:
        return records

    page_type = page_bytes[hdr_offset]
    if page_type != 0x0D:
        return records

    num_cells = struct.unpack(">H", page_bytes[hdr_offset + 3:hdr_offset + 5])[0]
    cell_content_offset = struct.unpack(">H", page_bytes[hdr_offset + 5:hdr_offset + 7])[0]
    if cell_content_offset == 0:
        cell_content_offset = 65536

    cell_ptr_end = hdr_offset + 8 + (num_cells * 2)
    if cell_ptr_end < cell_content_offset and cell_content_offset <= len(page_bytes):
        slack_bytes = page_bytes[cell_ptr_end:cell_content_offset]
        if len(slack_bytes) >= 8:
            # 1. Structured record carving
            idx = 0
            while idx < len(slack_bytes) - 6:
                rec_res = parse_sqlite_record(slack_bytes, idx)
                if rec_res:
                    cols, consumed = rec_res
                    has_text = any(isinstance(c, str) and len(c.strip("\x00 \t\r\n")) > 2 and any(ch.isalnum() for ch in c) for c in cols)
                    if has_text:
                        preview = " | ".join(str(c) for c in cols if c is not None)
                        records.append(DeletedRecord(
                            record_id=f"CARVED-SLACK-P{page_num}-OFF{cell_ptr_end + idx}",
                            database=db_name,
                            page_num=page_num,
                            offset_in_page=cell_ptr_end + idx,
                            source_type="unallocated_slack",
                            columns=cols,
                            raw_text=preview[:180],
                            confidence=0.88,
                            metadata={"slack_size": len(slack_bytes)},
                        ))
                        idx += max(consumed, 4)
                        continue
                idx += 1

            # 2. Text artifact carving across slack
            arts = carve_regex_artifacts(slack_bytes, min_len=6)
            for a in arts:
                txt = a["content"]
                # Skip if already captured in structured records
                if not any(txt in r.raw_text for r in records):
                    records.append(DeletedRecord(
                        record_id=f"CARVED-SLACK-STR-P{page_num}-OFF{cell_ptr_end + a['offset']}",
                        database=db_name,
                        page_num=page_num,
                        offset_in_page=cell_ptr_end + a["offset"],
                        source_type="unallocated_slack",
                        columns=[txt],
                        raw_text=txt,
                        confidence=0.82,
                        metadata={"artifact_type": a["type"]},
                    ))

    return records


# ==============================================================================
# Freelist Page Walking
# ==============================================================================

def extract_freelist_records(db_bytes: bytes, page_size: int, db_name: str) -> List[DeletedRecord]:
    """Walks the SQLite Freelist trunk and leaf pages to recover entire deleted records."""
    records = []
    if len(db_bytes) < 100:
        return records

    first_trunk = struct.unpack(">I", db_bytes[36:40])[0]
    freelist_count = struct.unpack(">I", db_bytes[32:36])[0]

    if first_trunk == 0 or freelist_count == 0:
        return records

    cur_trunk = first_trunk
    visited_trunks = set()

    while cur_trunk > 0 and cur_trunk not in visited_trunks:
        visited_trunks.add(cur_trunk)
        trunk_off = (cur_trunk - 1) * page_size
        if trunk_off + page_size > len(db_bytes):
            break

        trunk_data = db_bytes[trunk_off:trunk_off + page_size]
        next_trunk, num_leaves = struct.unpack(">II", trunk_data[:8])

        for leaf_idx in range(num_leaves):
            leaf_ptr_off = 8 + (leaf_idx * 4)
            if leaf_ptr_off + 4 > len(trunk_data):
                break
            leaf_pg = struct.unpack(">I", trunk_data[leaf_ptr_off:leaf_ptr_off + 4])[0]
            leaf_off = (leaf_pg - 1) * page_size
            if leaf_off + page_size > len(db_bytes):
                continue

            leaf_bytes = db_bytes[leaf_off:leaf_off + page_size]
            # Structured carving
            idx = 0
            while idx < len(leaf_bytes) - 6:
                rec_res = parse_sqlite_record(leaf_bytes, idx)
                if rec_res:
                    cols, consumed = rec_res
                    has_text = any(isinstance(c, str) and len(c.strip("\x00 \t\r\n")) > 2 and any(ch.isalnum() for ch in c) for c in cols)
                    if has_text:
                        preview = " | ".join(str(c) for c in cols if c is not None)
                        records.append(DeletedRecord(
                            record_id=f"CARVED-FREELIST-P{leaf_pg}-OFF{idx}",
                            database=db_name,
                            page_num=leaf_pg,
                            offset_in_page=idx,
                            source_type="freelist",
                            columns=cols,
                            raw_text=preview[:180],
                            confidence=0.92,
                            metadata={"leaf_page": leaf_pg},
                        ))
                        idx += max(consumed, 4)
                        continue
                idx += 1

            # Text artifact fallback
            arts = carve_regex_artifacts(leaf_bytes, min_len=6)
            for a in arts:
                txt = a["content"]
                if not any(txt in r.raw_text for r in records):
                    records.append(DeletedRecord(
                        record_id=f"CARVED-FREELIST-STR-P{leaf_pg}-OFF{a['offset']}",
                        database=db_name,
                        page_num=leaf_pg,
                        offset_in_page=a["offset"],
                        source_type="freelist",
                        columns=[txt],
                        raw_text=txt,
                        confidence=0.85,
                        metadata={"leaf_page": leaf_pg, "artifact_type": a["type"]},
                    ))

        cur_trunk = next_trunk

    return records


# ==============================================================================
# End-to-End Forensic SQLite Carver
# ==============================================================================

def carve_sqlite_database(db_path: Path | str, wal_path: Optional[Path | str] = None) -> List[DeletedRecord]:
    """
    Forensically inspects an SQLite database to carve deleted rows from:
    1. Freeblocks in all table leaf pages
    2. Unallocated slack space between cell pointers and cell bodies
    3. Deallocated freelist trunk and leaf pages
    4. Companion WAL write frames
    Deduplicates results against active database rows so active data is not mislabeled.
    """
    p = Path(db_path).resolve()
    if not p.is_file():
        return []

    try:
        with open(p, "rb") as f:
            raw_db = f.read()
    except Exception:
        return []

    if len(raw_db) < 100 or not raw_db.startswith(b"SQLite format 3\x00"):
        return []

    raw_ps = struct.unpack(">H", raw_db[16:18])[0]
    page_size = 65536 if raw_ps == 1 else (raw_ps if raw_ps > 0 else 4096)
    total_pages = len(raw_db) // page_size

    # 1. Fetch active records to avoid reporting live data as deleted
    active_texts: Set[str] = set()
    try:
        con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]
        for tbl in tables:
            try:
                cur.execute(f"SELECT * FROM [{tbl}] LIMIT 1000;")
                for r in cur.fetchall():
                    for val in r:
                        if isinstance(val, str) and len(val.strip()) > 3:
                            active_texts.add(val.strip().lower())
            except Exception:
                pass
        con.close()
    except Exception:
        pass

    all_carved: List[DeletedRecord] = []

    # 2. Carve Freeblocks & Unallocated Slack Page-by-Page
    for pg_idx in range(1, total_pages + 1):
        pg_start = (pg_idx - 1) * page_size
        pg_bytes = raw_db[pg_start:pg_start + page_size]

        # Freeblocks
        fb_recs = extract_page_freeblocks(pg_bytes, pg_idx, p.name)
        all_carved.extend(fb_recs)

        # Unallocated Slack
        slack_recs = extract_unallocated_slack(pg_bytes, pg_idx, p.name)
        all_carved.extend(slack_recs)

    # 3. Carve Freelist Pages
    freelist_recs = extract_freelist_records(raw_db, page_size, p.name)
    all_carved.extend(freelist_recs)

    # 4. Filter out active records & clean previews
    truly_deleted: List[DeletedRecord] = []
    seen_previews: Set[str] = set()

    for rec in all_carved:
        # Check if record text matches active tables
        is_active = False
        for col in rec.columns:
            if isinstance(col, str) and col.strip().lower() in active_texts:
                is_active = True
                break
        if is_active:
            continue

        # Clean preview text
        clean_text = rec.raw_text.strip("\x00 \t\r\n|")
        # Remove unprintable / non-ascii prefix control characters
        clean_text = re.sub(r"^[\x00-\x1F\x7F]+", "", clean_text).strip()
        rec.raw_text = clean_text

        norm_prev = clean_text.lower()
        if norm_prev in seen_previews or len(norm_prev) < 4 or not any(ch.isalnum() for ch in norm_prev):
            continue
        seen_previews.add(norm_prev)
        truly_deleted.append(rec)

    # 5. Scan companion WAL file if available
    target_wal = Path(wal_path) if wal_path else p.with_name(p.name + "-wal")
    if target_wal.is_file():
        try:
            with open(target_wal, "rb") as wf:
                raw_wal = wf.read()
            if len(raw_wal) >= 32 and struct.unpack(">I", raw_wal[:4])[0] in (0x377F0682, 0x377F0683):
                frame_hdr_size = 24
                frame_total = (len(raw_wal) - 32) // (frame_hdr_size + page_size)
                for f_idx in range(frame_total):
                    f_off = 32 + (f_idx * (frame_hdr_size + page_size))
                    pgno = struct.unpack(">I", raw_wal[f_off:f_off + 4])[0]
                    f_payload = raw_wal[f_off + frame_hdr_size:f_off + frame_hdr_size + page_size]

                    fb_wal = extract_page_freeblocks(f_payload, pgno, f"{p.name}-wal")
                    slack_wal = extract_unallocated_slack(f_payload, pgno, f"{p.name}-wal")
                    for r in fb_wal + slack_wal:
                        r.source_type = "wal_frame"
                        clean_w = re.sub(r"^[\x00-\x1F\x7F]+", "", r.raw_text.strip()).strip()
                        r.raw_text = clean_w
                        norm_w = clean_w.lower()
                        if norm_w not in seen_previews and len(norm_w) >= 4 and norm_w not in active_texts:
                            seen_previews.add(norm_w)
                            truly_deleted.append(r)
        except Exception:
            pass

    return truly_deleted


def carve_directory_databases(directory_path: Path | str) -> Dict[str, List[DeletedRecord]]:
    """Recursively scans a directory for SQLite databases and carves deleted data from all of them."""
    root = Path(directory_path).resolve()
    results: Dict[str, List[DeletedRecord]] = {}
    if not root.is_dir():
        return results

    db_files = list(root.rglob("*.sqlite")) + list(root.rglob("*.db"))
    for db in db_files:
        if db.name.endswith("-wal") or db.name.endswith("-shm"):
            continue
        carved = carve_sqlite_database(db)
        if carved:
            results[str(db.relative_to(root))] = carved

    return results


# ==============================================================================
# Export Utilities
# ==============================================================================

def export_carved_json(records_dict: Dict[str, List[DeletedRecord]] | List[DeletedRecord], out_path: Path | str) -> None:
    """Exports carved deleted records to a structured JSON file."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(records_dict, list):
        data = [r.to_dict() for r in records_dict]
    else:
        data = {k: [r.to_dict() for r in v] for k, v in records_dict.items()}

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_carved_csv(records: List[DeletedRecord], out_path: Path | str) -> None:
    """Exports carved deleted records to CSV spreadsheet."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "Record ID",
        "Database",
        "Page Number",
        "Offset In Page",
        "Source Type",
        "Confidence",
        "Raw Text Preview",
        "Columns Parsed",
    ]

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for r in records:
            cols_clean = " ; ".join(str(c) for c in r.columns if c is not None)
            row = [
                f'"{r.record_id}"',
                f'"{r.database}"',
                str(r.page_num),
                str(r.offset_in_page),
                f'"{r.source_type}"',
                f"{r.confidence:.2f}",
                f'"{r.raw_text.replace(chr(34), chr(39))}"',
                f'"{cols_clean.replace(chr(34), chr(39))}"',
            ]
            f.write(",".join(row) + "\n")
