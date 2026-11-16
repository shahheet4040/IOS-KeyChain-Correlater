from dataclasses import dataclass
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

WAL_MAGICS = (0x377F0682, 0x377F0683)
WAL_MAGIC_BE = 0x377F0682
WAL_MAGIC_LE = 0x377F0683
VALID_MAGICS = set(WAL_MAGICS)


@dataclass
class WalHeader:
    magic: int
    file_format: int
    page_size: int
    checkpoint_seq: int
    salt_1: int
    salt_2: int
    checksum_1: int
    checksum_2: int
    is_valid: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "magic": hex(self.magic),
            "file_format": self.file_format,
            "page_size": self.page_size,
            "checkpoint_seq": self.checkpoint_seq,
            "salt_1": hex(self.salt_1),
            "salt_2": hex(self.salt_2),
            "checksum_1": hex(self.checksum_1),
            "checksum_2": hex(self.checksum_2),
            "is_valid": self.is_valid,
        }


@dataclass
class WalFrame:
    frame_index: int
    offset: int
    pgno: int
    db_size: int
    is_commit: bool
    salt_1: int
    salt_2: int
    checksum_1: int
    checksum_2: int
    is_valid: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frame_index": self.frame_index,
            "offset": self.offset,
            "pgno": self.pgno,
            "db_size": self.db_size,
            "is_commit": self.is_commit,
            "salt_1": hex(self.salt_1),
            "salt_2": hex(self.salt_2),
            "is_valid": self.is_valid,
        }


class WalParseResult(dict):
    """
    WAL parse result matching the spec's dictionary structure:
    {"status": "ok", "size": size, "page_size": page_size, "checkpoint_seq": ckpt_seq,
     "frames_total": total, "frames_valid": valid, "commit_frames": commits, "distinct_pages": len(pages)}
    Also exposes attributes (.is_valid, .total_frames, .valid_frames, etc.) for convenience and compatibility.
    """
    def __init__(
        self,
        status: str,
        size: int,
        path: Optional[Path] = None,
        page_size: Optional[int] = None,
        checkpoint_seq: Optional[int] = None,
        frames_total: int = 0,
        frames_valid: int = 0,
        commit_frames: int = 0,
        distinct_pages: int = 0,
        header: Optional[WalHeader] = None,
        frames: Optional[List[WalFrame]] = None,
        unique_pages: Optional[List[int]] = None,
    ):
        data: Dict[str, Any] = {
            "status": status,
            "size": size,
        }
        if page_size is not None:
            data["page_size"] = page_size
        if checkpoint_seq is not None:
            data["checkpoint_seq"] = checkpoint_seq
        if status == "ok":
            data["frames_total"] = frames_total
            data["frames_valid"] = frames_valid
            data["commit_frames"] = commit_frames
            data["distinct_pages"] = distinct_pages

        super().__init__(data)
        self.status = status
        self.size_bytes = size
        self.size = size
        self.path = path
        self.page_size = page_size
        self.checkpoint_seq = checkpoint_seq
        self.total_frames = frames_total
        self.frames_total = frames_total
        self.valid_frames = frames_valid
        self.frames_valid = frames_valid
        self.commit_frames = commit_frames
        self.distinct_pages = distinct_pages
        self.header = header
        self.frames = frames or []
        self.unique_pages = unique_pages or []
        self.is_valid = (status == "ok")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path) if self.path else None,
            "size_bytes": self.size_bytes,
            "status": self.status,
            "page_size": self.page_size,
            "checkpoint_seq": self.checkpoint_seq,
            "header": self.header.to_dict() if self.header else None,
            "total_frames": self.total_frames,
            "valid_frames": self.valid_frames,
            "commit_frames": self.commit_frames,
            "distinct_pages": self.distinct_pages,
            "unique_pages": self.unique_pages,
            "is_valid": self.is_valid,
            "frames": [f.to_dict() for f in self.frames],
        }


def parse_wal(path: Union[str, Path]) -> WalParseResult:
    """
    Parses a SQLite Write-Ahead Log (WAL) file directly from binary format.
    Does not invoke SQLite recovery or checkpointing, preserving evidence immutability.
    """
    path_obj = Path(path)
    if not path_obj.is_file():
        raise ValueError(f"WAL file not found: {path_obj}")

    size = os.path.getsize(str(path_obj))
    if size < 32:
        return WalParseResult(status="too_small", size=size, path=path_obj)

    with open(path_obj, "rb") as f:
        header = f.read(32)
        magic, version, page_size, ckpt_seq, salt1, salt2, c1, c2 = struct.unpack(">8I", header)

        if magic not in WAL_MAGICS:
            return WalParseResult(status="bad_magic", size=size, path=path_obj)

        if page_size == 1:
            page_size = 65536

        if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)) != 0:
            return WalParseResult(status="bad_page_size", size=size, path=path_obj, page_size=page_size)

        wal_header = WalHeader(
            magic=magic,
            file_format=version,
            page_size=page_size,
            checkpoint_seq=ckpt_seq,
            salt_1=salt1,
            salt_2=salt2,
            checksum_1=c1,
            checksum_2=c2,
            is_valid=True,
        )

        frame_size = 24 + page_size
        total = (size - 32) // frame_size
        valid = commits = 0
        pages = set()
        frames: List[WalFrame] = []

        for idx in range(total):
            fh = f.read(24)
            if len(fh) < 24:
                break
            pgno, db_size, s1, s2, _a, _b = struct.unpack(">6I", fh)
            f.seek(page_size, os.SEEK_CUR)
            if s1 != salt1 or s2 != salt2:
                break

            valid += 1
            pages.add(pgno)
            is_commit = (db_size != 0)
            if is_commit:
                commits += 1

            frames.append(
                WalFrame(
                    frame_index=idx,
                    offset=32 + idx * frame_size,
                    pgno=pgno,
                    db_size=db_size,
                    is_commit=is_commit,
                    salt_1=s1,
                    salt_2=s2,
                    checksum_1=_a,
                    checksum_2=_b,
                    is_valid=True,
                )
            )

    return WalParseResult(
        status="ok",
        size=size,
        path=path_obj,
        page_size=page_size,
        checkpoint_seq=ckpt_seq,
        frames_total=total,
        frames_valid=valid,
        commit_frames=commits,
        distinct_pages=len(pages),
        header=wal_header,
        frames=frames,
        unique_pages=sorted(list(pages)),
    )


def inspect_database_wal(db_path: str | Path) -> Optional[WalParseResult]:
    """
    Checks if a database has an active companion -wal file and inspects it.
    Returns WalParseResult if a valid non-empty companion WAL exists, else None.
    """
    db_p = Path(db_path)
    wal_p = db_p.with_name(db_p.name + "-wal")
    if not wal_p.is_file():
        return None
    try:
        res = parse_wal(wal_p)
        return res if res.is_valid else None
    except Exception:
        return None
