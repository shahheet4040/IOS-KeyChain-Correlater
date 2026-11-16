"""
Integrated Audio & Media Gallery Engine
========================================
Catalogs, previews, and streams forensic media files extracted via
Apple File Conduit (AFC) or logical/physical disk dumps:
- Photos & Images (.jpg, .jpeg, .png, .heic, .heif)
- Voice Notes & Audio Memos (.m4a, .aac, .wav, .mp3, .caf)
- Video Recordings (.mov, .mp4, .m4v, .3gp)
- Documents & Attachments (.pdf, .plist, .txt)
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import mimetypes
from pathlib import Path
from typing import Any, Dict, List, Optional


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".bmp", ".gif"}
AUDIO_EXTS = {".m4a", ".aac", ".wav", ".mp3", ".caf", ".ogg"}
VIDEO_EXTS = {".mov", ".mp4", ".m4v", ".3gp", ".avi"}


@dataclass
class MediaItem:
    item_id: str
    file_name: str
    relative_path: str
    absolute_path: str
    media_category: str  # "image", "audio", "video", "document"
    file_size_bytes: int
    file_size_formatted: str
    mime_type: str
    modified_time: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["filename"] = self.file_name
        d["path"] = self.absolute_path
        d["category"] = self.media_category
        d["size_formatted"] = self.file_size_formatted
        d["modified"] = self.modified_time
        return d


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def scan_media_directory(
    root_dirs: List[Path | str],
    category_filter: Optional[str] = None,
    max_items: int = 1000,
) -> Dict[str, Any]:
    """
    Scans media folders to index images, voice memos, and videos.
    """
    items: List[MediaItem] = []
    category_counts = {"image": 0, "audio": 0, "video": 0, "document": 0}

    for r in root_dirs:
        root = Path(r).resolve()
        if not root.is_dir():
            continue

        for p in root.rglob("*"):
            if not p.is_file():
                continue

            ext = p.suffix.lower()
            if ext in IMAGE_EXTS:
                cat = "image"
            elif ext in AUDIO_EXTS:
                cat = "audio"
            elif ext in VIDEO_EXTS:
                cat = "video"
            elif ext in {".pdf", ".txt", ".json", ".plist", ".log"}:
                cat = "document"
            else:
                continue

            category_counts[cat] = category_counts.get(cat, 0) + 1

            if category_filter and category_filter.lower() != "all" and cat != category_filter.lower():
                continue

            if len(items) >= max_items:
                continue

            stat = p.stat()
            mime, _ = mimetypes.guess_type(str(p))
            if not mime:
                if cat == "audio":
                    mime = "audio/mp4" if ext == ".m4a" else "audio/aac"
                elif cat == "video":
                    mime = "video/mp4"
                elif cat == "image":
                    mime = "image/jpeg"
                else:
                    mime = "application/octet-stream"

            rel = p.relative_to(root).as_posix()
            mod_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            items.append(MediaItem(
                item_id=f"MED-{len(items)+1}",
                file_name=p.name,
                relative_path=rel,
                absolute_path=str(p),
                media_category=cat,
                file_size_bytes=stat.st_size,
                file_size_formatted=_format_size(stat.st_size),
                mime_type=mime,
                modified_time=mod_time,
            ))

    # Sort newest first
    items.sort(key=lambda x: x.modified_time, reverse=True)

    total_discovered = sum(category_counts.values())
    return {
        "total": total_discovered,
        "total_items": total_discovered,
        "categories": category_counts,
        "category_counts": category_counts,
        "items": [it.to_dict() for it in items[:max_items]],
    }
