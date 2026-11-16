from pathlib import Path
import pytest
from correlator.media_gallery import scan_media_directory, _format_size


def test_format_size():
    assert _format_size(500) == "500 B"
    assert _format_size(1500) == "1.5 KB"
    assert _format_size(2 * 1024 * 1024) == "2.0 MB"


def test_scan_media_directory(tmp_path: Path):
    media_dir = tmp_path / "DCIM" / "100APPLE"
    media_dir.mkdir(parents=True)

    # Create dummy images
    (media_dir / "IMG_0001.JPG").write_bytes(b"\xFF\xD8\xFF" + b"\x00" * 200)
    (media_dir / "IMG_0002.PNG").write_bytes(b"\x89PNG" + b"\x00" * 300)

    # Create dummy audio voice notes
    voice_dir = tmp_path / "Recordings"
    voice_dir.mkdir()
    (voice_dir / "memo_01.m4a").write_bytes(b"dummy audio" * 50)
    (voice_dir / "note.wav").write_bytes(b"RIFF" + b"\x00" * 500)

    # Create dummy video
    (media_dir / "clip.mov").write_bytes(b"moov" + b"\x00" * 1000)

    # Create dummy document
    (tmp_path / "doc.pdf").write_bytes(b"%PDF-1.4" + b"\x00" * 100)

    # 1. Scan all
    res = scan_media_directory([tmp_path])
    assert res["total"] == 6
    assert res["categories"]["image"] == 2
    assert res["categories"]["audio"] == 2
    assert res["categories"]["video"] == 1
    assert res["categories"]["document"] == 1
    assert len(res["items"]) == 6

    # 2. Filter image category
    img_res = scan_media_directory([tmp_path], category_filter="image")
    assert len(img_res["items"]) == 2
    assert all(i["media_category"] == "image" for i in img_res["items"])

    # 3. Filter audio category
    audio_res = scan_media_directory([tmp_path], category_filter="audio")
    assert len(audio_res["items"]) == 2
    assert all(i["media_category"] == "audio" for i in audio_res["items"])

    # 4. Limit max items
    limit_res = scan_media_directory([tmp_path], max_items=2)
    assert len(limit_res["items"]) == 2
    assert limit_res["total"] == 6  # Total count preserved in categories


def test_scan_media_non_existent():
    res = scan_media_directory(["/non/existent/path/98765"])
    assert res["total"] == 0
    assert res["items"] == []
