import plistlib
import pytest
from pathlib import Path

from correlator.scanner import scan_extraction


def test_scanner_missing_dir(tmp_path):
    missing = tmp_path / "does_not_exist"
    with pytest.raises(ValueError, match="not found"):
        scan_extraction(missing)


def test_scanner_empty_dir(tmp_path):
    empty = tmp_path / "empty_dir"
    empty.mkdir()
    dbs = scan_extraction(empty)
    assert dbs == []


def test_scanner_synthetic_extraction():
    base = Path(__file__).resolve().parent.parent / "out" / "fake"
    extraction_root = base / "extraction"

    dbs = scan_extraction(extraction_root)
    # Exactly 4 databases in synthetic extraction
    assert len(dbs) == 4

    by_name = {d.name: d for d in dbs}
    assert ("app_a.sqlite" in by_name or "signal.sqlite" in by_name)
    assert ("app_b.sqlite" in by_name or "legacy.sqlite" in by_name)
    assert "ChatStorage.sqlite" in by_name
    assert "orphan.db" in by_name

    # Check App A / Signal metadata
    app_a = by_name.get("app_a.sqlite") or by_name.get("signal.sqlite")
    assert app_a.bundle_id in ("org.example.app_a", "org.whispersystems.signal")
    assert app_a.container_type == "AppGroup"
    assert app_a.container_uuid == "AAAA-1111"
    assert app_a.has_wal is True
    assert app_a.has_shm is True

    # Check App B / Legacy metadata
    app_b = by_name.get("app_b.sqlite") or by_name.get("legacy.sqlite")
    assert app_b.bundle_id == "org.example.app_b"
    assert app_b.container_type == "Application"
    assert app_b.container_uuid == "BBBB-2222"
    assert app_b.has_wal is True

    # Check WhatsApp metadata
    wa = by_name["ChatStorage.sqlite"]
    assert wa.bundle_id == "net.whatsapp.WhatsApp"
    assert wa.container_type == "AppGroup"
    assert wa.container_uuid == "CCCC-3333"
    assert wa.has_wal is True

    # Check Orphan DB metadata
    orphan = by_name["orphan.db"]
    assert orphan.bundle_id == "org.example.orphan"
    assert orphan.container_type == "Application"
    assert orphan.container_uuid == "DDDD-4444"
    assert orphan.has_wal in (True, False)


def test_scanner_ignores_non_db_and_wal_files(tmp_path):
    # Setup dummy directory structure
    (tmp_path / "data.sqlite").touch()
    (tmp_path / "data.sqlite-wal").touch()
    (tmp_path / "data.sqlite-shm").touch()
    (tmp_path / "test.db").touch()
    (tmp_path / "notes.txt").touch()
    (tmp_path / "photo.jpg").touch()

    dbs = scan_extraction(tmp_path)
    names = [d.name for d in dbs]
    assert sorted(names) == ["data.sqlite", "test.db"]
    data_db = next(d for d in dbs if d.name == "data.sqlite")
    assert data_db.has_wal is True
    assert data_db.has_shm is True


def test_scanner_database_outside_containers(tmp_path):
    # A database placed outside Containers (e.g. system SMS or Notes)
    system_dir = tmp_path / "private" / "var" / "mobile" / "Library" / "SMS"
    system_dir.mkdir(parents=True)
    db_file = system_dir / "sms.db"
    db_file.touch()

    dbs = scan_extraction(tmp_path)
    assert len(dbs) == 1
    db = dbs[0]
    assert db.name == "sms.db"
    assert db.bundle_id is None
    assert db.container_type is None
    assert db.container_uuid is None


def test_scanner_corrupted_plist(tmp_path):
    # Container with corrupted plist should not crash scanner
    container_dir = tmp_path / "Containers" / "Data" / "Application" / "CORRUPT-UUID"
    container_dir.mkdir(parents=True)
    (container_dir / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(b"NOT A VALID PLIST")
    (container_dir / "Documents").mkdir()
    (container_dir / "Documents" / "app.sqlite").touch()

    dbs = scan_extraction(tmp_path)
    assert len(dbs) == 1
    db = dbs[0]
    assert db.name == "app.sqlite"
    assert db.bundle_id is None
    assert db.container_type == "Application"
    assert db.container_uuid == "CORRUPT-UUID"


def test_scanner_deeply_nested_database_and_category(tmp_path):
    # Test deeply nested database and category-based container type detection
    container_dir = tmp_path / "CustomContainers" / "APP-9999"
    nested_dir = container_dir / "Library" / "Application Support" / "SubDir" / "Data"
    nested_dir.mkdir(parents=True)
    
    # Write plist with MCMMetadataCategory = 7 (AppGroup) and CFBundleIdentifier fallback
    plist_path = container_dir / ".com.apple.mobile_container_manager.metadata.plist"
    with open(plist_path, "wb") as f:
        plistlib.dump({
            "CFBundleIdentifier": "group.com.example.nested",
            "MCMMetadataCategory": 7,
        }, f)

    db_path = nested_dir / "CoreDataStore.storedata"
    db_path.touch()
    journal_path = nested_dir / "CoreDataStore.storedata-journal"
    journal_path.touch()

    dbs = scan_extraction(tmp_path)
    assert len(dbs) == 1
    db = dbs[0]
    assert db.name == "CoreDataStore.storedata"
    assert db.bundle_id == "group.com.example.nested"
    assert db.container_type == "AppGroup"
    assert db.container_uuid == "APP-9999"
    assert db.has_journal is True
    assert db.has_wal is False
