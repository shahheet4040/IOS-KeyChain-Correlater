import os
from pathlib import Path
import sqlite3
import pytest

from correlator.keychain import classify_protection_class
from correlator.ram_carver import (
    shannon_entropy,
    is_probable_crypto_key,
    carve_keys_from_memory,
)
from correlator.itunes_backup import (
    is_itunes_backup,
    parse_itunes_manifest,
    find_app_databases_in_itunes_backup,
)
from correlator.messaging_profiles import (
    match_profile_for_container,
    SIGNAL_PROFILE,
    TELEGRAM_PROFILE,
    WHATSAPP_PROFILE,
)
from correlator.certificate import (
    generate_forensic_certificate,
    render_certificate_markdown,
)


def test_classify_protection_class():
    name, desc, is_bio = classify_protection_class("ck")
    assert "Class C" in name
    assert not is_bio

    name_a, desc_a, is_bio_a = classify_protection_class("ak", access_control="kSecAccessControlBiometryAny")
    assert "Class A" in name_a
    assert is_bio_a is True

    name_un, desc_un, _ = classify_protection_class("")
    assert name_un == "Unspecified"


def test_ram_carver():
    # Null bytes should fail
    assert not is_probable_crypto_key(b"\x00" * 32)
    # ASCII text should fail
    assert not is_probable_crypto_key(b"This is a 32-byte plain text str")
    
    # Real high-entropy key
    real_key = os.urandom(32)
    assert is_probable_crypto_key(real_key)
    assert shannon_entropy(real_key) > 4.5

    # Memory buffer carving test
    dummy_mem = b"HEADER_INFO" + (b"\x00" * 16) + real_key + (b"\xFF" * 16) + b"FOOTER"
    candidates = carve_keys_from_memory(dummy_mem, min_entropy=4.0)
    assert any(c["key_bytes"] == real_key for c in candidates)


def test_itunes_backup(tmp_path):
    backup_dir = tmp_path / "Backup_001"
    backup_dir.mkdir()
    manifest_db = backup_dir / "Manifest.db"

    conn = sqlite3.connect(manifest_db)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    
    file_id = "3d0d7e5fb2340000000000000000000000000000"
    cursor.execute("INSERT INTO Files VALUES (?, ?, ?, ?, ?)", (
        file_id,
        "AppDomain-net.whatsapp.WhatsApp",
        "Documents/ChatStorage.sqlite",
        1,
        b"",
    ))
    conn.commit()
    conn.close()

    # Create the hashed file on disk
    sub_folder = backup_dir / file_id[:2]
    sub_folder.mkdir()
    target_file = sub_folder / file_id
    target_file.write_bytes(b"SQLITE_DUMMY_DATA")

    assert is_itunes_backup(backup_dir) is True
    records = parse_itunes_manifest(backup_dir)
    assert len(records) == 1
    assert records[0].file_id == file_id
    assert records[0].domain == "AppDomain-net.whatsapp.WhatsApp"
    assert records[0].physical_path == target_file

    matched = find_app_databases_in_itunes_backup(backup_dir, "whatsapp")
    assert len(matched) == 1


def test_messaging_profiles():
    prof_signal = match_profile_for_container("group.org.whispersystems.signal")
    assert prof_signal == SIGNAL_PROFILE

    prof_tg = match_profile_for_container("ph.telegra.Telegraph")
    assert prof_tg == TELEGRAM_PROFILE

    prof_wa = match_profile_for_container("net.whatsapp.WhatsApp")
    assert prof_wa == WHATSAPP_PROFILE


def test_forensic_certificate(tmp_path):
    dummy_ev = tmp_path / "evidence.raw"
    dummy_ev.write_bytes(b"EVIDENCE_BITS")
    dummy_out = tmp_path / "decrypted.sqlite"
    dummy_out.write_bytes(b"DECRYPTED_BITS")

    cert = generate_forensic_certificate(
        case_number="CASE-2026-99",
        evidence_name="iPhone 15 Pro Max Extraction",
        evidence_paths=[dummy_ev],
        decrypted_output_paths=[dummy_out],
        examiner_name="Agent Smith",
    )

    assert cert["case_number"] == "CASE-2026-99"
    assert "ISO/IEC 27037:2012 (Guidelines for Digital Evidence Handling)" in cert["standard_compliance"]
    assert len(cert["input_evidence"]) == 1
    assert len(cert["decrypted_outputs"]) == 1

    md = render_certificate_markdown(cert)
    assert "Digital Forensic Verification & Chain of Custody Certificate" in md
    assert "CASE-2026-99" in md
