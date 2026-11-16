import os
from pathlib import Path
import pytest
import zlib

from correlator.whatsapp_crypt import (
    is_crypt_database,
    decrypt_whatsapp_crypt14_15,
    try_decrypt_additional_formats,
)

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


@pytest.mark.skipif(not CRYPTOGRAPHY_AVAILABLE, reason="cryptography required")
def test_whatsapp_crypt14_15_encryption_and_decryption(tmp_path):
    # 1. Create a dummy SQLite database payload
    dummy_sqlite = b"SQLite format 3\x00" + b"\x00" * 100 + b"TABLE_MESSAGES_DUMMY_DATA"
    compressed = zlib.compress(dummy_sqlite)

    # 2. Simulate WhatsApp crypt14/15 header and AES-GCM encryption
    key = os.urandom(32)
    iv = os.urandom(16)
    nonce = iv[:12]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(compressed) + encryptor.finalize()
    tag = encryptor.tag

    header = b"\x00\x01WhatsAppBackup"[:15]
    crypt_payload = header + iv + ciphertext + tag

    crypt_file = tmp_path / "msgstore.db.crypt14"
    crypt_file.write_bytes(crypt_payload)

    assert is_crypt_database(crypt_file)

    # 3. Decrypt using whatsapp_crypt
    out_decrypted = tmp_path / "msgstore.sqlite"
    success = decrypt_whatsapp_crypt14_15(crypt_file, out_decrypted, key)

    assert success is True
    assert out_decrypted.exists()
    assert out_decrypted.read_bytes() == dummy_sqlite

    # 4. Test try_decrypt_additional_formats
    ok, fmt, matching_key = try_decrypt_additional_formats(crypt_file, [b"\x00" * 32, key], out_decrypted)
    assert ok is True
    assert "WhatsApp" in fmt
    assert matching_key == key
