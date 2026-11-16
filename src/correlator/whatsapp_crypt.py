"""
WhatsApp Crypt12/Crypt14/Crypt15 & Multi-Platform Decryptor
==========================================================
Decrypts encrypted WhatsApp database backups (msgstore.db.crypt12/14/15)
using the 32-byte master key extracted from Keychain, Android keystore,
or the raw WhatsApp 'key' file.

Also supports generic AES-256-GCM / AES-256-CBC encrypted SQLite databases.
"""

from pathlib import Path
from typing import Optional, Tuple
import zlib

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


def is_crypt_database(file_path: str | Path) -> bool:
    """Detects if a file is an encrypted WhatsApp backup or custom cipher DB."""
    p = Path(file_path)
    name = p.name.lower()
    if any(name.endswith(ext) for ext in (".crypt12", ".crypt14", ".crypt15", ".crypt")):
        return True

    # Check header magic for crypt14/15
    try:
        with open(p, "rb") as f:
            header = f.read(32)
            if b"WhatsApp" in header or header.startswith(b"\x00\x01") or header.startswith(b"\x00\x02"):
                return True
    except Exception:
        pass
    return False


def decrypt_whatsapp_crypt14_15(
    encrypted_path: str | Path,
    out_decrypted_sqlite: str | Path,
    key_bytes: bytes,
) -> bool:
    """
    Decrypts WhatsApp crypt14 and crypt15 backups using AES-256-GCM.
    
    Header structure of crypt14/15:
    - Bytes 0-15: Header/Magic
    - Bytes 15-31: IV/Nonce (16 bytes) or Salt
    - Remaining bytes: Encrypted AES-GCM ciphertext + 16-byte authentication tag
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography package is required for WhatsApp crypt decryption.")

    if len(key_bytes) != 32:
        raise ValueError(f"WhatsApp decryption requires a 32-byte AES key (got {len(key_bytes)} bytes)")

    enc_file = Path(encrypted_path).resolve()
    out_file = Path(out_decrypted_sqlite).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    data = enc_file.read_bytes()
    if len(data) < 67:
        raise ValueError("Encrypted database file is too small to contain a valid crypt header.")

    # WhatsApp crypt14/15 layout:
    # Offset 0..15: Header / version metadata
    # Offset 15..31: IV (16 bytes, first 12 bytes used for GCM nonce)
    # Offset 31..-16: Ciphertext payload
    # Offset -16..: Tag (16 bytes)
    iv = data[15:31]
    gcm_nonce = iv[:12]
    tag = data[-16:]
    ciphertext = data[31:-16]

    # Try standard AES-GCM decryption
    try:
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(gcm_nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        # WhatsApp payloads are zlib compressed after decryption
        try:
            decompressed = zlib.decompress(decrypted)
        except Exception:
            # If not compressed or raw SQLite
            decompressed = decrypted

        out_file.write_bytes(decompressed)
        return True
    except Exception as e:
        # Fallback to AES-CBC (used in legacy crypt12)
        try:
            iv_cbc = data[51:67] if len(data) > 67 else data[:16]
            ciphertext_cbc = data[67:] if len(data) > 67 else data[16:]
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_cbc), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext_cbc) + decryptor.finalize()

            try:
                decompressed = zlib.decompress(decrypted)
            except Exception:
                decompressed = decrypted

            if decompressed.startswith(b"SQLite format 3"):
                out_file.write_bytes(decompressed)
                return True
        except Exception:
            pass

        raise RuntimeError(f"WhatsApp crypt decryption failed (Key mismatch or corrupted payload): {e}")


def try_decrypt_additional_formats(
    db_path: Path,
    candidate_keys: list[bytes],
    out_dest: Path,
) -> Tuple[bool, Optional[str], Optional[bytes]]:
    """
    Attempts decryption of WhatsApp crypt14/15 or custom AES SQLite databases
    against a list of candidate keys.
    Returns (success, format_name, matching_key_bytes).
    """
    if not is_crypt_database(db_path):
        return False, None, None

    for key in candidate_keys:
        if len(key) == 32:
            try:
                if decrypt_whatsapp_crypt14_15(db_path, out_dest, key):
                    # Verify output is valid SQLite
                    with open(out_dest, "rb") as f:
                        hdr = f.read(16)
                        if hdr.startswith(b"SQLite format 3"):
                            return True, "WhatsApp crypt14/15 (AES-GCM)", key
            except Exception:
                continue

    return False, None, None
