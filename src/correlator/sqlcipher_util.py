import contextlib
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
from sqlcipher3 import dbapi2 as sqlcipher

PROFILES = [
    {"name": "default", "pragmas": [], "hex_len": 64},
    {"name": "compat3", "pragmas": ["PRAGMA cipher_compatibility = 3;"], "hex_len": 64},
    {"name": "signal_like", "pragmas": ["PRAGMA cipher_plaintext_header_size = 32;"], "hex_len": 96},  # ASSUMPTION: verify before relying on it
    # Additional industry & application custom ciphers
    {"name": "wcdb_wechat", "pragmas": ["PRAGMA cipher_page_size = 4096;", "PRAGMA kdf_iter = 64000;"], "hex_len": 64},
    {"name": "sqlcipher_4096", "pragmas": ["PRAGMA cipher_page_size = 4096;"], "hex_len": 64},
    {"name": "compat2", "pragmas": ["PRAGMA cipher_compatibility = 2;"], "hex_len": 64},
    {"name": "compat1", "pragmas": ["PRAGMA cipher_compatibility = 1;"], "hex_len": 64},
    {"name": "sqlcipher_no_hmac", "pragmas": ["PRAGMA cipher_use_hmac = OFF;"], "hex_len": 64},
    {"name": "signal_like_v3", "pragmas": ["PRAGMA cipher_plaintext_header_size = 32;", "PRAGMA cipher_compatibility = 3;"], "hex_len": 96},
]


def fingerprint(key_bytes: bytes) -> str:
    """Return the first 8 hex characters of the key's SHA-256."""
    return hashlib.sha256(key_bytes).hexdigest()[:8]


def sha256_file(path) -> str:
    """Compute SHA-256 hex digest of a file in 1MB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_plain_sqlite(path) -> bool:
    """Check if file can be read as plain SQLite."""
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            con.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return True
        finally:
            con.close()
    except sqlite3.DatabaseError:
        return False


@contextlib.contextmanager
def _suppress_c_stderr():
    """Suppress C-level stderr output (such as SQLCipher HMAC verification failures)."""
    saved_fd = None
    stderr_fd = None
    try:
        stderr_fd = sys.stderr.fileno()
        saved_fd = os.dup(stderr_fd)
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull_fd, stderr_fd)
        os.close(devnull_fd)
    except Exception:
        pass
    try:
        yield
    finally:
        if saved_fd is not None and stderr_fd is not None:
            try:
                os.dup2(saved_fd, stderr_fd)
                os.close(saved_fd)
            except Exception:
                pass


def try_key(db_path, key_bytes: bytes, profile: dict) -> bool:
    """Attempt opening and checking integrity of an encrypted SQLite database in read-only mode."""
    hex_key = key_bytes.hex()
    if len(hex_key) != profile["hex_len"]:
        return False
    con = None
    try:
        with _suppress_c_stderr():
            uri = Path(db_path).resolve().as_uri() + "?mode=ro"
            con = sqlcipher.connect(uri, uri=True, timeout=5.0)
            con.execute(f"PRAGMA key = \"x'{hex_key}'\";")
            for p in profile["pragmas"]:
                con.execute(p)
            con.execute("SELECT count(*) FROM sqlite_master").fetchone()
            bad = con.execute("PRAGMA cipher_integrity_check;").fetchall()
            return len(bad) == 0
    except sqlcipher.DatabaseError:
        return False
    finally:
        if con is not None:
            con.close()


def export_decrypted(src_path, dest_path, key_bytes: bytes, profile: dict) -> None:
    """
    Exports an encrypted database to a decrypted plaintext SQLite database.
    Does not modify the source database.
    """
    dest_path = Path(dest_path).resolve()
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if dest_path.exists():
        dest_path.unlink()

    hex_key = key_bytes.hex()
    uri = Path(src_path).resolve().as_uri() + "?mode=ro"
    con = None
    try:
        con = sqlcipher.connect(uri, uri=True, timeout=10.0)
        con.execute(f"PRAGMA key = \"x'{hex_key}'\";")
        for p in profile["pragmas"]:
            con.execute(p)
        dest_str = dest_path.as_posix()
        con.execute(f'ATTACH DATABASE "{dest_str}" AS plaintext KEY "";')
        con.execute("SELECT sqlcipher_export('plaintext');")
        con.execute("DETACH DATABASE plaintext;")
    finally:
        if con is not None:
            con.close()
