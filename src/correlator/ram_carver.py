"""
Volatile Memory (RAM) Key Carver for Digital Forensics
======================================================
Carves raw 32-byte (AES-256) and 48-byte cryptographic keys from volatile
memory dumps (Frida memory dumps, LLDB dumps, Android/iOS RAM dumps, .dmp, .raw).

Filters candidate byte sequences using Shannon Entropy and byte-distribution
analysis to eliminate null-padding, ASCII strings, and low-entropy memory blocks.
"""

import math
from pathlib import Path
from typing import Any, Dict, List, Set, Union

from correlator.sqlcipher_util import fingerprint


def shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon entropy of a byte string in bits per byte (0.0 to 8.0).
    True cryptographic keys (AES-256) typically exhibit entropy > 7.2.
    """
    if not data:
        return 0.0
    length = len(data)
    frequencies = {}
    for b in data:
        frequencies[b] = frequencies.get(b, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_probable_crypto_key(data: bytes, min_entropy: float = 4.2) -> bool:
    """
    Evaluates whether a slice of bytes has the statistical characteristics
    of an AES-256 or raw cryptographic key:
    - Minimum length of 32 or 48 bytes
    - Shannon entropy >= min_entropy (Note: max theoretical entropy for 32 bytes is log2(32) = 5.0 bits/byte)
    - Not predominantly ASCII text
    - Not zero-filled or uniform repeated bytes
    """
    if len(data) not in (32, 48):
        return False

    # Check for identical repeated bytes (e.g. b"\x00"*32 or b"\xff"*32)
    if len(set(data)) <= 4:
        return False

    # Check for printable ASCII text (e.g. JSON strings or code in memory)
    printable_count = sum(1 for b in data if 32 <= b <= 126)
    if printable_count / len(data) > 0.85:
        return False

    # Entropy check: 32 bytes of uniform random data has entropy close to 4.5 - 5.0
    ent = shannon_entropy(data)
    return ent >= min_entropy


def carve_keys_from_memory(
    data_or_path: Union[bytes, str, Path],
    min_entropy: float = 4.2,
    target_lengths: tuple = (32, 48),
    alignment_stride: int = 1,
) -> List[Dict[str, Any]]:
    """
    Carves candidate cryptographic keys from a raw memory buffer or file.

    Parameters:
    - data_or_path: Raw bytes or path to .dmp / .raw / .bin memory file
    - min_entropy: Minimum Shannon entropy (default: 7.2 bits/byte)
    - target_lengths: Tuple of key byte lengths to search for (default: 32, 48)
    - alignment_stride: Memory alignment stride (default: 4-byte / 32-bit boundary)

    Returns:
    List of normalized key candidate dictionaries ready for correlation.
    """
    if isinstance(data_or_path, (str, Path)):
        p = Path(data_or_path)
        if not p.is_file():
            raise FileNotFoundError(f"Memory dump file not found: {p}")
        buffer = p.read_bytes()
        source_name = p.name
    else:
        buffer = data_or_path
        source_name = "raw_buffer"

    total_len = len(buffer)
    seen_keys: Set[bytes] = set()
    candidates: List[Dict[str, Any]] = []

    for length in target_lengths:
        if total_len < length:
            continue

        # Step through memory buffer along alignment boundary
        for offset in range(0, total_len - length + 1, alignment_stride):
            chunk = buffer[offset : offset + length]

            if chunk in seen_keys:
                continue

            if is_probable_crypto_key(chunk, min_entropy=min_entropy):
                seen_keys.add(chunk)
                ent = shannon_entropy(chunk)
                fp = fingerprint(chunk)

                candidates.append({
                    "key_bytes": chunk,
                    "fingerprint": fp,
                    "service": f"RAM:{source_name}",
                    "account": f"offset_0x{offset:08X}",
                    "access_group": "VolatileMemory",
                    "hint_score": 2,
                    "entropy": round(ent, 3),
                    "protection_class": "VolatileRAM",
                    "protection_description": "Extracted from volatile process memory / RAM dump.",
                    "is_biometric": False,
                })

    # Sort descending by entropy
    candidates.sort(key=lambda c: -c.get("entropy", 0.0))
    return candidates
