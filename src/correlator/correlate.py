from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from correlator.sqlcipher_util import PROFILES, try_key


def correlate(scratch_copy: str | Path, cands: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """
    For every profile in PROFILES and every candidate, calls try_key.
    Collects every success, not only the first.
    Each match is {key_fingerprint, profile, service, account, access_group}.
    Zero matches means not_decrypted.
    One match means decrypted.
    More than one distinct key means ambiguous.
    The same key matching under two profiles counts once, using the first profile.
    Returns (status, matches).
    """
    db_path = Path(scratch_copy).resolve()
    matches: List[Dict[str, Any]] = []
    seen_keys = set()

    for cand in cands:
        kb = cand["key_bytes"]
        fp = cand["fingerprint"]

        # If already matched under an earlier profile, do not re-match under another profile
        if fp in seen_keys:
            continue

        for profile in PROFILES:
            if try_key(db_path, kb, profile):
                match_record = {
                    "key_fingerprint": fp,
                    "profile": profile["name"],
                    "service": cand.get("service", ""),
                    "account": cand.get("account", ""),
                    "access_group": cand.get("access_group", ""),
                    "key_bytes": kb,
                }
                matches.append(match_record)
                seen_keys.add(fp)
                break  # Record the first matching profile for this key

    # Determine status
    distinct_keys = {m["key_fingerprint"] for m in matches}
    if len(distinct_keys) == 0:
        status = "not_decrypted"
    elif len(distinct_keys) == 1:
        status = "decrypted"
    else:
        status = "ambiguous"

    return status, matches
