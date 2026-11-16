from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional

from correlator.keychain import candidates, load_keychain
from correlator.scanner import DiscoveredDatabase, scan_extraction
from correlator.sqlcipher_util import PROFILES, is_plain_sqlite, sha256_file, try_key


@dataclass
class CorrelationResult:
    relpath: str
    name: str
    status: str  # "decrypted", "plain", "not_decrypted"
    sha256: Optional[str] = None
    bundle_id: Optional[str] = None
    container_type: Optional[str] = None
    container_uuid: Optional[str] = None
    key_fingerprint: Optional[str] = None
    key_bytes: Optional[bytes] = None
    profile: Optional[str] = None
    service: Optional[str] = None
    account: Optional[str] = None
    access_group: Optional[str] = None
    has_wal: bool = False
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relpath": self.relpath,
            "name": self.name,
            "status": self.status,
            "sha256": self.sha256,
            "bundle_id": self.bundle_id,
            "container_type": self.container_type,
            "container_uuid": self.container_uuid,
            "key_fingerprint": self.key_fingerprint,
            "profile": self.profile,
            "service": self.service,
            "account": self.account,
            "access_group": self.access_group,
            "has_wal": self.has_wal,
            "size_bytes": self.size_bytes,
        }


def _prioritize_candidates_for_db(
    cands: List[Dict[str, Any]], bundle_id: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Sorts candidates prioritizing those whose service or access_group matches
    the container's bundle_id, followed by higher hint scores.
    """
    if not bundle_id:
        return cands

    bundle_lower = bundle_id.lower()
    # Split bundle id into notable segments (e.g. ['org', 'example', 'app_a'] -> ['example', 'app_a'])
    tokens = [t for t in bundle_lower.split(".") if len(t) > 3 and t not in {"com", "org", "net"}]

    def priority_key(cand: Dict[str, Any]):
        svc = cand.get("service", "").lower()
        grp = cand.get("access_group", "").lower()

        relevance = 0
        if bundle_lower in svc or bundle_lower in grp:
            relevance = 20
        elif any(token in svc or token in grp for token in tokens):
            relevance = 10

        return (-(relevance + cand["hint_score"]), cand["fingerprint"])

    return sorted(cands, key=priority_key)


def correlate_database(
    db: DiscoveredDatabase,
    cands: List[Dict[str, Any]],
    profiles: Optional[List[Dict[str, Any]]] = None,
    scratch_dir: Optional[Path] = None,
) -> CorrelationResult:
    """
    Evaluates a single discovered database:
    1. Computes SHA-256 digest of pristine database file.
    2. Checks if unencrypted (plain SQLite).
    3. Tests candidate keys against configured SQLCipher profiles.
       If scratch_dir is provided, tests keys on an isolated copy of the main file.
    4. Returns CorrelationResult.
    """
    if profiles is None:
        profiles = PROFILES

    digest = sha256_file(db.path)

    result = CorrelationResult(
        relpath=db.relpath,
        name=db.name,
        status="not_decrypted",
        sha256=digest,
        bundle_id=db.bundle_id,
        container_type=db.container_type,
        container_uuid=db.container_uuid,
        has_wal=db.has_wal,
        size_bytes=db.size_bytes,
    )

    # 1. Check if unencrypted
    if is_plain_sqlite(db.path):
        result.status = "plain"
        return result

    # 2. Prepare test target (scratch copy if requested)
    target_path = db.path
    if scratch_dir is not None:
        scratch_db_dir = scratch_dir / f"scratch_{db.container_uuid or 'unknown'}_{db.name}"
        scratch_db_dir.mkdir(parents=True, exist_ok=True)
        temp_copy = scratch_db_dir / db.name
        shutil.copy2(db.path, temp_copy)
        target_path = temp_copy

    # 3. Prioritize candidates for this container
    prioritized = _prioritize_candidates_for_db(cands, db.bundle_id)

    # 4. Test candidates against profiles
    try:
        for cand in prioritized:
            kb = cand["key_bytes"]
            for prof in profiles:
                if try_key(target_path, kb, prof):
                    result.status = "decrypted"
                    result.key_fingerprint = cand["fingerprint"]
                    result.key_bytes = kb
                    result.profile = prof["name"]
                    result.service = cand.get("service")
                    result.account = cand.get("account")
                    result.access_group = cand.get("access_group")
                    return result
    finally:
        # Cleanup temporary scratch copy if used
        if scratch_dir is not None and target_path != db.path and target_path.exists():
            shutil.rmtree(target_path.parent, ignore_errors=True)

    return result


def correlate(
    extraction_root: str | Path,
    keychain_path: str | Path,
    profiles: Optional[List[Dict[str, Any]]] = None,
    work_dir: Optional[str | Path] = None,
) -> List[CorrelationResult]:
    """
    Scans extraction root, loads keychain candidate keys, and correlates them.
    If work_dir is provided, creates and uses an isolated scratch folder.
    Returns list of CorrelationResult sorted by relpath.
    """
    databases = scan_extraction(extraction_root)
    rows, _ = load_keychain(keychain_path)
    cands = candidates(rows)

    scratch_dir = None
    if work_dir is not None:
        scratch_dir = Path(work_dir) / "scratch"
        scratch_dir.mkdir(parents=True, exist_ok=True)

    results: List[CorrelationResult] = []
    for db in databases:
        res = correlate_database(db, cands, profiles=profiles, scratch_dir=scratch_dir)
        results.append(res)

    results.sort(key=lambda r: r.relpath)
    return results
