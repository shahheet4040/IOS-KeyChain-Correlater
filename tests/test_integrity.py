from pathlib import Path
import shutil
from correlator.pipeline import execute_pipeline
from correlator.sqlcipher_util import sha256_file, try_key, PROFILES

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "out" / "fake"
EXTRACTION_DIR = FIXTURES_DIR / "extraction"
KEYCHAIN_PATH = FIXTURES_DIR / "keychain.json"


def test_evidence_immutability_pipeline(tmp_path):
    """
    Verify that running the entire correlation and reporting pipeline
    does not alter even a single byte of the original extraction evidence.
    """
    assert EXTRACTION_DIR.exists(), "Harness extraction fixture missing"
    assert KEYCHAIN_PATH.exists(), "Harness keychain fixture missing"

    # Copy extraction to an isolated test directory to verify immutability
    test_extraction = tmp_path / "extraction_evidence"
    shutil.copytree(EXTRACTION_DIR, test_extraction)

    # Compute pre-execution SHA-256 for every single file in the evidence tree
    pre_hashes = {}
    for p in test_extraction.rglob("*"):
        if p.is_file():
            rel = p.relative_to(test_extraction).as_posix()
            pre_hashes[rel] = sha256_file(p)

    assert len(pre_hashes) > 0

    out_dir = tmp_path / "reports"
    export_dir = tmp_path / "exports"

    # Run the full pipeline
    pipe_res = execute_pipeline(
        extraction=test_extraction,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir,
        export_dir=export_dir,
    )

    assert pipe_res["total_databases"] == 4
    assert pipe_res["decrypted_count"] == 2

    # Compute post-execution SHA-256 for all evidence files
    post_hashes = {}
    for p in test_extraction.rglob("*"):
        if p.is_file():
            rel = p.relative_to(test_extraction).as_posix()
            post_hashes[rel] = sha256_file(p)

    # Immutability assertion: pre and post hashes must be 100% identical
    assert set(pre_hashes.keys()) == set(post_hashes.keys()), "Evidence file set changed!"
    for rel, pre_h in pre_hashes.items():
        post_h = post_hashes[rel]
        assert pre_h == post_h, f"Forensic integrity violated for {rel}: pre={pre_h}, post={post_h}"


def test_wal_companions_not_checkpointed_or_deleted(tmp_path):
    """
    Verify that companion -wal and -shm files are not merged, truncated, or deleted.
    """
    test_extraction = tmp_path / "extraction_wal_check"
    shutil.copytree(EXTRACTION_DIR, test_extraction)

    wal_files = list(test_extraction.rglob("*-wal"))
    assert len(wal_files) >= 1, "Expected at least one -wal file in synthetic extraction"

    wal_pre_stats = {
        w.relative_to(test_extraction).as_posix(): (w.stat().st_size, sha256_file(w))
        for w in wal_files
    }

    out_dir = tmp_path / "out"
    execute_pipeline(
        extraction=test_extraction,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir,
    )

    for rel, (size, sha) in wal_pre_stats.items():
        wal_path = test_extraction / rel
        assert wal_path.exists(), f"WAL companion file was deleted: {rel}"
        assert wal_path.stat().st_size == size, f"WAL file size changed for {rel}"
        assert sha256_file(wal_path) == sha, f"WAL content altered for {rel}"


def test_try_key_read_only_protection(tmp_path):
    """
    Verify that try_key connects with ?mode=ro and cannot mutate database state.
    """
    db_file = tmp_path / "test_ro.sqlite"
    # Create empty file
    db_file.write_bytes(b"\x00" * 4096)
    initial_sha = sha256_file(db_file)

    # Test arbitrary key
    dummy_key = b"\x11" * 32
    prof = PROFILES[0]
    success = try_key(db_file, dummy_key, prof)
    assert not success

    # Verify hash has not changed
    assert sha256_file(db_file) == initial_sha


def test_integrity_spec_assertions(tmp_path):
    """
    Spec: SHA-256 of every input file is identical before and after a run.
    """
    from correlator.pipeline import run

    # Copy extraction to an isolated folder
    test_extraction = tmp_path / "extraction_run_check"
    shutil.copytree(EXTRACTION_DIR, test_extraction)

    # Compute SHA-256 before
    hashes_before = {
        p.relative_to(test_extraction).as_posix(): sha256_file(p)
        for p in test_extraction.rglob("*")
        if p.is_file()
    }
    assert len(hashes_before) > 0

    # Run the pipeline
    run(test_extraction, KEYCHAIN_PATH, tmp_path / "run_out")

    # Compute SHA-256 after
    hashes_after = {
        p.relative_to(test_extraction).as_posix(): sha256_file(p)
        for p in test_extraction.rglob("*")
        if p.is_file()
    }

    # Must be 100% identical
    assert hashes_before == hashes_after

