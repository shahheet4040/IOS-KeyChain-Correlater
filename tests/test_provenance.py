"""
Unit Tests for Forensic Provenance Tracking & Step Mapping
==========================================================
Verifies that all sequential operations performed during extraction,
keychain parsing, cryptographic matching, and decryption are recorded
into a tamper-evident audit trail and visual provenance map.
"""

from pathlib import Path
from correlator.engine import CorrelationResult
from correlator.provenance import (
    ForensicStep,
    ProvenanceTracker,
    StepPhase,
    StepStatus,
    build_default_provenance_map,
)


def test_provenance_tracker_lifecycle(tmp_path):
    tracker = ProvenanceTracker(case_id="FSL-CASE-001")
    s1 = tracker.record_step(
        phase=StepPhase.TRIAGE,
        action="Discovered 3 SQLite databases in extraction root",
        target="File Scanner",
    )
    assert s1.step_number == 1
    assert s1.phase == StepPhase.TRIAGE.value
    assert s1.status == "success"

    s2 = tracker.record_step(
        phase=StepPhase.CORRELATION,
        action="Matched SQLCipher v4 master key",
        target="signal.sqlite",
        details={"profile": "SQLCipher v4", "key_fp": "abcd1234"},
    )
    assert s2.step_number == 2
    assert s2.details["profile"] == "SQLCipher v4"

    timeline = tracker.get_timeline()
    assert len(timeline) == 2

    # Export test
    out_json = tmp_path / "provenance.json"
    tracker.export_json(out_json)
    assert out_json.is_file()
    assert out_json.stat().st_size > 50


def test_build_default_provenance_map():
    res1 = CorrelationResult(
        name="signal.sqlite",
        relpath="AppGroup/signal/signal.sqlite",
        status="decrypted",
        bundle_id="org.whispersystems.signal",
        profile="SQLCipher v4",
        key_fingerprint="a1b2c3d4",
        has_wal=True,
    )
    res2 = CorrelationResult(
        name="plain.sqlite",
        relpath="Application/plain/plain.sqlite",
        status="plain",
        bundle_id="org.example.plain",
    )

    tracker = build_default_provenance_map(
        results=[res1, res2],
        extraction_path="/mock/extraction",
        keychain_path="/mock/keychain.plist",
        export_dir="/mock/exports",
    )

    steps = tracker.get_timeline()
    assert len(steps) >= 6

    phases = [s["phase"] for s in steps]
    assert StepPhase.TRIAGE.value in phases
    assert StepPhase.INTEGRITY_PRE.value in phases
    assert StepPhase.KEYCHAIN.value in phases
    assert StepPhase.CORRELATION.value in phases
    assert StepPhase.DECRYPTION.value in phases
    assert StepPhase.INTEGRITY_POST.value in phases
