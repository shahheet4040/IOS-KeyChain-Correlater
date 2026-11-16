"""iOS Keychain Correlator: Forensic correlation of iOS Keychain exports and SQLCipher databases."""

from correlator.engine import CorrelationResult, correlate, correlate_database
from correlator.evaluate import evaluate_report, run_evaluation
from correlator.inventory import scan_containers
from correlator.keychain import candidates, load_keychain
from correlator.pipeline import (
    IntegrityError,
    execute_pipeline,
    format_table,
    run,
    run_pipeline,
)
from correlator.report import generate_html_report, generate_json_report, write_html, write_json
from correlator.scanner import DiscoveredDatabase, scan_extraction
from correlator.sqlcipher_util import (
    PROFILES,
    fingerprint,
    is_plain_sqlite,
    sha256_file,
    try_key,
)
from correlator.triage import (
    TriageDatabase,
    classify,
    classify_database,
    find_databases,
    triage_extraction,
)
from correlator.wal import (
    WalFrame,
    WalHeader,
    WalParseResult,
    inspect_database_wal,
    parse_wal,
)

__all__ = [
    "CorrelationResult",
    "correlate",
    "correlate_database",
    "load_keychain",
    "candidates",
    "DiscoveredDatabase",
    "scan_extraction",
    "PROFILES",
    "fingerprint",
    "is_plain_sqlite",
    "sha256_file",
    "try_key",
    "TriageDatabase",
    "classify_database",
    "triage_extraction",
    "WalFrame",
    "WalHeader",
    "WalParseResult",
    "inspect_database_wal",
    "parse_wal",
    "generate_json_report",
    "generate_html_report",
    "evaluate_report",
    "run_evaluation",
    "IntegrityError",
    "execute_pipeline",
    "run_pipeline",
    "format_table",
    "scan_containers",
    "find_databases",
    "classify",
    "write_json",
    "write_html",
    "run",
]
