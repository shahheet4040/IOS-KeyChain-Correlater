import base64
import json
from pathlib import Path
from correlator.pipeline import execute_pipeline, run_pipeline

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "out" / "fake"
EXTRACTION_DIR = FIXTURES_DIR / "extraction"
KEYCHAIN_PATH = FIXTURES_DIR / "keychain.json"


def _get_keychain_secrets():
    with open(KEYCHAIN_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)
    secrets = []
    for r in records:
        b64 = r.get("value_b64")
        if b64:
            secrets.append(b64)
            try:
                raw_bytes = base64.b64decode(b64)
                if len(raw_bytes) in (32, 48):
                    secrets.append(raw_bytes.hex())
            except Exception:
                pass
    return secrets


def test_no_key_leak_in_json_report(tmp_path):
    """
    Ensure that report.json contains ONLY key fingerprints and NEVER
    contains full raw cryptographic keys (hex or base64).
    """
    raw_secrets = _get_keychain_secrets()
    assert len(raw_secrets) > 0

    out_dir = tmp_path / "leak_test_out"
    res = execute_pipeline(
        extraction=EXTRACTION_DIR,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir,
    )

    report_path = res["report_json_path"]
    report_text = report_path.read_text(encoding="utf-8")

    # Verify no raw secrets appear anywhere in report.json text
    for secret in raw_secrets:
        assert secret not in report_text, f"Raw key secret leaked into report.json: {secret}"

    # Also inspect structured JSON
    report_json = json.loads(report_text)
    for db in report_json["databases"]:
        assert "key_bytes" not in db, "Raw key_bytes present in database report dictionary!"
        if db.get("key_fingerprint"):
            assert len(db["key_fingerprint"]) == 8


def test_no_key_leak_in_html_report(tmp_path):
    """
    Ensure that standalone report.html never contains raw key material.
    """
    raw_secrets = _get_keychain_secrets()
    assert len(raw_secrets) > 0

    out_dir = tmp_path / "html_leak_test"
    res = execute_pipeline(
        extraction=EXTRACTION_DIR,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir,
    )

    html_path = res["report_html_path"]
    html_text = html_path.read_text(encoding="utf-8")

    for secret in raw_secrets:
        assert secret not in html_text, f"Raw secret leaked into report.html: {secret}"


def test_no_key_leak_in_stdout(tmp_path, capsys):
    """
    Ensure that running the pipeline CLI does not print raw key hex or base64 to console.
    """
    raw_secrets = _get_keychain_secrets()
    assert len(raw_secrets) > 0

    out_dir = tmp_path / "cli_leak_test"
    run_pipeline(
        extraction=EXTRACTION_DIR,
        keychain=KEYCHAIN_PATH,
        out_dir=out_dir,
    )

    captured = capsys.readouterr()
    full_output = captured.out + captured.err

    for secret in raw_secrets:
        assert secret not in full_output, f"Raw secret leaked into terminal output: {secret}"


def test_no_key_leak_spec_assertions(tmp_path):
    """
    Spec: No full key in hex appears in report.json or report.html.
    """
    from correlator.pipeline import run

    raw_secrets = _get_keychain_secrets()
    # Filter to only the hex representation of the keys
    hex_keys = [s for s in raw_secrets if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) in (64, 96)]
    assert len(hex_keys) > 0

    out_dir = tmp_path / "spec_leak_test"
    run(EXTRACTION_DIR, KEYCHAIN_PATH, out_dir)

    json_text = (out_dir / "report.json").read_text(encoding="utf-8")
    html_text = (out_dir / "report.html").read_text(encoding="utf-8")

    for key_hex in hex_keys:
        assert key_hex.lower() not in json_text.lower(), f"Full key hex found in report.json: {key_hex}"
        assert key_hex.lower() not in html_text.lower(), f"Full key hex found in report.html: {key_hex}"

