import sys
from pathlib import Path
import pytest

# Ensure virtualenv site-packages, src, and harness are on sys.path
_root = Path(__file__).resolve().parent.parent
_venv_site = _root / ".venv" / "Lib" / "site-packages"
_src = _root / "src"
_harness = _root / "harness"

if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

if _harness.is_dir() and str(_harness) not in sys.path:
    sys.path.insert(0, str(_harness))


@pytest.fixture(scope="session", autouse=True)
def manage_test_fixtures():
    """Ensures that synthetic test fixtures (out/fake) exist during tests and cleans up after."""
    fake_dir = _root / "out" / "fake"
    keychain_file = fake_dir / "keychain.json"
    ground_truth = fake_dir / "ground_truth.json"
    report_file = fake_dir / "report.json"

    if not keychain_file.is_file() or not ground_truth.is_file() or not report_file.is_file():
        try:
            from make_fake_extraction import generate_fake_extraction
            generate_fake_extraction(fake_dir)
        except Exception as e:
            print(f"Notice: Synthetic fixture generation: {e}")

    yield

    # Automatic Teardown: purge all test artifacts so the tool and workspace remain clean for real data
    import shutil
    for folder in [_root / "cases_workspace", _root / "out"]:
        if folder.is_dir():
            for item in folder.iterdir():
                if item.name == ".gitkeep":
                    continue
                try:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        item.unlink(missing_ok=True)
                except Exception:
                    pass
