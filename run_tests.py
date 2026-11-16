import sys
from pathlib import Path

_root = Path(__file__).resolve().parent
_venv_site = _root / ".venv" / "Lib" / "site-packages"
_src = _root / "src"

if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import pytest

if __name__ == "__main__":
    args = sys.argv[1:] if len(sys.argv) > 1 else ["-q"]
    sys.exit(pytest.main(args))
