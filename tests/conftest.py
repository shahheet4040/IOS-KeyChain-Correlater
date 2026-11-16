import sys
from pathlib import Path

# Ensure virtualenv site-packages and src are on sys.path
_root = Path(__file__).resolve().parent.parent
_venv_site = _root / ".venv" / "Lib" / "site-packages"
_src = _root / "src"

if _venv_site.is_dir() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))
