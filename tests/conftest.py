import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
src = repo_root / "src"
if src.exists() and str(src) not in sys.path:
    sys.path.insert(0, str(src))
