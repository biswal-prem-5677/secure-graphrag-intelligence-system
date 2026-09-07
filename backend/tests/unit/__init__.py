import sys
from pathlib import Path

proj = Path(__file__).resolve().parents[3]
if str(proj) not in sys.path:
    sys.path.insert(0, str(proj))

backend = proj / "backend"
if str(backend) not in sys.path:
    sys.path.insert(0, str(backend))

app = backend / "app"
if str(app) not in sys.path:
    sys.path.insert(0, str(app))
