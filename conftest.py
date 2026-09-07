import os
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

backend_dir = root / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

app_dir = str(backend_dir / "app")
if app_dir in sys.path:
    sys.path.remove(app_dir)

os.environ["ENVIRONMENT"] = "testing"
os.environ["LLM_PROVIDER"] = "mock"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-at-least-32-chars-long"
os.environ["DEFAULT_ADMIN_PASSWORD"] = "SecureAdmin2024!"
os.environ["DEFAULT_USER_PASSWORD"] = "SecureAnalyst2024!"
os.environ["NEO4J_URI"] = "bolt://localhost:7687"
os.environ["NEO4J_USER"] = "neo4j"
os.environ["NEO4J_PASSWORD"] = "graphrag_secure_2024"
os.environ["MAX_CONTEXT_TOKENS"] = "2000"
