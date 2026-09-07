"""
Pytest configuration for Secure GraphRAG test suite. Sets test environment variables and loads path.
"""
import os
import sys
from pathlib import Path

# Ensure final_project root and backend root are on sys.path
backend_root = Path(__file__).resolve().parent
proj_root = backend_root.parent

# Put proj_root first so 'evaluation' resolves to final_project/evaluation
if str(proj_root) not in sys.path:
    sys.path.insert(0, str(proj_root))

if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

# Remove app from sys.path if present to avoid shadowing top-level packages
app_root = str(backend_root / "app")
if app_root in sys.path:
    sys.path.remove(app_root)

# Set deterministic testing environment variables
os.environ["ENVIRONMENT"] = "testing"
os.environ["LLM_PROVIDER"] = "mock"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-at-least-32-chars-long"
os.environ["DEFAULT_ADMIN_PASSWORD"] = "SecureAdmin2024!"
os.environ["DEFAULT_USER_PASSWORD"] = "SecureAnalyst2024!"
os.environ["NEO4J_URI"] = "bolt://localhost:7687"
os.environ["NEO4J_USER"] = "neo4j"
os.environ["NEO4J_PASSWORD"] = "graphrag_secure_2024"
os.environ["MAX_CONTEXT_TOKENS"] = "2000"
