import os
import sys
from pathlib import Path
import pytest

tests_dir = Path(__file__).resolve().parent
backend_dir = tests_dir.parent
proj_root = backend_dir.parent

if str(proj_root) not in sys.path:
    sys.path.insert(0, str(proj_root))

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


os.environ["DATABASE_URL"] = "sqlite:///./data/test_secure_graphrag.db"
os.environ["SEED_DEFAULT_USERS"] = "true"


@pytest.fixture(autouse=True)
def reset_test_state():
    """Clear query cache, reset database tables, and re-seed default test users."""
    try:
        from app.cache.cache import query_cache
        query_cache.clear()
    except Exception:
        pass

    try:
        from app.db.database import SessionLocal, init_db
        from app.db.models import (
            DBFeedback,
            DBProfile,
            DBSavedInvestigation,
            DBSessionContext,
            DBSubscription,
            DBUser,
            DBUserMemory,
            DBUserUsage,
        )
        from app.security.auth import seed_default_users

        init_db()
        db = SessionLocal()
        try:
            db.query(DBFeedback).delete()
            db.query(DBSavedInvestigation).delete()
            db.query(DBSessionContext).delete()
            db.query(DBUserMemory).delete()
            db.query(DBUserUsage).delete()
            db.query(DBSubscription).delete()
            db.query(DBProfile).delete()
            db.query(DBUser).delete()
            db.commit()
        finally:
            db.close()

        seed_default_users()

        from app.models.user import User, UserRole, user_store
        from app.security.auth import hash_password
        import uuid
        unit_test_users = [
            "billing_analyst",
            "analyst_prod",
            "analyst_1",
            "analyst_2",
            "analyst_fb",
            "user_a",
            "user_b",
            "analyst_concise",
            "user_gdpr",
            "user_test",
            "user_1",
            "user_2",
            "user_x",
        ]
        for uname in unit_test_users:
            if not user_store.user_exists(uname):
                user_store.add_user(
                    User(
                        id=f"test-uuid-{uname}",
                        username=uname,
                        role=UserRole.analyst,
                        hashed_password=hash_password("TestPass123!"),
                        email=f"{uname}@test.local",
                    )
                )
    except Exception:
        pass

    yield

    try:
        from app.cache.cache import query_cache
        query_cache.clear()
    except Exception:
        pass

