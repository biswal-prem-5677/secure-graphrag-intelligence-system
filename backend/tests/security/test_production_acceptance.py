"""
Production Acceptance Security & Hardening Tests.

Verifies:
1. Production configuration fails closed on weak or placeholder secrets.
2. Normal users cannot access administrator endpoints (RBAC enforcement).
3. Developer sandbox upgrade/downgrade endpoints are absent (cannot self-upgrade).
4. User query history is isolated per authenticated user.
5. Email format validation rejects invalid inputs.
6. Oversized payloads (>10MB) are rejected with HTTP 413.
"""
import pytest
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import app
from app.models.user import User, UserRole
from app.security.auth import create_access_token, hash_password, user_store
from app.db.repository import QueryHistoryRepository

client = TestClient(app)


def test_production_config_fails_closed_on_weak_jwt():
    """Production mode must reject missing or <32 char JWT secret."""
    with pytest.raises(ValueError, match="JWT_SECRET_KEY"):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="too-short",
            DATABASE_URL="postgresql://user:pass@localhost:5432/db",
            ALLOWED_ORIGINS="https://app.example.com",
            DEFAULT_ADMIN_PASSWORD="StrongAdminPassword123!",
            DEFAULT_USER_PASSWORD="StrongUserPassword123!",
            REDIS_URL="redis://localhost:6379/0",
        )


def test_production_config_rejects_default_sqlite():
    """Production mode must reject SQLite database URL."""
    with pytest.raises(ValueError, match="DATABASE_URL is still the default SQLite path"):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="super-secure-production-jwt-key-minimum-32-chars-long",
            DATABASE_URL="sqlite:///./data/secure_graphrag.db",
            ALLOWED_ORIGINS="https://app.example.com",
            DEFAULT_ADMIN_PASSWORD="StrongAdminPassword123!",
            DEFAULT_USER_PASSWORD="StrongUserPassword123!",
            REDIS_URL="redis://localhost:6379/0",
        )


def test_production_config_rejects_missing_redis():
    """Production mode must require REDIS_URL for rate limiting."""
    with pytest.raises(ValueError, match="REDIS_URL must be set in production"):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="super-secure-production-jwt-key-minimum-32-chars-long",
            DATABASE_URL="postgresql://user:pass@localhost:5432/db",
            ALLOWED_ORIGINS="https://app.example.com",
            DEFAULT_ADMIN_PASSWORD="StrongAdminPassword123!",
            DEFAULT_USER_PASSWORD="StrongUserPassword123!",
            REDIS_URL="",
        )


def test_production_config_rejects_placeholder_stripe_when_enabled():
    """Production mode must reject placeholder stripe secret when STRIPE_ENABLED is True."""
    with pytest.raises(ValueError, match="STRIPE_SECRET_KEY"):
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="super-secure-production-jwt-key-minimum-32-chars-long",
            DATABASE_URL="postgresql://user:pass@localhost:5432/db",
            ALLOWED_ORIGINS="https://app.example.com",
            DEFAULT_ADMIN_PASSWORD="StrongAdminPassword123!",
            DEFAULT_USER_PASSWORD="StrongUserPassword123!",
            REDIS_URL="redis://localhost:6379/0",
            STRIPE_ENABLED=True,
            STRIPE_SECRET_KEY="",
        )


def test_normal_user_cannot_access_admin_endpoints():
    """Analyst user attempting to access /api/v1/admin/* endpoints receives 403 Forbidden."""
    analyst_user = User(
        id="analyst-test-id",
        username="analyst_test_user",
        role=UserRole.analyst,
        hashed_password=hash_password("Pass123!"),
    )
    user_store.add_user(analyst_user)
    token = create_access_token({"sub": "analyst_test_user", "role": "analyst"})
    headers = {"Authorization": f"Bearer {token}"}

    # Test all admin endpoints
    assert client.get("/api/v1/admin/observability", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/quality", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/traces", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/alerts", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/feedback-list", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/evaluations", headers=headers).status_code == 403
    assert client.post("/api/v1/admin/evaluations/run", headers=headers).status_code == 403


def test_sandbox_upgrade_endpoints_absent():
    """Developer sandbox upgrade endpoints must not exist (preventing unauthorized self-upgrades)."""
    analyst_user = User(
        id="analyst-test-id-2",
        username="analyst_test_user_2",
        role=UserRole.analyst,
        hashed_password=hash_password("Pass123!"),
    )
    user_store.add_user(analyst_user)
    token = create_access_token({"sub": "analyst_test_user_2", "role": "analyst"})
    headers = {"Authorization": f"Bearer {token}"}

    resp_upgrade = client.post("/api/v1/billing/sandbox-upgrade", headers=headers)
    assert resp_upgrade.status_code == 404

    resp_downgrade = client.post("/api/v1/billing/sandbox-downgrade", headers=headers)
    assert resp_downgrade.status_code == 404


def test_query_history_user_isolation():
    """Query history records created for user A must not be visible to user B."""
    user_a = User(
        id="user-a-history-id",
        username="user_a_history",
        role=UserRole.analyst,
        hashed_password=hash_password("Pass123!"),
    )
    user_b = User(
        id="user-b-history-id",
        username="user_b_history",
        role=UserRole.analyst,
        hashed_password=hash_password("Pass123!"),
    )
    user_store.add_user(user_a)
    user_store.add_user(user_b)

    # Insert history directly via repository for user A
    QueryHistoryRepository.create(
        user_id="user-a-history-id",
        query_id="query-a-123",
        query="What is APT29 TTP?",
        confidence="high",
        operational_state="COMPLETE_WITH_REASONING",
    )

    # List history for user B
    user_b_history = QueryHistoryRepository.list_for_user(user_id="user-b-history-id")
    user_b_query_ids = [h.query_id for h in user_b_history]
    assert "query-a-123" not in user_b_query_ids

    # List history for user A
    user_a_history = QueryHistoryRepository.list_for_user(user_id="user-a-history-id")
    user_a_query_ids = [h.query_id for h in user_a_history]
    assert "query-a-123" in user_a_query_ids


def test_registration_rejects_invalid_email_format():
    """Register request rejects malformed email strings."""
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "username": "bademailuser",
            "password": "ValidPassword123!",
            "email": "not-an-email-address",
        },
    )
    assert resp.status_code == 422


def test_oversized_payload_rejected_with_413():
    """Payloads exceeding the 10MB limit are rejected with HTTP 413."""
    headers = {"Content-Length": str(15 * 1024 * 1024)}  # 15 MB
    resp = client.post("/api/v1/auth/login", headers=headers, data=b"x")
    assert resp.status_code == 413
    assert "Payload Too Large" in resp.text
