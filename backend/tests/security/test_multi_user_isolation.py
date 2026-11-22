"""
Comprehensive production multi-user isolation and authorization test suite.
Verifies server-side enforcement preventing IDOR, cross-tenant data leakage,
and unauthorized access across all user-scoped subsystems.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User, UserRole, user_store
from app.models.saved import saved_store, SavedInvestigationCreate
from app.models.memory import memory_store
from app.models.profile import profile_store, UserProfile
from app.models.usage import usage_tracker
from app.models.subscription import subscription_store
from app.cache.cache import query_cache
from app.schemas.schemas import ConfidenceLevel, GraphData
from app.security.auth import create_access_token, hash_password


client = TestClient(app)


@pytest.fixture
def auth_tokens():
    """Create two distinct users in the database and return valid JWT Bearer headers."""
    user_a_name = "test_analyst_alice"
    user_b_name = "test_analyst_bob"

    # Register / ensure users exist
    if not user_store.user_exists(user_a_name):
        user_store.add_user(
            User(
                id="test-uuid-alice",
                username=user_a_name,
                role=UserRole.analyst,
                hashed_password=hash_password("AliceSecurePass123!"),
                email="alice@defense.gov",
            )
        )
    if not user_store.user_exists(user_b_name):
        user_store.add_user(
            User(
                id="test-uuid-bob",
                username=user_b_name,
                role=UserRole.analyst,
                hashed_password=hash_password("BobSecurePass456!"),
                email="bob@intel.mil",
            )
        )

    token_a = create_access_token({"sub": user_a_name, "role": "analyst"})
    token_b = create_access_token({"sub": user_b_name, "role": "analyst"})

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    return {
        "user_a": user_a_name,
        "user_b": user_b_name,
        "headers_a": headers_a,
        "headers_b": headers_b,
    }


def test_public_user_registration_flow():
    """Verify public registration, credential validation, and duplicate rejection."""
    import uuid
    unique_suffix = str(uuid.uuid4())[:8]
    username = f"new_cadet_{unique_suffix}"
    email = f"cadet_{unique_suffix}@soc.corp"

    # 1. Register new user
    res = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "StrongPassword999!", "email": email},
    )
    assert res.status_code == 201
    data = res.json()
    assert "access_token" in data
    assert data["username"] == username
    assert "password" not in data
    assert "hashed_password" not in data

    # 2. Reject duplicate username
    dup_user_res = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "StrongPassword999!", "email": f"diff_{unique_suffix}@soc.corp"},
    )
    assert dup_user_res.status_code == 400
    assert "already registered" in dup_user_res.json()["detail"].lower()

    # 3. Reject duplicate email
    dup_email_res = client.post(
        "/api/v1/auth/register",
        json={"username": f"other_{unique_suffix}", "password": "StrongPassword999!", "email": email},
    )
    assert dup_email_res.status_code == 400
    assert "already registered" in dup_email_res.json()["detail"].lower()

    # 4. Verify login with new credentials
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "StrongPassword999!"},
    )
    assert login_res.status_code == 200
    login_token = login_res.json()["access_token"]

    # 5. Verify /me endpoint returns sanitized data
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {login_token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == username
    assert me_data["email"] == email
    assert "password" not in me_data
    assert "hashed_password" not in me_data


def test_saved_investigation_idor_protection(auth_tokens):
    """Verify User B cannot view, retrieve, or delete User A's saved investigations."""
    # Alice saves an investigation
    save_payload = {
        "query_id": "qry-alice-001",
        "query": "Investigate APT29 intrusion vector",
        "title": "APT29 Classified Report",
        "answer": "APT29 utilized spear-phishing and compromised credentials.",
        "confidence": "HIGH",
        "confidence_explanation": "Verified across multi-source threat telemetry.",
        "graph_data": {"nodes": [], "edges": []},
        "relationship_paths": [],
        "evidence_records": [],
        "cited_sources": ["ThreatFeed-A"],
    }

    create_res = client.post("/api/v1/saved/", json=save_payload, headers=auth_tokens["headers_a"])
    assert create_res.status_code == 200
    saved_id = create_res.json()["id"]

    # Alice can retrieve her own investigation
    alice_get = client.get(f"/api/v1/saved/{saved_id}", headers=auth_tokens["headers_a"])
    assert alice_get.status_code == 200
    assert alice_get.json()["id"] == saved_id

    # Anti-IDOR: Bob CANNOT retrieve Alice's investigation
    bob_get = client.get(f"/api/v1/saved/{saved_id}", headers=auth_tokens["headers_b"])
    assert bob_get.status_code == 404
    assert "not found" in bob_get.json()["detail"].lower()

    # Bob's list does NOT contain Alice's investigation
    bob_list = client.get("/api/v1/saved/", headers=auth_tokens["headers_b"])
    assert bob_list.status_code == 200
    bob_item_ids = [item["id"] for item in bob_list.json()]
    assert saved_id not in bob_item_ids

    # Anti-IDOR: Bob CANNOT delete Alice's investigation
    bob_delete = client.delete(f"/api/v1/saved/{saved_id}", headers=auth_tokens["headers_b"])
    assert bob_delete.status_code == 404

    # Alice's investigation remains completely intact
    alice_verify = client.get(f"/api/v1/saved/{saved_id}", headers=auth_tokens["headers_a"])
    assert alice_verify.status_code == 200
    assert alice_verify.json()["id"] == saved_id

    # Alice deletes her own investigation
    alice_delete = client.delete(f"/api/v1/saved/{saved_id}", headers=auth_tokens["headers_a"])
    assert alice_delete.status_code == 200


def test_user_memory_cross_user_isolation(auth_tokens):
    """Verify that User A's persistent memory and preferences are never leaked to User B."""
    # Alice adds memory preference
    alice_mem = client.post(
        "/api/v1/memory/",
        json={"key": "preferred_language", "value": "Python"},
        headers=auth_tokens["headers_a"],
    )
    assert alice_mem.status_code == 200
    alice_mem_id = alice_mem.json()["id"]

    # Bob adds different memory preference
    bob_mem = client.post(
        "/api/v1/memory/",
        json={"key": "preferred_language", "value": "Rust"},
        headers=auth_tokens["headers_b"],
    )
    assert bob_mem.status_code == 200
    bob_mem_id = bob_mem.json()["id"]

    # Alice lists memory -> sees Python, not Rust
    alice_list = client.get("/api/v1/memory/", headers=auth_tokens["headers_a"])
    assert alice_list.status_code == 200
    alice_items = {m["key"]: m["value"] for m in alice_list.json()}
    assert alice_items.get("preferred_language") == "Python"

    # Bob lists memory -> sees Rust, not Python
    bob_list = client.get("/api/v1/memory/", headers=auth_tokens["headers_b"])
    assert bob_list.status_code == 200
    bob_items = {m["key"]: m["value"] for m in bob_list.json()}
    assert bob_items.get("preferred_language") == "Rust"

    # Anti-IDOR: Bob attempts to delete Alice's memory item -> rejected (404)
    del_res = client.delete(f"/api/v1/memory/{alice_mem_id}", headers=auth_tokens["headers_b"])
    assert del_res.status_code == 404

    # Verify Alice's memory is completely unchanged
    alice_verify = client.get("/api/v1/memory/", headers=auth_tokens["headers_a"])
    alice_items_after = {m["key"]: m["value"] for m in alice_verify.json()}
    assert alice_items_after.get("preferred_language") == "Python"


def test_user_profile_cross_user_isolation(auth_tokens):
    """Verify profile retrieval and updates are strictly isolated to the authenticated user."""
    # Alice updates her profile
    update_alice = client.put(
        "/api/v1/profile/",
        json={
            "display_name": "Alice Cyber Specialist",
            "team": "Red Team Defense",
            "role_title": "Lead Incident Responder",
            "preferences": {"concise_answers": True, "theme": "dark"},
        },
        headers=auth_tokens["headers_a"],
    )
    assert update_alice.status_code == 200

    # Bob updates his profile
    update_bob = client.put(
        "/api/v1/profile/",
        json={
            "display_name": "Bob Threat Hunter",
            "team": "Blue Team Operations",
            "role_title": "Senior Forensic Analyst",
            "preferences": {"concise_answers": False, "theme": "light"},
        },
        headers=auth_tokens["headers_b"],
    )
    assert update_bob.status_code == 200

    # Alice reads profile
    prof_a = client.get("/api/v1/profile/", headers=auth_tokens["headers_a"]).json()
    assert prof_a["display_name"] == "Alice Cyber Specialist"
    assert prof_a["team"] == "Red Team Defense"
    assert prof_a["preferences"]["concise_answers"] is True

    # Bob reads profile
    prof_b = client.get("/api/v1/profile/", headers=auth_tokens["headers_b"]).json()
    assert prof_b["display_name"] == "Bob Threat Hunter"
    assert prof_b["team"] == "Blue Team Operations"
    assert prof_b["preferences"]["concise_answers"] is False


def test_usage_and_subscription_isolation(auth_tokens):
    """Verify usage quotas and subscription tiers cannot bleed across tenants."""
    from app.models.subscription import PlanTier
    user_a = auth_tokens["user_a"]
    user_b = auth_tokens["user_b"]

    # Initial state
    initial_a = usage_tracker.get_current_usage(user_a)
    initial_b = usage_tracker.get_current_usage(user_b)

    # Record 5 queries for Alice
    for _ in range(5):
        usage_tracker.check_and_increment(user_a)

    usage_a = usage_tracker.get_current_usage(user_a)
    usage_b = usage_tracker.get_current_usage(user_b)

    # Alice usage incremented by 5
    assert usage_a == initial_a + 5
    # Bob usage remained untouched
    assert usage_b == initial_b

    # Alice upgrades to pro tier
    sub_a = subscription_store.get_subscription(user_a)
    sub_a.plan_tier = PlanTier.pro
    subscription_store.update_subscription(sub_a)

    sub_a = subscription_store.get_subscription(user_a)
    sub_b = subscription_store.get_subscription(user_b)

    assert sub_a.plan_tier == PlanTier.pro
    assert sub_b.plan_tier == PlanTier.free


def test_query_cache_user_isolation():
    """Verify query cache keys are scoped by user to avoid cross-user result leakage."""
    query_text = "What is the primary malware used by PHANTOM DRAGON?"
    res_alice = {"answer": "Private Alice intelligence report", "confidence": "HIGH"}
    res_bob = {"answer": "Bob customized intelligence report", "confidence": "HIGH"}

    # Alice caches her result
    query_cache.set(query_text, res_alice, user_id="alice_user")

    # Bob queries the exact same text
    cached_for_bob = query_cache.get(query_text, user_id="bob_user")
    assert cached_for_bob is None

    # Bob sets his own result
    query_cache.set(query_text, res_bob, user_id="bob_user")

    # Alice retrieves her cached result
    assert query_cache.get(query_text, user_id="alice_user") == res_alice
    # Bob retrieves his cached result
    assert query_cache.get(query_text, user_id="bob_user") == res_bob


def test_identity_lifecycle_and_query_relational_integrity():
    """
    Task 4 Integration Test:
    1. Register a new user.
    2. Verify a DBUser row exists.
    3. Verify its id is a UUID and differs from username.
    4. Login using username/password.
    5. Obtain JWT.
    6. Call protected POST /api/v1/query.
    7. Ensure usage/subscription creation succeeds.
    8. Ensure subscription.user_id equals DBUser.id.
    9. Ensure query_history.user_id equals DBUser.id.
    10. Ensure no username is stored in relational user_id foreign-key columns.
    11. Ensure the query does not produce a ForeignKeyViolation.
    """
    import uuid
    from app.db.database import SessionLocal
    from app.db.models import DBUser, DBSubscription, DBQueryHistory

    unique_id = str(uuid.uuid4())[:8]
    test_username = f"analyst_lifecycle_{unique_id}"
    test_password = "SecurePassword2026!"
    test_email = f"lifecycle_{unique_id}@intel.gov"

    # 1. Register new user
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"username": test_username, "password": test_password, "email": test_email},
    )
    assert reg_resp.status_code == 201, reg_resp.text

    # 2 & 3. Verify DBUser row exists, id is UUID and differs from username
    db = SessionLocal()
    try:
        db_user = db.query(DBUser).filter(DBUser.username == test_username).first()
        assert db_user is not None
        assert db_user.id != test_username
        assert len(db_user.id) == 36  # Canonical UUID length
        canonical_uuid = db_user.id

        # 4 & 5. Login and obtain JWT
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": test_username, "password": test_password},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 6 & 7. Call protected POST /api/v1/query
        q_resp = client.post(
            "/api/v1/query",
            json={"query": "What malware does PHANTOM DRAGON use?"},
            headers=headers,
        )
        assert q_resp.status_code == 200, f"Query failed with: {q_resp.text}"

        # 8. Ensure subscription.user_id equals DBUser.id (canonical UUID)
        sub = db.query(DBSubscription).filter(DBSubscription.user_id == canonical_uuid).first()
        assert sub is not None
        assert sub.user_id == canonical_uuid
        assert sub.user_id != test_username

        # 9. Ensure query_history.user_id equals DBUser.id
        q_hist = db.query(DBQueryHistory).filter(DBQueryHistory.user_id == canonical_uuid).first()
        assert q_hist is not None
        assert q_hist.user_id == canonical_uuid
        assert q_hist.user_id != test_username

        # 10. Ensure no username is stored in relational user_id FK columns
        sub_by_username = db.query(DBSubscription).filter(DBSubscription.user_id == test_username).first()
        assert sub_by_username is None, "Username must NOT be stored in relational foreign-key column"

        q_by_username = db.query(DBQueryHistory).filter(DBQueryHistory.user_id == test_username).first()
        assert q_by_username is None, "Username must NOT be stored in query_history foreign-key column"

    finally:
        db.close()


def test_legacy_repository_username_resolution_defense_in_depth(auth_tokens):
    """
    Task 5 Verification:
    Verify that passing a username accidentally through a legacy repository path
    resolves to the correct DBUser.id (UUID) rather than inserting an invalid FK
    or creating an unlinked record.
    """
    from app.db.database import SessionLocal
    from app.db.models import DBUser, DBSubscription
    from app.db.repository import _resolve_user_id, SubscriptionRepository

    db = SessionLocal()
    try:
        user_a_name = auth_tokens["user_a"]
        user_a = db.query(DBUser).filter(DBUser.username == user_a_name).first()
        assert user_a is not None

        # 1. Directly test _resolve_user_id
        resolved_from_username = _resolve_user_id(user_a_name, db)
        assert resolved_from_username == user_a.id

        resolved_from_uuid = _resolve_user_id(user_a.id, db)
        assert resolved_from_uuid == user_a.id

        # Non-existent identifier returned unchanged, never creates new user
        unknown_id = "non_existent_user_9999"
        resolved_unknown = _resolve_user_id(unknown_id, db)
        assert resolved_unknown == unknown_id
        assert db.query(DBUser).filter(DBUser.username == unknown_id).first() is None

        # 2. Call repository method with username identifier
        sub = SubscriptionRepository.get_or_create(user_id=user_a_name, db=db)
        assert sub.user_id == user_a.id
        assert sub.user_id != user_a_name
    finally:
        db.close()

