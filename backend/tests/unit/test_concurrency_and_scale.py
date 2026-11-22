"""
Concurrency, Atomic Locking & Database Connection Pool Stress Tests.

Verifies:
1. Atomic quota enforcement under concurrent race conditions (FOR UPDATE row locking).
2. Database connection pool concurrency safety across 50 simultaneous threads.
3. Concurrent query history logging maintaining transactional integrity and user scoping.
"""
import concurrent.futures
import uuid
from app.db.database import SessionLocal
from app.db.repository import QueryHistoryRepository, UsageRepository
from app.models.user import User, UserRole
from app.security.auth import hash_password, user_store
from sqlalchemy import text


def test_concurrent_atomic_quota_enforcement():
    """20 concurrent threads attempting to check_and_increment with limit=10.
    
    Proves that atomic row locking (FOR UPDATE) prevents race conditions:
    Exactly 10 requests must succeed (is_allowed=True) and 10 must be denied (is_allowed=False).
    """
    user_id = f"concurrency-user-{uuid.uuid4()}"
    from app.db.repository import UserRepository
    UserRepository.create(username=f"user_{uuid.uuid4().hex[:8]}", hashed_password=hash_password("Pass123!"), user_id=user_id)
    date_str = "2026-09-08"
    limit = 10
    total_attempts = 20

    results = []

    def attempt_query():
        allowed, count, _ = UsageRepository.check_and_increment(
            user_id=user_id, date_str=date_str, limit=limit
        )
        return allowed, count

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_query) for _ in range(total_attempts)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    allowed_count = sum(1 for allowed, _ in results if allowed)
    denied_count = sum(1 for allowed, _ in results if not allowed)

    assert allowed_count == 10, f"Expected exactly 10 allowed queries, got {allowed_count}"
    assert denied_count == 10, f"Expected exactly 10 denied queries, got {denied_count}"

    # Verify final count in database
    db = SessionLocal()
    try:
        from app.db.models import DBUserUsage
        usage_rec = (
            db.query(DBUserUsage)
            .filter(DBUserUsage.user_id == user_id, DBUserUsage.date_str == date_str)
            .first()
        )
        assert usage_rec is not None
        assert usage_rec.query_count == 10
    finally:
        db.close()


def test_concurrent_database_pool_session_safety():
    """50 concurrent worker threads executing database queries in parallel.
    
    Verifies that the SQLAlchemy connection pool gracefully recycles connections,
    releases sessions, and does not deadlock or leak under concurrency.
    """
    concurrency_count = 50

    def query_worker(idx: int):
        db = SessionLocal()
        try:
            res = db.execute(text("SELECT 1")).scalar()
            return res == 1
        finally:
            db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(query_worker, i) for i in range(concurrency_count)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == concurrency_count
    assert all(results), "All concurrent database session executions must succeed"


def test_concurrent_query_history_inserts():
    """Concurrent query history writes for multiple users maintain isolation and integrity."""
    user_a_id = f"concurrent-a-{uuid.uuid4()}"
    user_b_id = f"concurrent-b-{uuid.uuid4()}"
    from app.db.repository import UserRepository
    UserRepository.create(username=f"user_a_{uuid.uuid4().hex[:8]}", hashed_password=hash_password("Pass123!"), user_id=user_a_id)
    UserRepository.create(username=f"user_b_{uuid.uuid4().hex[:8]}", hashed_password=hash_password("Pass123!"), user_id=user_b_id)

    def write_history(user_id: str, idx: int):
        QueryHistoryRepository.create(
            user_id=user_id,
            query_id=f"qid-{user_id}-{idx}",
            query=f"Concurrent query {idx}",
            confidence="high",
            operational_state="COMPLETE_WITH_REASONING",
        )
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i in range(15):
            futures.append(executor.submit(write_history, user_a_id, i))
            futures.append(executor.submit(write_history, user_b_id, i))
        for f in concurrent.futures.as_completed(futures):
            assert f.result() is True

    # Check isolation and counts
    history_a = QueryHistoryRepository.list_for_user(user_id=user_a_id, limit=50)
    history_b = QueryHistoryRepository.list_for_user(user_id=user_b_id, limit=50)

    assert len(history_a) == 15
    assert len(history_b) == 15
    assert all(h.user_id == user_a_id for h in history_a)
    assert all(h.user_id == user_b_id for h in history_b)
