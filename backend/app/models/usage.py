"""
UsageTracker: Measures daily investigations per user with tier limits.
"""
from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Dict, Tuple
from pydantic import BaseModel
from app.core.config import settings
from app.models.subscription import PlanTier, subscription_store


class UsageStats(BaseModel):
    user_id: str
    plan_tier: PlanTier
    daily_count: int
    daily_limit: int
    resets_at: str


class UsageTracker:
    """Thread-safe usage tracker that measures daily investigations per user."""

    def __init__(self) -> None:
        self._usage: Dict[Tuple[str, str], int] = {}
        self._lock = Lock()

    def _get_current_date_str(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def get_daily_limit(self, user_id: str) -> int:
        """Get the daily query limit for the user based on their plan tier."""
        sub = subscription_store.get_subscription(user_id)
        if sub.plan_tier == PlanTier.enterprise:
            return 10000
        elif sub.plan_tier == PlanTier.pro:
            return settings.PRO_TIER_DAILY_QUERY_LIMIT
        return settings.FREE_TIER_DAILY_QUERY_LIMIT

    def get_current_usage(self, user_id: str) -> int:
        """Get today's query count for the user."""
        date_str = self._get_current_date_str()
        with self._lock:
            return self._usage.get((user_id, date_str), 0)

    def check_and_increment(self, user_id: str) -> Tuple[bool, int, int]:
        """Check quota and increment. Returns (allowed, current_count, limit)."""
        limit = self.get_daily_limit(user_id)
        date_str = self._get_current_date_str()
        with self._lock:
            current = self._usage.get((user_id, date_str), 0)
            if current >= limit:
                return False, current, limit
            self._usage[(user_id, date_str)] = current + 1
            return True, current + 1, limit

    def get_stats(self, user_id: str) -> UsageStats:
        """Get comprehensive usage statistics for dashboard display."""
        sub = subscription_store.get_subscription(user_id)
        current = self.get_current_usage(user_id)
        limit = self.get_daily_limit(user_id)
        return UsageStats(
            user_id=user_id,
            plan_tier=sub.plan_tier,
            daily_count=current,
            daily_limit=limit,
            resets_at="Midnight UTC",
        )

    def reset_for_testing(self) -> None:
        with self._lock:
            self._usage.clear()


usage_tracker = UsageTracker()
