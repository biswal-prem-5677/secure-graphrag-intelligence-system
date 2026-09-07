"""
Subscription models and store for Stripe billing integration.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel, Field


class PlanTier(str, Enum):
    free = "free"
    pro = "pro"
    enterprise = "enterprise"


class SubscriptionStatus(str, Enum):
    active = "active"
    past_due = "past_due"
    canceled = "canceled"
    incomplete = "incomplete"


class Subscription(BaseModel):
    user_id: str
    plan_tier: PlanTier = PlanTier.free
    status: SubscriptionStatus = SubscriptionStatus.active
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool = False


class SubscriptionStore:
    """Thread-safe in-memory store for user subscriptions."""

    def __init__(self) -> None:
        self._subs: Dict[str, Subscription] = {}

    def get_subscription(self, user_id: str) -> Subscription:
        """Get or initialize default Free tier subscription for user."""
        if user_id not in self._subs:
            self._subs[user_id] = Subscription(user_id=user_id, plan_tier=PlanTier.free)
        return self._subs[user_id]

    def update_subscription(self, sub: Subscription) -> None:
        """Update or create user subscription record."""
        self._subs[sub.user_id] = sub

    def find_by_customer_id(self, customer_id: str) -> Optional[Subscription]:
        for sub in self._subs.values():
            if sub.stripe_customer_id == customer_id:
                return sub
        return None

    def find_by_subscription_id(self, subscription_id: str) -> Optional[Subscription]:
        for sub in self._subs.values():
            if sub.stripe_subscription_id == subscription_id:
                return sub
        return None


subscription_store = SubscriptionStore()
