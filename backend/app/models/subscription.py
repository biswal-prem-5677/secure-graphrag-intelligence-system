"""
Subscription models and persistent store for Stripe billing integration.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel, Field
from app.db.database import SessionLocal
from app.db.models import DBSubscription
from app.db.repository import SubscriptionRepository


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


def _to_pydantic_sub(db_sub: DBSubscription) -> Subscription:
    return Subscription(
        user_id=db_sub.user_id,
        plan_tier=PlanTier(db_sub.plan_tier),
        status=SubscriptionStatus(db_sub.status),
        stripe_customer_id=db_sub.stripe_customer_id,
        stripe_subscription_id=db_sub.stripe_subscription_id,
        current_period_end=db_sub.current_period_end,
        cancel_at_period_end=db_sub.cancel_at_period_end,
    )


class SubscriptionStore:
    """Thread-safe persistent store for user subscriptions."""

    def get_subscription(self, user_id: str) -> Subscription:
        """Get or initialize default Free tier subscription for user."""
        db_sub = SubscriptionRepository.get_or_create(user_id)
        return _to_pydantic_sub(db_sub)

    def update_subscription(self, sub: Subscription) -> None:
        """Update or create user subscription record."""
        db = SessionLocal()
        try:
            db_sub = db.query(DBSubscription).filter(DBSubscription.user_id == sub.user_id).first()
            if not db_sub:
                db_sub = DBSubscription(user_id=sub.user_id)
                db.add(db_sub)
            db_sub.plan_tier = sub.plan_tier.value
            db_sub.status = sub.status.value
            db_sub.stripe_customer_id = sub.stripe_customer_id
            db_sub.stripe_subscription_id = sub.stripe_subscription_id
            db_sub.current_period_end = sub.current_period_end
            db_sub.cancel_at_period_end = sub.cancel_at_period_end
            db.commit()
        finally:
            db.close()

    def find_by_customer_id(self, customer_id: str) -> Optional[Subscription]:
        db = SessionLocal()
        try:
            db_sub = db.query(DBSubscription).filter(DBSubscription.stripe_customer_id == customer_id).first()
            return _to_pydantic_sub(db_sub) if db_sub else None
        finally:
            db.close()

    def find_by_subscription_id(self, subscription_id: str) -> Optional[Subscription]:
        db = SessionLocal()
        try:
            db_sub = db.query(DBSubscription).filter(DBSubscription.stripe_subscription_id == subscription_id).first()
            return _to_pydantic_sub(db_sub) if db_sub else None
        finally:
            db.close()


subscription_store = SubscriptionStore()
