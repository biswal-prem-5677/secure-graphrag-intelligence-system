import pytest
from app.models.subscription import PlanTier, SubscriptionStatus, subscription_store
from app.models.usage import usage_tracker
from app.services.billing_service import billing_service


def test_billing_subscription_lifecycle():
    sub = subscription_store.get_subscription("billing_analyst")
    assert sub.plan_tier == PlanTier.free
    assert sub.status == SubscriptionStatus.active

    # Check daily limit for free tier
    limit = usage_tracker.get_daily_limit("billing_analyst")
    assert limit == 20

    # Simulate upgrade event
    event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": "billing_analyst",
                "customer": "cus_123",
                "subscription": "sub_123",
            }
        },
    }
    billing_service.process_webhook_event(event)

    sub_after = subscription_store.get_subscription("billing_analyst")
    assert sub_after.plan_tier == PlanTier.pro
    assert usage_tracker.get_daily_limit("billing_analyst") == 200
