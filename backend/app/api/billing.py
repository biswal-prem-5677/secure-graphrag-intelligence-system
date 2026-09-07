"""
Billing and subscription endpoints.
"""
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from app.core.logging import get_logger
from app.models.subscription import PlanTier, SubscriptionStatus, subscription_store
from app.models.usage import usage_tracker
from app.models.user import User
from app.security.auth import get_current_user
from app.services.billing_service import billing_service

logger = get_logger("api_billing")
router = APIRouter(prefix="/api/v1/billing", tags=["Billing & Subscriptions"])


@router.get("/subscription")
async def get_subscription_and_usage(current_user: User = Depends(get_current_user)):
    sub = subscription_store.get_subscription(current_user.username)
    stats = usage_tracker.get_stats(current_user.username)
    return {
        "user_id": current_user.username,
        "plan_tier": sub.plan_tier.value,
        "status": sub.status.value,
        "daily_count": stats.daily_count,
        "daily_limit": stats.daily_limit,
        "resets_at": stats.resets_at,
        "is_stripe_configured": billing_service.is_stripe_configured(),
    }


@router.post("/create-checkout-session")
async def create_checkout_session(
    current_user: User = Depends(get_current_user),
):
    """Create a Stripe Checkout Session for upgrading to Pro tier ($49/mo)."""
    success_url = "http://localhost:3000/billing?upgrade_success=true"
    cancel_url = "http://localhost:3000/billing?upgrade_canceled=true"
    res = billing_service.create_checkout_session(
        user_id=current_user.username,
        success_url=success_url,
        cancel_url=cancel_url,
    )
    return res


@router.post("/create-portal-session")
async def create_portal_session(
    current_user: User = Depends(get_current_user),
):
    """Create a Stripe Customer Billing Portal Session for managing active subscriptions."""
    return_url = "http://localhost:3000/billing"
    return billing_service.create_customer_portal_session(
        user_id=current_user.username, return_url=return_url
    )


@router.post("/webhook")
async def handle_stripe_webhook(
    request: Request, stripe_signature: str = Header(None, alias="stripe-signature")
):
    payload = await request.body()
    if not billing_service.verify_webhook_signature(payload, stripe_signature or ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Stripe signature")
    event_data = await request.json()
    billing_service.process_webhook_event(event_data)
    return {"status": "success"}


@router.post("/sandbox-upgrade")
async def sandbox_upgrade(current_user: User = Depends(get_current_user)):
    """Developer sandbox endpoint to test instant Pro plan tier upgrade."""
    sub = subscription_store.get_subscription(current_user.username)
    sub.plan_tier = PlanTier.pro
    sub.status = SubscriptionStatus.active
    subscription_store.update_subscription(sub)
    return {"message": "Upgraded to Pro tier in sandbox mode", "plan_tier": "pro"}


@router.post("/sandbox-downgrade")
async def sandbox_downgrade(current_user: User = Depends(get_current_user)):
    """Developer sandbox endpoint to test downgrading back to Free tier."""
    sub = subscription_store.get_subscription(current_user.username)
    sub.plan_tier = PlanTier.free
    sub.status = SubscriptionStatus.active
    subscription_store.update_subscription(sub)
    return {"message": "Downgraded to Free tier in sandbox mode", "plan_tier": "free"}
