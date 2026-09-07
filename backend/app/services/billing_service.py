"""
BillingService: Stripe Payment Integration Service with sandbox and live capabilities.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict, Optional, Tuple
from app.core.config import settings
from app.core.logging import get_logger
from app.models.subscription import PlanTier, Subscription, SubscriptionStatus, subscription_store

logger = get_logger("billing_service")


class BillingService:
    """Stripe Payment Integration Service with sandbox and live capabilities."""

    def __init__(self) -> None:
        self.api_key = settings.STRIPE_SECRET_KEY
        self.webhook_secret = settings.STRIPE_WEBHOOK_SECRET
        self.pro_price_id = settings.STRIPE_PRO_PRICE_ID

    def is_stripe_configured(self) -> bool:
        """Check if live/test Stripe API credentials are set (not just a placeholder)."""
        return bool(self.api_key and not self.api_key.startswith("sk_test_placeholder"))

    def create_checkout_session(self, user_id: str, success_url: str, cancel_url: str) -> Dict[str, str]:
        """Create a Stripe Checkout Session for upgrading to Pro tier ($49/mo)."""
        if not self.is_stripe_configured():
            # Return mock sandbox checkout URL for testing & local development
            mock_url = f"http://localhost:3000/billing?mock_checkout=true&session_id=cs_test_mock_{user_id}&user={user_id}"
            return {"checkout_url": mock_url, "session_id": f"cs_test_mock_{user_id}"}

        try:
            import stripe
            stripe.api_key = self.api_key
            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[{"price": self.pro_price_id, "quantity": 1}],
                mode="subscription",
                success_url=success_url,
                cancel_url=cancel_url,
                client_reference_id=user_id,
                metadata={"user_id": user_id},
            )
            return {"checkout_url": session.url, "session_id": session.id}
        except Exception as e:
            logger.error("stripe_checkout_failed", error=str(e))
            raise RuntimeError(f"Stripe API error: {e}") from e

    def create_customer_portal_session(self, user_id: str, return_url: str) -> Dict[str, str]:
        """Generate a Stripe Customer Portal Session URL for managing active subscriptions."""
        sub = subscription_store.get_subscription(user_id)
        if not self.is_stripe_configured() or not sub.stripe_customer_id:
            mock_url = f"http://localhost:3000/billing?mock_portal=true&user={user_id}"
            return {"portal_url": mock_url}

        try:
            import stripe
            stripe.api_key = self.api_key
            session = stripe.billing_portal.Session.create(
                customer=sub.stripe_customer_id, return_url=return_url
            )
            return {"portal_url": session.url}
        except Exception as e:
            logger.error("stripe_portal_failed", error=str(e))
            raise RuntimeError(f"Stripe portal error: {e}") from e

    def verify_webhook_signature(self, payload_bytes: bytes, signature_header: str) -> bool:
        if not self.webhook_secret or self.webhook_secret.startswith("whsec_placeholder"):
            return True
        try:
            import stripe
            stripe.Webhook.construct_event(payload_bytes, signature_header, self.webhook_secret)
            return True
        except Exception:
            return False

    def process_webhook_event(self, event_data: Dict[str, Any]) -> None:
        """Process verified Stripe webhook events (checkout.session.completed, etc.)."""
        event_type = event_data.get("type")
        data_obj = event_data.get("data", {}).get("object", {})
        logger.info("processing_stripe_webhook", event_type=event_type)

        if event_type == "checkout.session.completed":
            user_id = data_obj.get("client_reference_id") or data_obj.get("metadata", {}).get("user_id")
            customer_id = data_obj.get("customer")
            sub_id = data_obj.get("subscription")
            if user_id:
                sub = subscription_store.get_subscription(user_id)
                sub.plan_tier = PlanTier.pro
                sub.status = SubscriptionStatus.active
                sub.stripe_customer_id = customer_id
                sub.stripe_subscription_id = sub_id
                subscription_store.update_subscription(sub)
                logger.info("user_upgraded_to_pro", user_id=user_id)

        elif event_type == "customer.subscription.deleted":
            sub_id = data_obj.get("id")
            sub = subscription_store.find_by_subscription_id(sub_id)
            if sub:
                sub.plan_tier = PlanTier.free
                sub.status = SubscriptionStatus.canceled
                subscription_store.update_subscription(sub)
                logger.info("subscription_canceled", user_id=sub.user_id)


billing_service = BillingService()
