"""
Administrator Observability & Quality endpoints (Admin role only).
"""
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from app.core.alerts import alert_engine
from app.core.telemetry import telemetry_store
from app.models.feedback import UserFeedback, feedback_store
from app.models.user import User
from app.security.auth import require_admin

router = APIRouter(prefix="/api/v1/admin", tags=["Administrator Observability & Quality"])


@router.get("/observability")
async def get_admin_observability(
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """Retrieve comprehensive real-time telemetry, token counts, and latency percentiles."""
    return telemetry_store.get_metrics()


@router.get("/quality")
async def get_admin_quality_metrics(
    current_user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """Retrieve aggregated quality metrics, ratings, and hallucination reports."""
    metrics = feedback_store.get_metrics()
    return metrics.model_dump()


@router.get("/traces")
async def get_recent_traces(
    limit: int = 50,
    current_user: User = Depends(require_admin),
) -> List[Dict[str, Any]]:
    """Retrieve recent investigation traces with stage timings and cost records."""
    return telemetry_store.get_recent_traces(limit=limit)


@router.get("/alerts")
async def get_alerts(
    current_user: User = Depends(require_admin),
) -> List[Dict[str, Any]]:
    """Retrieve active system health and anomaly detection alerts."""
    return alert_engine.get_active_alerts()


@router.get("/feedback-list", response_model=List[UserFeedback])
async def get_feedback_list(
    limit: int = 100,
    current_user: User = Depends(require_admin),
) -> List[UserFeedback]:
    """List raw user feedback entries for quality triage (Admin only)."""
    return feedback_store.list_feedback(limit=limit)
