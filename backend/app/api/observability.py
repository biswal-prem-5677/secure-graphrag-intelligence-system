"""
Public and admin observability summary endpoints.
"""
from typing import Any, Dict
from fastapi import APIRouter
from app.cache.cache import query_cache
from app.core.alerts import alert_engine
from app.core.telemetry import telemetry_store
from app.evaluation.cost_tracker import cost_tracker

router = APIRouter(prefix="/api/v1/observability", tags=["Observability"])


@router.get("/health")
async def get_system_health() -> Dict[str, Any]:
    """Public system health and performance summary (no auth required)."""
    metrics = telemetry_store.get_metrics()
    status_str = "HEALTHY"
    if metrics["error_rate_percent"] > 5.0 or metrics["avg_latency_ms"] > 3000.0:
        status_str = "DEGRADED"
    if metrics["error_rate_percent"] > 25.0:
        status_str = "CRITICAL"
    return {
        "status": status_str,
        "avg_latency_ms": metrics["avg_latency_ms"],
        "p95_latency_ms": metrics["p95_latency_ms"],
        "cache_hit_ratio": metrics["hit_ratio_percent"],
    }


@router.get("/summary")
async def get_observability_summary() -> Dict[str, Any]:
    """Full observability summary including telemetry, cost, and cache metrics."""
    return {
        "telemetry": telemetry_store.get_metrics(),
        "cache": query_cache.get_stats(),
        "costs": cost_tracker.get_summary(),
        "active_alerts": alert_engine.get_active_alerts(),
    }
