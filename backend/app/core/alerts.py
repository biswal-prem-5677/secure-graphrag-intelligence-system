"""
AlertEngine: Evaluates telemetry streams against operational alert thresholds and raises anomaly alerts.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
from app.core.logging import get_logger

logger = get_logger("core_alerts")


class AnomalyAlert(BaseModel):
    id: str
    title: str
    severity: str  # "WARNING" or "CRITICAL"
    description: str
    timestamp: float = Field(default_factory=time.time)


class AlertEngine:
    """Evaluates telemetry streams against operational alert thresholds."""

    def __init__(self) -> None:
        self._alerts: List[AnomalyAlert] = []

    def evaluate_telemetry(self, telemetry: Dict[str, Any]) -> List[AnomalyAlert]:
        """Check for operational anomalies."""
        new_alerts: List[AnomalyAlert] = []
        error_rate = telemetry.get("error_rate_percent", 0.0)
        p95_latency = telemetry.get("p95_latency_ms", 0.0)
        total_requests = telemetry.get("total_requests", 0)

        # Check Error Rate Spike
        if error_rate >= 10.0 and total_requests >= 5:
            alert = AnomalyAlert(
                id=f"alert-err-{int(time.time())}",
                title="Error Rate Spike Detected",
                severity="CRITICAL",
                description=f"Error rate reached {error_rate:.1f}% over {total_requests} requests.",
            )
            new_alerts.append(alert)
            self._alerts.append(alert)
            logger.warning("alert_error_rate_spike", error_rate=error_rate)

        # Check Latency Degradation
        if p95_latency >= 3000.0 and total_requests >= 5:
            alert = AnomalyAlert(
                id=f"alert-lat-{int(time.time())}",
                title="P95 Latency Degradation",
                severity="WARNING",
                description=f"P95 query latency degraded to {p95_latency:.1f} ms.",
            )
            new_alerts.append(alert)
            self._alerts.append(alert)
            logger.warning("alert_latency_degraded", p95=p95_latency)

        return new_alerts

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        return [a.model_dump() for a in self._alerts[-50:]]


alert_engine = AlertEngine()


# Legacy helper functions
def emit_alert(severity: str, message: str, **context: Any) -> None:
    logger.warning("legacy_alert", severity=severity, message=message, **context)


def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    return alert_engine.get_active_alerts()[:limit]
