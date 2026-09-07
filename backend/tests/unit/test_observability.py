import pytest
from app.core.alerts import alert_engine
from app.core.telemetry import telemetry_store


def test_telemetry_recording_and_percentiles():
    telemetry_store.record_query("INV-TRC-TEST1", 100.0, "mock", 50, "HIGH")
    telemetry_store.record_query("INV-TRC-TEST2", 200.0, "mock", 75, "HIGH")
    telemetry_store.record_query("INV-TRC-TEST3", 300.0, "mock", 100, "HIGH")

    metrics = telemetry_store.get_metrics()
    assert metrics["total_requests"] >= 3
    assert metrics["p95_latency_ms"] >= 100.0


def test_anomaly_alert_engine():
    telemetry = {
        "error_rate_percent": 15.0,
        "p95_latency_ms": 3500.0,
        "total_requests": 10,
    }
    alerts = alert_engine.evaluate_telemetry(telemetry)
    assert len(alerts) == 2
    titles = [a.title for a in alerts]
    assert "Error Rate Spike Detected" in titles
    assert "P95 Latency Degradation" in titles
