import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_metrics_prometheus_compatible():
    resp = client.get("/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_requests" in data
    assert "cache" in data
