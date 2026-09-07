import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_ready_endpoint():
    resp = client.get("/ready")
    assert resp.status_code == 200
    assert "status" in resp.json()


def test_login_and_protected_query_flow():
    # Login
    login_resp = client.post("/api/v1/auth/login", json={"username": "analyst", "password": "SecureAnalyst2024!"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Query
    q_resp = client.post(
        "/api/v1/query",
        json={"query": "What malware does PHANTOM DRAGON use?"},
        headers=headers,
    )
    assert q_resp.status_code == 200
    data = q_resp.json()
    assert "DragonScale" in data["answer"] or "PHANTOM DRAGON" in data["answer"]
    assert data["confidence"] in ("HIGH", "MEDIUM")
    assert data["operational_state"] == "TASK_COMPLETED"
