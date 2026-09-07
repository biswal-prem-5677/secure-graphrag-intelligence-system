import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_observability_public_and_admin():
    # Public health summary
    resp = client.get("/api/v1/observability/health")
    assert resp.status_code == 200
    assert "status" in resp.json()

    # Admin summary
    login_resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "SecureAdmin2024!"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    obs_resp = client.get("/api/v1/admin/observability", headers=headers)
    assert obs_resp.status_code == 200
    assert "total_requests" in obs_resp.json()
