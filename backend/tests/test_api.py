import pytest
from fastapi.testclient import TestClient

from app.main import app

TEST_KEY = "test-key-not-a-real-secret"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("API_KEY", TEST_KEY)
    return TestClient(app)


def _payload(**overrides):
    message = {
        "subject": "Your invoice",
        "sender": "Billing Team <billing@example.com>",
        "reply_to": None,
        "auth_results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
    }
    message.update(overrides)
    return {"message": message}


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_requires_api_key(client):
    assert client.post("/analyze", json=_payload()).status_code == 401


def test_analyze_rejects_wrong_api_key(client):
    response = client.post("/analyze", json=_payload(), headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_analyze_fails_closed_when_server_key_missing(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    response = TestClient(app).post(
        "/analyze", json=_payload(), headers={"X-API-Key": "anything"}
    )
    assert response.status_code == 503


def test_analyze_returns_live_result(client):
    response = client.post("/analyze", json=_payload(), headers={"X-API-Key": TEST_KEY})
    assert response.status_code == 200
    body = response.json()
    assert body["analysis_mode"] == "live"
    assert body["verdict"] in {"LOW_RISK", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"}
    assert 0 <= body["score"] <= 100


def test_analyze_rejects_oversized_field(client):
    response = client.post(
        "/analyze", json=_payload(subject="A" * 1001), headers={"X-API-Key": TEST_KEY}
    )
    assert response.status_code == 422


def test_analyze_rejects_unknown_fields(client):
    response = client.post(
        "/analyze", json=_payload(body_html="<script>"), headers={"X-API-Key": TEST_KEY}
    )
    assert response.status_code == 422


def test_rejects_oversized_body(client):
    response = client.post(
        "/analyze",
        content=b"x" * (64 * 1024 + 1),
        headers={"X-API-Key": TEST_KEY, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
