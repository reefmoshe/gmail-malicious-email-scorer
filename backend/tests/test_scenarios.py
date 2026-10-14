"""Realistic end-to-end scenarios through the HTTP API, using the exact payload shape
the Gmail add-on sends (addon/Extract.gs)."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from helpers import gmail_auth

KEY = "test-key-not-a-real-secret"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("API_KEY", KEY)
    return TestClient(app)


def analyze(client, sender, reply_to=None, return_path=None, auth_results=None, subject="Hello"):
    payload = {
        "message": {
            "subject": subject,
            "sender": sender,
            "reply_to": reply_to,
            "return_path": return_path,
            "date": "2026-10-14T09:00:00.000Z",
            "auth_results": auth_results,
        }
    }
    response = client.post("/analyze", json=payload, headers={"X-API-Key": KEY})
    assert response.status_code == 200, response.text
    return response.json()


def counted(body):
    return {f["signal_id"]: f["counted_points"] for f in body["findings"] if f["counted_points"] > 0}


def test_legitimate_authenticated_notification(client):
    body = analyze(client, "GitHub <noreply@github.com>", auth_results=gmail_auth("github.com"))
    assert (body["verdict"], body["score"], counted(body)) == ("LOW_RISK", 0, {})
    assert body["positive_findings"][0]["id"] == "AUTH_DMARC_PASS"


def test_legitimate_newsletter_sent_through_an_email_service(client):
    body = analyze(
        client,
        "Acme Store <news@acme-store.com>",
        reply_to="help@acme-store.zendesk.com",
        return_path="bounce-123@em.sendgrid.net",
        auth_results=gmail_auth("acme-store.com", spf_domain="em.sendgrid.net"),
    )
    assert body["verdict"] == "LOW_RISK"
    assert body["score"] == 8


def test_forwarded_legitimate_mail(client):
    body = analyze(client, "Bank Hapoalim <info@bankhapoalim.co.il>", auth_results=gmail_auth("bankhapoalim.co.il", spf="fail"))
    assert (body["verdict"], body["score"]) == ("LOW_RISK", 0)


def test_spoofed_bank_domain(client):
    body = analyze(
        client,
        "Bank Leumi <alerts@leumi.co.il>",
        auth_results=gmail_auth("leumi.co.il", spf="softfail", dkim=None, dmarc="fail", policy="p=REJECT dis=QUARANTINE"),
    )
    assert body["verdict"] == "SUSPICIOUS"
    assert counted(body) == {"AUTH_DMARC_FAIL": 25}


def test_brand_impersonation_from_lookalike_domain(client):
    body = analyze(client, "PayPal Service <service@paypa1-secure.com>", auth_results=gmail_auth("paypa1-secure.com"))
    assert counted(body) == {"SENDER_LOOKALIKE_DOMAIN": 15, "SENDER_BRAND_DISPLAY_MISMATCH": 10}
    assert body["verdict"] == "SUSPICIOUS"
    assert body["positive_findings"][0]["id"] == "AUTH_DMARC_PASS"  # authenticated != trustworthy


def test_business_email_compromise_reply_diversion(client):
    """Header-only BEC evidence is weak by design: reported, but LOW_RISK until content
    analysis (financial request, urgency) is available."""
    body = analyze(client, "Dana Levi (CEO) <dana@acme.com>", reply_to="dana.levi.ceo@gmail.com", auth_results=gmail_auth("acme.com"))
    assert counted(body) == {"SENDER_REPLYTO_MISMATCH": 8}
    assert body["verdict"] == "LOW_RISK"
    assert "free personal mailbox" in body["findings"][0]["explanation"]


def test_combined_impersonation_without_authentication(client):
    body = analyze(
        client,
        "Microsoft 365 Security <alert@rnicrosoft-support.com>",
        reply_to="it@micr0soft-help.net",
        auth_results=gmail_auth("rnicrosoft-support.com", spf="fail", dkim=None, dmarc=None),
    )
    assert counted(body) == {
        "SENDER_LOOKALIKE_DOMAIN": 15,
        "SENDER_REPLYTO_LOOKALIKE": 10,  # capped: sender identity is capped at 25
        "AUTH_SPF_FAIL": 10,
        "AUTH_DKIM_NONE": 3,
    }
    assert body["score"] == 38
    assert body["verdict"] == "SUSPICIOUS"


def test_message_you_sent_yourself(client):
    body = analyze(client, "Me <me@gmail.com>", auth_results=None)
    assert body["verdict"] == "LOW_RISK"
    statuses = {c["id"]: c["status"] for c in body["checks"]}
    assert statuses["authentication_results"] == "not_available"
    assert any("authentication" in limitation.lower() for limitation in body["coverage"]["limitations"])


def test_response_contract_fields(client):
    body = analyze(client, "A <a@acme.com>", auth_results=gmail_auth("acme.com"))
    assert set(body) == {
        "analysis_mode", "score_type", "score", "verdict", "verdict_reason", "summary", "top_reasons",
        "findings", "positive_findings", "categories", "checks", "coverage", "engine_version",
    }
    assert body["analysis_mode"] == "live"
    assert body["score_type"] == "heuristic_risk_score"
