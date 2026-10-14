"""On-demand AI explanation: /analyze never calls the provider; /explain does, once."""

import logging
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.explain import llm
from app.main import app

API_KEY = "test-backend-key"
ANTHROPIC_KEY = "sk-test-not-a-real-anthropic-key"
MESSAGE = {
    "subject": "Account notice",
    "sender": "PayPal Service <service@paypa1-secure.com>",
    "body_text": "Your account will be suspended within 24 hours. Please verify your password.",
    "links": [{"url": "https://paypal-verify-login.com", "text": "www.paypal.com"}],
    "attachments": [],
}


def ai_output(payload):
    result = payload["engine_result"]
    return {
        "summary": f"Rated {result['verdict']} with a risk score of {result['risk_score']}/100.",
        "key_reasons": ["The sender imitates PayPal."],
        "recommendation": "Do not click the link.",
        "limitations": None,
    }


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("API_KEY", API_KEY)
    return TestClient(app)


@pytest.fixture
def provider(monkeypatch):
    """Installs a fake provider and returns the list of calls it received."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    calls = []

    def fake(payload):
        calls.append(payload)
        return ai_output(payload)

    monkeypatch.setattr(llm, "call_provider", fake)
    return calls


def post(client, path, message=MESSAGE):
    response = client.post(path, json={"message": message}, headers={"X-API-Key": API_KEY})
    return response.status_code, response.json()


def test_opening_an_email_never_calls_the_provider(client, provider):
    status, body = post(client, "/analyze")
    assert status == 200
    assert provider == []
    assert body["explanation"]["source"] == "template"
    assert body["ai_explanation_available"] is True  # the add-on shows the button


def test_button_is_hidden_without_a_key(client):
    _, body = post(client, "/analyze")
    assert body["ai_explanation_available"] is False


def test_clicking_explain_calls_the_provider_once_and_keeps_the_engine_result(client, provider):
    _, analyzed = post(client, "/analyze")
    status, explained = post(client, "/explain")
    assert status == 200 and len(provider) == 1
    assert explained["explanation"]["source"] == "ai"
    for field in ("score", "verdict", "verdict_reason", "findings", "categories", "checks", "coverage"):
        assert explained[field] == analyzed[field]


def test_client_cannot_supply_its_own_score_or_verdict(client, provider):
    response = client.post(
        "/explain",
        json={"message": MESSAGE, "score": 0, "verdict": "LOW_RISK"},
        headers={"X-API-Key": API_KEY},
    )
    assert response.status_code == 422
    assert provider == []


def test_repeated_clicks_do_not_pay_twice(client, provider):
    post(client, "/explain")
    post(client, "/explain")
    assert len(provider) == 1


def test_concurrent_duplicate_clicks_make_a_single_provider_call(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    calls = []

    def slow_fake(payload):
        calls.append(payload)
        time.sleep(0.2)
        return ai_output(payload)

    monkeypatch.setattr(llm, "call_provider", slow_fake)
    from helpers import run

    result = run(**MESSAGE)
    threads = [threading.Thread(target=llm.generate, args=(result,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1


def test_explain_without_a_key_returns_the_template(client, monkeypatch):
    monkeypatch.setattr(llm, "call_provider", lambda payload: pytest.fail("provider must not be called"))
    status, body = post(client, "/explain")
    assert status == 200 and body["explanation"]["source"] == "template"


def test_provider_failure_returns_the_full_result_with_the_template(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)

    def broken(payload):
        raise ConnectionError("down")

    monkeypatch.setattr(llm, "call_provider", broken)
    status, body = post(client, "/explain")
    assert status == 200
    assert body["verdict"] == "MALICIOUS" or body["verdict"] == "SUSPICIOUS"
    assert body["findings"] and body["explanation"]["source"] == "template"


def test_explain_requires_the_backend_key(client, provider):
    response = client.post("/explain", json={"message": MESSAGE})
    assert response.status_code == 401
    assert provider == []


def test_logs_contain_no_email_content_or_credentials(client, provider, caplog):
    with caplog.at_level(logging.DEBUG):
        post(client, "/analyze")
        post(client, "/explain")
    assert "explain verdict=" in caplog.text
    for secret in (ANTHROPIC_KEY, API_KEY, "verify your password", "paypa1-secure.com", "PayPal Service"):
        assert secret not in caplog.text


def test_startup_warm_up_imports_the_sdk_only_when_enabled_and_makes_no_request(monkeypatch):
    started = []
    monkeypatch.setattr(llm.threading, "Thread", lambda **kw: type("T", (), {"start": lambda self: started.append(kw["name"])})())
    llm.warm_up()
    assert started == []  # no key: nothing happens
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    llm.warm_up()
    assert started == ["llm-warm-up"]


def test_warm_up_failure_never_breaks_startup(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def failing_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    monkeypatch.setattr(builtins, "__import__", failing_import)
    llm.warm_up()  # runs in a thread; must not raise


def test_the_app_runs_the_warm_up_when_it_starts(monkeypatch):
    calls = []
    monkeypatch.setattr(llm, "warm_up", lambda: calls.append("warm"))
    with TestClient(app):
        pass
    assert calls == ["warm"]
