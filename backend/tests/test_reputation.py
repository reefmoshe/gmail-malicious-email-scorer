"""Reputation layer with a fake Safe Browsing endpoint - no network access in tests."""

import io
import logging
import urllib.error

import pytest

from app import reputation
from helpers import check_status, counted, finding, gmail_auth, run

KEY = "fake-safe-browsing-key"


def L(url, text=None):
    return {"url": url, "text": text}


class FakeSafeBrowsing:
    def __init__(self, listed=None, error=None):
        self.listed = listed or {}
        self.error = error
        self.calls = []

    def __call__(self, url, body, timeout):
        self.calls.append((url, body, timeout))
        if self.error:
            raise self.error
        matches = []
        for entry in body["threatInfo"]["threatEntries"]:
            host = entry["url"].split("//", 1)[1].rstrip("/")
            if host in self.listed:
                matches.append({"threatType": self.listed[host], "threat": {"url": entry["url"]}, "cacheDuration": "300s"})
        return {"matches": matches} if matches else {}


@pytest.fixture
def provider(monkeypatch):
    def install(**kwargs):
        fake = FakeSafeBrowsing(**kwargs)
        monkeypatch.setenv("SAFE_BROWSING_API_KEY", KEY)
        monkeypatch.setattr(reputation, "_post_json", fake)
        return fake

    return install


def analyze(*links):
    return run(sender="Acme <news@acme.com>", auth_results=gmail_auth("acme.com"), links=list(links))


def test_not_configured_is_not_available_and_never_clean():
    result = analyze(L("https://evil.example"))
    assert check_status(result, "url_reputation") == "not_available"
    assert any("SAFE_BROWSING_API_KEY" in limitation for limitation in result.coverage.limitations)


def test_listed_host_is_independent_confirmation_and_raises_score_to_90(provider):
    provider(listed={"evil.example": "SOCIAL_ENGINEERING"})
    result = analyze(L("https://evil.example"), L("https://www.acme.com"))
    f = finding(result, "URL_REPUTATION_MALICIOUS")
    assert "SOCIAL_ENGINEERING" in f.evidence[0] and "domain-level" in f.evidence[0] and "UTC" in f.evidence[0]
    assert result.score >= 90 and result.verdict == "MALICIOUS"
    assert "threat intelligence" in result.verdict_reason


def test_no_listing_is_completed_but_not_reported_as_safe(provider):
    provider()
    result = analyze(L("https://www.acme.com"))
    assert check_status(result, "url_reputation") == "completed"
    assert counted(result) == {}
    assert not any(p.id.startswith("URL_REPUTATION") for p in result.positive_findings)
    assert "does not mean a link is safe" in next(c.reason for c in result.checks if c.id == "url_reputation")


def test_only_host_names_are_sent(provider):
    fake = provider()
    analyze(L("https://user@login.evil.example"), L("http://192.0.2.1"))
    entries = [e["url"] for e in fake.calls[0][1]["threatInfo"]["threatEntries"]]
    assert entries == ["http://login.evil.example/", "http://192.0.2.1/"]


def test_results_are_cached(provider):
    fake = provider()
    analyze(L("https://www.acme.com"))
    analyze(L("https://www.acme.com"))
    assert len(fake.calls) == 1


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("unreachable"),
        TimeoutError(),
        urllib.error.HTTPError("u", 500, "err", {}, io.BytesIO()),
        ValueError("bad json"),
    ],
)
def test_provider_failure_is_reported_and_analysis_continues(provider, error):
    provider(error=error)
    result = analyze(L("https://paypal-verify-login.com"))
    assert check_status(result, "url_reputation") == "failed"
    assert "URL_LOOKALIKE_DOMAIN" in counted(result)  # heuristics still work
    assert result.verdict == "SUSPICIOUS"


def test_rate_limit_backs_off_without_calling_again(provider):
    fake = provider(error=urllib.error.HTTPError("u", 429, "slow down", {"Retry-After": "120"}, io.BytesIO()))
    analyze(L("https://a.example"))
    result = analyze(L("https://b.example"))
    assert len(fake.calls) == 1
    assert "rate-limited" in next(c.reason for c in result.checks if c.id == "url_reputation")


def test_api_key_is_never_logged(provider, caplog):
    provider(error=urllib.error.URLError("down"))
    with caplog.at_level(logging.DEBUG):
        analyze(L("https://a.example"))
    assert KEY not in caplog.text


def test_reputation_and_heuristics_share_the_link_category_cap(provider):
    provider(listed={"paypal-verify-login.com": "SOCIAL_ENGINEERING"})
    result = analyze(L("https://paypal-verify-login.com", "www.paypal.com"))
    category = next(c for c in result.categories if c.id == "urls")
    assert category.score == 35  # no stacking beyond the cap; the floor carries the verdict
    assert result.score == 90
