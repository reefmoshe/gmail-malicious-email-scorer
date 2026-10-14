import logging

from app import engine
from app.engine.models import Check
from helpers import check_status, gmail_auth, run


def test_failed_check_is_isolated_reported_and_not_logged_with_content(monkeypatch, caplog):
    def explode(ctx):
        raise RuntimeError(f"secret content {ctx.sender.address}")

    broken = Check("display_name", "sender_identity", "Sender name impersonation", explode)
    monkeypatch.setattr(engine, "CHECKS", tuple(broken if c.id == "display_name" else c for c in engine.CHECKS))

    with caplog.at_level(logging.WARNING):
        result = run(sender="PayPal <x@paypa1.com>", auth_results=gmail_auth("paypa1.com"))

    assert check_status(result, "display_name") == "failed"
    assert check_status(result, "lookalike_domains") == "completed"
    assert any("failed unexpectedly" in limitation for limitation in result.coverage.limitations)
    sender_category = next(c for c in result.categories if c.id == "sender_identity")
    assert sender_category.status == "partial"
    assert "RuntimeError" in caplog.text
    assert "secret content" not in caplog.text and "paypa1" not in caplog.text


def test_no_usable_data_is_inconclusive_not_safe():
    result = run(sender="", auth_results=None)
    assert result.verdict == "INCONCLUSIVE"
    assert result.score is None


def test_categories_without_collected_data_are_not_available():
    """An older add-on sends no links, attachments or text: reported, never treated as clean."""
    result = run(sender="A <a@acme.com>", auth_results=gmail_auth("acme.com"))
    statuses = {c.id: c.status for c in result.categories}
    assert statuses == {
        "authentication": "completed",
        "sender_identity": "completed",
        "urls": "not_available",
        "attachments": "not_available",
        "content": "not_available",
        "combined": "not_available",
        "organization": "not_applicable",  # no organization configured
    }
    assert check_status(result, "attachments") == "not_available"


def test_empty_collections_are_not_applicable_not_missing():
    result = run(sender="A <a@acme.com>", auth_results=gmail_auth("acme.com"), links=[], attachments=[], body_text="")
    statuses = {c.id: c.status for c in result.categories}
    assert statuses["urls"] == statuses["attachments"] == "not_applicable"
    assert statuses["content"] == "completed"


def test_max_attainable_score_with_both_categories_allows_malicious():
    result = run(sender="A <a@acme.com>", auth_results=gmail_auth("acme.com"))
    assert result.coverage.max_attainable_score == 75
    assert not any("not MALICIOUS" in limitation for limitation in result.coverage.limitations)


def test_unreachable_malicious_verdict_is_stated_explicitly():
    """Without authentication results only sender identity (cap 45) can contribute."""
    result = run(sender="A <a@acme.com>", auth_results=None)
    assert result.coverage.max_attainable_score == 45
    assert any("not MALICIOUS" in limitation for limitation in result.coverage.limitations)


def test_low_risk_summary_never_claims_the_email_is_safe():
    result = run(sender="A <a@acme.com>", auth_results=gmail_auth("acme.com"))
    assert result.verdict == "LOW_RISK"
    assert "not a guarantee" in result.summary
