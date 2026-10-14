import pytest

from app.engine.content import find_indicators
from helpers import check_status, counted, finding, gmail_auth, run


def text_only(body, subject="Hello", sender="Acme <info@acme.com>"):
    return run(sender=sender, subject=subject, auth_results=gmail_auth("acme.com"), body_text=body)


# --- Single keywords are not enough ---------------------------------------------------

@pytest.mark.parametrize(
    "body",
    [
        "Our summer sale is urgent! Don't miss out.",
        "Your password is never shared with partners.",
        "Meeting notes are confidential, please do not forward.",
        "Dear customer, thank you for your order.",
        "Your account dashboard has a new look.",
        "Invoice #123 is attached for your records.",
        "החשבון שלך עודכן בהצלחה. תודה!",
    ],
)
def test_keywords_without_a_request_are_ignored(body):
    assert counted(text_only(body)) == {}


def test_missing_text_is_not_available_and_empty_text_is_clean():
    assert check_status(run(sender="A <a@acme.com>"), "content") == "not_available"
    assert check_status(text_only(""), "content") == "completed"


# --- Requests ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "body",
    [
        "Please verify your password using the secure form.",
        "Kindly confirm your login details to keep access.",
        "Reply with the verification code we sent you.",
        "Click below to verify your account.",
        "יש לאמת את פרטי ההתחברות שלך.",
        "אנא הזן את הסיסמה שלך בטופס.",
    ],
)
def test_credential_requests_in_english_and_hebrew(body):
    assert "CONTENT_CREDENTIAL_REQUEST" in counted(text_only(body))


@pytest.mark.parametrize(
    "body",
    [
        "Please process a wire transfer of $24,500 to the vendor.",
        "Can you buy five gift cards and send me the codes?",
        "Please update our bank account details to the new IBAN below.",
        "נא לבצע העברה בנקאית לספק עוד היום.",
        "שימו לב לשינוי בפרטי חשבון הבנק שלנו.",
    ],
)
def test_financial_requests_in_english_and_hebrew(body):
    assert "CONTENT_FINANCIAL_REQUEST" in counted(text_only(body))


def test_bank_details_change_is_financial_not_a_credential_request():
    result = text_only("Please update our bank account details to the new IBAN below.")
    assert finding(result, "CONTENT_CREDENTIAL_REQUEST") is None


# --- Pressure tactics: only with a request, counted once -------------------------------------

def test_pressure_tactics_are_correlated():
    result = text_only(
        "Your account will be suspended. Act immediately! Verify your password now. "
        "Final notice, within 24 hours."
    )
    statuses = {f.signal_id: f.score_status for f in result.findings}
    pressure = [statuses[s] for s in ("CONTENT_ACCOUNT_THREAT", "CONTENT_URGENCY") if s in statuses]
    assert sorted(pressure) == ["correlated", "counted"]


def test_secrecy_counts_only_with_money():
    with_login = text_only("Keep this confidential. Please verify your password.")
    assert finding(with_login, "CONTENT_SECRECY") is None
    with_money = text_only("Keep this confidential. Please process a wire transfer today.")
    assert finding(with_money, "CONTENT_SECRECY") is not None


def test_content_category_cap_is_15():
    result = text_only(
        "Dear customer, your account will be suspended immediately. Verify your password now. "
        "Also please process a wire transfer and keep this confidential."
    )
    category = next(c for c in result.categories if c.id == "content")
    assert (category.score, category.cap) == (15, 15)


def test_legitimate_security_notification_stays_low_risk():
    """A real 'reset your password' notice is a known false-positive shape: low score, not suspicious."""
    result = run(
        sender="Google <no-reply@accounts.google.com>",
        auth_results=gmail_auth("google.com"),
        body_text="Your password was changed. If you did not change it, reset your password immediately.",
    )
    assert result.verdict == "LOW_RISK"


def test_evidence_snippets_are_bounded():
    found = find_indicators("", "Please verify your password. " * 50 + "x" * 5000)
    assert len(found.credential_request) <= 3
    assert all(len(s) <= 200 for s in found.credential_request)


def test_hostile_long_text_is_processed_quickly():
    import time

    start = time.perf_counter()
    find_indicators("", ("a" * 50 + " ") * 190 + "(" * 500)
    assert time.perf_counter() - start < 1.0
