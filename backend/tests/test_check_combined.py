from helpers import check_status, counted, finding, gmail_auth, run

WIRE = "Please process a wire transfer to our new supplier today."


def test_bec_from_free_mailbox_posing_as_executive():
    result = run(
        sender="Dana Levi CEO <dana.levi.ceo@gmail.com>",
        body_text=f"{WIRE} It is urgent. Keep this confidential, I'm in a meeting.",
    )
    assert counted(result)["COMBINED_BEC_PATTERN"] == 20
    assert result.verdict == "SUSPICIOUS"
    assert result.score == 47  # 12 identity + 10 request + 5 pressure + 20 combination


def test_bec_with_reply_diversion():
    result = run(
        sender="Dana (CFO) <dana@acme.com>",
        reply_to="dana.cfo.office@gmail.com",
        auth_results=gmail_auth("acme.com"),
        body_text="Please update our bank account details to the new IBAN below before paying the invoice.",
    )
    assert counted(result) == {"COMBINED_BEC_PATTERN": 20, "CONTENT_FINANCIAL_REQUEST": 10, "SENDER_REPLYTO_MISMATCH": 6}
    assert result.verdict == "SUSPICIOUS"


def test_authority_claim_in_text_from_free_mailbox():
    result = run(sender="Dana <dana.levi@gmail.com>", body_text=f"This is the CEO. {WIRE}")
    assert "COMBINED_BEC_PATTERN" in counted(result)


def test_payment_request_from_normal_business_sender_is_not_bec():
    result = run(
        sender="Acme Billing <billing@acme.com>",
        auth_results=gmail_auth("acme.com"),
        body_text="Please pay invoice #123 by the end of the month.",
    )
    assert finding(result, "COMBINED_BEC_PATTERN") is None
    assert result.verdict == "LOW_RISK"


def test_personal_free_mailbox_with_payment_but_no_claim_is_not_bec():
    result = run(sender="Dana Cohen <dana.cohen@gmail.com>", body_text="Can you pay me back for the concert tickets?")
    assert finding(result, "COMBINED_BEC_PATTERN") is None


def test_credential_request_from_brand_impersonator():
    result = run(
        sender="PayPal Service <service@paypa1-secure.com>",
        auth_results=gmail_auth("paypa1-secure.com"),
        body_text="Please verify your password to restore access.",
    )
    assert counted(result)["COMBINED_IMPERSONATION_REQUEST"] == 10


def test_no_request_means_no_combined_finding():
    result = run(sender="PayPal Service <service@paypa1-secure.com>", body_text="Thanks for being a customer.")
    assert finding(result, "COMBINED_IMPERSONATION_REQUEST") is None


def test_combined_needs_text():
    assert check_status(run(sender="A <a@acme.com>"), "combined") == "not_available"


def test_full_phishing_email_across_all_categories():
    result = run(
        sender="PayPal Service <service@paypa1-secure.com>",
        auth_results=gmail_auth("paypa1-secure.com"),
        body_text="Dear customer, your account will be suspended within 24 hours. Please verify your password.",
        links=[{"url": "https://paypal-verify-login.com", "text": "https://www.paypal.com"}],
        attachments=[{"filename": "PayPal_Form.html", "content_type": "text/html", "size": 2048}],
    )
    assert result.verdict == "MALICIOUS"
    assert result.score == 100
