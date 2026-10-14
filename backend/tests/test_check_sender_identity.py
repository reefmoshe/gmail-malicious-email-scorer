import pytest

from helpers import check_status, counted, finding, gmail_auth, run


def _auth(domain):
    return gmail_auth(domain)


# --- Display name ------------------------------------------------------------------

def test_brand_in_display_name_from_unrelated_domain():
    result = run(sender="PayPal <service@random-shop.com>", auth_results=_auth("random-shop.com"))
    assert counted(result) == {"SENDER_BRAND_DISPLAY_MISMATCH": 10}


@pytest.mark.parametrize("sender", ["PayPal <service@paypal.com>", "PayPal <service@mail.paypal.com>"])
def test_brand_in_display_name_from_official_domain_is_fine(sender):
    assert counted(run(sender=sender)) == {}


def test_brand_must_be_a_whole_word():
    assert counted(run(sender="Amazonas Tours <info@amazonas-travel.com>")) == {}


def test_display_name_with_foreign_address_is_flagged_once():
    """Display address and brand mention describe the same claim: counted once."""
    result = run(sender='"security@paypal.com" <alerts@evil-domain.xyz>')
    statuses = {f.signal_id: f.score_status for f in result.findings}
    assert set(statuses) == {"SENDER_DISPLAY_HAS_ADDRESS", "SENDER_BRAND_DISPLAY_MISMATCH"}
    assert sorted(statuses.values()) == ["correlated", "counted"]
    assert result.score == 10


def test_display_name_with_own_address_is_fine():
    assert counted(run(sender='"john@acme.com" <john@acme.com>')) == {}


def test_freemail_account_claiming_to_be_a_department():
    result = run(sender="IT Support <it.helpdesk.acme@gmail.com>")
    assert counted(result) == {"SENDER_FREEMAIL_ORG_CLAIM": 8}


def test_freemail_account_with_a_personal_name_is_fine():
    assert counted(run(sender="Dana Cohen <dana.cohen@gmail.com>")) == {}


def test_hebrew_brand_name_is_detected():
    result = run(sender="בנק הפועלים <service@bank-update.xyz>")
    assert "SENDER_BRAND_DISPLAY_MISMATCH" in counted(result)


def test_hebrew_common_word_is_not_a_brand():
    """'לאומי' alone means 'national' (e.g. National Insurance), not Bank Leumi."""
    assert counted(run(sender="ביטוח לאומי <info@btl.gov.il>")) == {}


@pytest.mark.parametrize("display", ["Pay​Pal", "PayPa1 Security", "PаyPal"])
def test_display_name_evasion_tricks_are_normalized(display):
    """Zero-width characters, digit swaps and Cyrillic letters do not hide the brand."""
    assert "SENDER_BRAND_DISPLAY_MISMATCH" in counted(run(sender=f"{display} <a@unrelated.example>"))


# --- Look-alike domains -------------------------------------------------------------

def test_lookalike_sender_domain():
    result = run(sender="Accounts <no-reply@paypa1.com>", auth_results=_auth("paypa1.com"))
    assert counted(result) == {"SENDER_LOOKALIKE_DOMAIN": 15}
    assert "paypal.com" in finding(result, "SENDER_LOOKALIKE_DOMAIN").evidence[0]


def test_lookalike_domain_with_idn_is_shown_in_punycode():
    result = run(sender="Accounts <no-reply@xn--pypal-4ve.com>")
    evidence = finding(result, "SENDER_LOOKALIKE_DOMAIN").evidence[0]
    assert "xn--pypal-4ve.com" in evidence


# --- Reply-To ------------------------------------------------------------------------

def test_no_reply_to_is_not_applicable():
    assert check_status(run(sender="A <a@acme.com>"), "reply_to") == "not_applicable"


def test_reply_to_same_organization_is_fine():
    assert counted(run(sender="A <a@mail.acme.com>", reply_to="support@acme.com")) == {}


def test_legitimate_different_reply_to_is_low_risk():
    """Newsletters and ticketing systems routinely use a different Reply-To."""
    result = run(
        sender="Shop News <news@shop.example>",
        reply_to="support@shop.zendesk.com",
        auth_results=_auth("shop.example"),
    )
    assert counted(result) == {"SENDER_REPLYTO_MISMATCH": 8}
    assert result.verdict == "LOW_RISK"


def test_reply_to_free_mailbox_is_explained():
    result = run(sender="CFO <cfo@acme.com>", reply_to="acme.cfo.office@gmail.com")
    assert "free personal mailbox" in finding(result, "SENDER_REPLYTO_MISMATCH").explanation


def test_multiple_reply_to_addresses_count_once_with_all_evidence():
    result = run(sender="A <a@acme.com>", reply_to="x@one.example, y@two.example")
    f = finding(result, "SENDER_REPLYTO_MISMATCH")
    assert f.counted_points == 8
    assert len(f.evidence) == 2


def test_reply_to_lookalike_supersedes_plain_mismatch():
    result = run(sender="A <a@acme.com>", reply_to="billing@paypal-support.net")
    assert counted(result) == {"SENDER_REPLYTO_LOOKALIKE": 15}
    assert finding(result, "SENDER_REPLYTO_MISMATCH").score_status == "correlated"


# --- Malformed input -----------------------------------------------------------------

@pytest.mark.parametrize("sender", ["", "<<<>>>", "no address here", "a@", "@nodomain", "x@bad_domain"])
def test_malformed_sender_makes_identity_checks_not_available(sender):
    result = run(sender=sender)
    assert check_status(result, "display_name") == "not_available"
    assert check_status(result, "lookalike_domains") == "not_available"
    assert counted(result) == {}
