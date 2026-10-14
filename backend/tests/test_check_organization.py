import pytest

from app.engine.organization import configured_organization
from helpers import check_status, counted, finding, gmail_auth, run


@pytest.fixture
def upwind(monkeypatch):
    monkeypatch.setenv("ORG_DOMAINS", "upwind.io")
    monkeypatch.setenv("ORG_NAME", "Upwind")


def test_not_configured_is_not_applicable():
    result = run(sender="Upwind IT <it@upw1nd.io>")
    assert check_status(result, "organization") == "not_applicable"
    assert "ORG_DOMAINS" in next(c.reason for c in result.checks if c.id == "organization")


def test_configuration_parsing(monkeypatch):
    monkeypatch.setenv("ORG_DOMAINS", " Mail.Upwind.io , upwind.com,not a domain,")
    org = configured_organization()
    assert org.domains == ("upwind.io", "upwind.com")
    assert org.name == "Upwind"


def test_organization_is_never_inferred_from_the_gmail_address():
    assert configured_organization() is None


@pytest.mark.parametrize("domain", ["upw1nd.io", "upwind-security.com", "upwind.io.account-verify.net", "upwlnd.io"])
def test_lookalikes_of_the_organization(upwind, domain):
    result = run(sender=f"Team <team@{domain}>")
    assert counted(result).get("ORG_LOOKALIKE_DOMAIN") == 40


def test_reply_to_lookalike_of_the_organization(upwind):
    result = run(sender="A <a@partner.example>", reply_to="finance@upwind-billing.com")
    assert "Reply-To" in finding(result, "ORG_LOOKALIKE_DOMAIN").evidence[0]


@pytest.mark.parametrize(
    "sender",
    [
        "Upwind Team <team@upwind.io>",           # internal
        "Dana <dana@mail.upwind.io>",             # internal subdomain
        "Partner Co <hello@partner.example>",     # ordinary external sender
        "Unwind Spa <hi@unwind.com>",             # dictionary word, benign exception
        "Wind Surf <info@upwind.com>",            # other ending of a dictionary-word name: not enough
    ],
)
def test_internal_and_ordinary_external_senders_are_clean(upwind, sender):
    assert "ORG_LOOKALIKE_DOMAIN" not in counted(run(sender=sender))
    assert "ORG_EXTERNAL_IDENTITY_CLAIM" not in counted(run(sender=sender))


def test_external_sender_claiming_the_organization(upwind):
    result = run(sender="Upwind IT Support <helpdesk@gmail.com>")
    assert counted(result)["ORG_EXTERNAL_IDENTITY_CLAIM"] == 15


def test_external_sender_showing_an_internal_address(upwind):
    result = run(sender='"ceo@upwind.io" <ceo.office@outlook.com>')
    assert any("internal address" in e for e in finding(result, "ORG_EXTERNAL_IDENTITY_CLAIM").evidence)


def test_claim_on_a_lookalike_domain_only_reinforces(upwind):
    result = run(sender="Upwind Security <security@upw1nd.io>")
    assert counted(result) == {"ORG_LOOKALIKE_DOMAIN": 40, "ORG_EXTERNAL_IDENTITY_CLAIM": 5}


def test_internal_bec_combination(upwind):
    result = run(
        sender="Upwind Finance <finance.upwind@gmail.com>",
        body_text="Please process a wire transfer to our new supplier today.",
    )
    assert counted(result)["COMBINED_BEC_PATTERN"] == 20
    assert result.verdict == "SUSPICIOUS"


def test_global_brand_and_organization_are_not_double_counted(upwind):
    """Upwind is configured as the organization, not as a global brand."""
    result = run(sender="Team <team@upw1nd.io>")
    assert finding(result, "SENDER_LOOKALIKE_DOMAIN") is None
