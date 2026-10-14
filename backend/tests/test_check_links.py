import pytest

from helpers import check_status, counted, finding, gmail_auth, run

SENDER = "Acme <news@acme-store.com>"


def L(url, text=None):
    return {"url": url, "text": text}


def links_only(*links):
    """Authenticated, unremarkable sender: only link findings can appear."""
    return run(sender=SENDER, auth_results=gmail_auth("acme-store.com"), links=list(links))


# --- Status ---------------------------------------------------------------------------

def test_older_add_on_without_links_is_not_available():
    assert check_status(run(sender=SENDER), "links") == "not_available"


def test_message_without_links_is_not_applicable():
    assert check_status(links_only(), "links") == "not_applicable"


def test_unparseable_links_are_reported_not_scored():
    result = links_only(L("javascript:alert(1)"), L("http://"))
    assert counted(result) == {}
    assert "could not be interpreted" in next(c.reason for c in result.checks if c.id == "links")


# --- Legitimate links -----------------------------------------------------------------

def test_legitimate_newsletter_with_click_tracking_is_clean():
    result = links_only(
        L("https://acme.us1.list-manage.com", "www.acme-store.com"),
        L("https://click.e.acme-store.com", "acme-store.com"),
        L("https://www.acme-store.com"),
        L("https://nam02.safelinks.protection.outlook.com", "www.acme-store.com"),
    )
    assert counted(result) == {}


def test_brand_owned_domains_are_the_same_owner():
    assert counted(links_only(L("https://www.amazon.co.uk", "amazon.com"))) == {}


def test_non_domain_link_text_is_ignored():
    assert counted(links_only(L("https://evil.example", "Click here to view your invoice"))) == {}


# --- Signals --------------------------------------------------------------------------

def test_text_shows_one_site_but_link_goes_elsewhere():
    result = links_only(L("https://login-portal.example", "https://www.paypal.com"))
    assert finding(result, "URL_TEXT_HREF_MISMATCH").counted_points == 25
    assert result.verdict == "SUSPICIOUS"  # high severity: the floor applies


def test_lookalike_link_domain():
    assert counted(links_only(L("https://paypal-verify-login.com"))) == {"URL_LOOKALIKE_DOMAIN": 15}


def test_obfuscated_ip_link():
    f = finding(links_only(L("https://3232235777")), "URL_IP_HOST")
    assert f.counted_points == 15
    assert "192.168.1.1" in f.evidence[0] and "disguise" in f.evidence[0]


def test_at_trick():
    f = finding(links_only(L("https://paypal.com@evil.example")), "URL_USERINFO_AT")
    assert f.counted_points == 15 and "evil.example" in f.evidence[0]


def test_deeply_nested_subdomains():
    result = links_only(L("https://login.secure.account.verify.update.example.com"))
    assert counted(result) == {"URL_DECEPTIVE_STRUCTURE": 8}


def test_mixed_alphabet_domain_without_brand_match():
    domain = "exaмple.com".encode("idna").decode()  # Latin "exa" + Cyrillic "м" + "ple"
    result = links_only(L(f"https://{domain}"))
    assert "mixes letters" in finding(result, "URL_DECEPTIVE_STRUCTURE").evidence[0]


def test_suspicious_tld_shortener_and_plain_http_are_weak():
    result = links_only(L("https://promo.example.top"), L("https://bit.ly"), L("http://www.acme-store.com"))
    assert counted(result) == {"URL_SUSPICIOUS_TLD": 5, "URL_SHORTENER": 5, "URL_PLAIN_HTTP": 3}
    assert result.verdict == "LOW_RISK"


# --- Counting and correlation -----------------------------------------------------------

def test_many_links_count_each_signal_once_with_bounded_evidence():
    result = links_only(*[L(f"http://host{i}.example.com") for i in range(8)])
    f = finding(result, "URL_PLAIN_HTTP")
    assert f.counted_points == 3
    assert len(f.evidence) == 6 and f.evidence[-1] == "...and 3 more links"


def test_shortener_behind_deceptive_text_is_counted_once():
    result = links_only(L("https://bit.ly", "www.dhl.com"))
    assert counted(result) == {"URL_TEXT_HREF_MISMATCH": 25}
    assert finding(result, "URL_SHORTENER").score_status == "correlated"


def test_lookalike_destination_behind_brand_text_only_reinforces():
    result = links_only(L("https://paypal-verify-login.com", "www.paypal.com"))
    assert counted(result) == {"URL_TEXT_HREF_MISMATCH": 25, "URL_LOOKALIKE_DOMAIN": 5}
    assert finding(result, "URL_LOOKALIKE_DOMAIN").score_status == "reinforcing"


def test_links_category_cap_is_35():
    result = links_only(L("http://paypal.com@3232235777", "www.paypal.com"), L("https://paypal-verify-login.com"))
    category = next(c for c in result.categories if c.id == "urls")
    assert (category.score, category.cap) == (35, 35)


def test_link_to_senders_own_lookalike_domain_is_not_scored_twice():
    result = run(
        sender="PayPal Service <service@paypa1-secure.com>",
        auth_results=gmail_auth("paypa1-secure.com"),
        links=[L("https://login.paypa1-secure.com", "https://www.paypal.com")],
    )
    assert finding(result, "URL_LOOKALIKE_DOMAIN") is None
    assert "the sender's own domain" in finding(result, "URL_TEXT_HREF_MISMATCH").evidence[0]
    assert result.score == 65  # sender 35 + 5, link text 25


def test_independent_evidence_across_categories_reaches_malicious():
    result = run(
        sender="PayPal Service <service@paypa1-secure.com>",
        auth_results=gmail_auth("paypa1-secure.com"),
        links=[L("https://paypal-verify-login.com", "https://www.paypal.com")],
    )
    assert result.score == 70
    assert result.verdict == "MALICIOUS"


# --- Input validation --------------------------------------------------------------------

@pytest.mark.parametrize(
    "links",
    [
        [{"url": "https://a.com", "text": None, "extra": 1}],
        [{"url": "h" * 601}],
        [{"url": "https://a.com", "text": "t" * 201}],
        [{"url": "https://a.com"}] * 51,
    ],
)
def test_link_payload_limits_are_enforced(links):
    from pydantic import ValidationError

    from app.schemas import EmailMessage

    with pytest.raises(ValidationError):
        EmailMessage(sender=SENDER, links=links)
