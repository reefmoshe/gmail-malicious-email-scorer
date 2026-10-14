import pytest

from app.engine.domains import (
    edit_distance,
    find_lookalike,
    normalize_domain,
    registered_domain,
    skeleton,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("PayPal.COM", "paypal.com"),
        ("example.com.", "example.com"),
        ("pаypal.com", "xn--pypal-4ve.com"),  # Cyrillic "а" -> punycode
        ("bad domain.com", None),
        ("under_score.com", None),
        ("localhost", None),
        ("", None),
        (None, None),
        ("a" * 64 + ".com", None),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("mail.paypal.com", "paypal.com"),
        ("secure.bankhapoalim.co.il", "bankhapoalim.co.il"),
        ("paypal.com.account-verify.net", "account-verify.net"),
        ("attacker.github.io", "attacker.github.io"),  # PSL private section: separate owners
    ],
)
def test_registered_domain(domain, expected):
    assert registered_domain(domain) == expected


def test_skeleton_unifies_lookalike_characters():
    assert skeleton("paypa1") == skeleton("PayPal") == skeleton("pаypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")


def test_edit_distance_counts_adjacent_swap_as_one():
    assert edit_distance("microsoft", "micorsoft") == 1
    assert edit_distance("paypal", "paypall") == 1
    assert edit_distance("abc", "abc") == 0


@pytest.mark.parametrize(
    "domain, brand, technique_fragment",
    [
        ("paypa1.com", "PayPal", "look-alike characters"),
        ("xn--pypal-4ve.com", "PayPal", "look-alike characters"),
        ("xn--80ak6aa92e.com", "Apple", "look-alike characters"),  # "apple" spelled entirely in Cyrillic
        ("rnicrosoft.com", "Microsoft", "look-alike characters"),
        ("paypal.net", "PayPal", "different domain ending"),
        ("paypall.com", "PayPal", "typo"),
        ("micorsoft.com", "Microsoft", "typo"),
        ("paypal-secure-login.com", "PayPal", "other words"),
        ("secure-paypai.com", "PayPal", "other words"),
        ("paypal.com.account-verify.net", "PayPal", "subdomain"),
        ("upw1nd.io", "Upwind", "look-alike characters"),
        ("bankhapoalim-online.co.il", "Bank Hapoalim", "other words"),
        ("leumi-update.com", "Bank Leumi", "other words"),
    ],
)
def test_detects_lookalikes(domain, brand, technique_fragment):
    match = find_lookalike(domain)
    assert match is not None, domain
    assert match.brand == brand
    assert technique_fragment in match.technique


@pytest.mark.parametrize(
    "domain",
    [
        "paypal.com",
        "mail.paypal.com",          # subdomain of an official domain
        "google.co.il",             # official country domain
        "applebees.com",            # brand only as a substring, not a whole label
        "amazonas-tours.com",       # "amazonas" is not "amazon"
        "googleplex-fans.org",
        "office.co.il",             # generic word, deliberately not a brand token
        "outlook.com",
        "gmail.com",
        "github.com",
        "dhl-express-tracking.com",  # DHL has no token: three letters is too short to compare
    ],
)
def test_does_not_flag_legitimate_or_unrelated_domains(domain):
    assert find_lookalike(domain) is None


@pytest.mark.parametrize(
    "domain",
    ["ｐａｙｐａｌ.com", "PAYPAL.COM.", "email.paypal.com", "xn--zz.com", "xn--e1afmkfd.com"],  # last: "пример" (example)
)
def test_unicode_and_punycode_edge_cases_do_not_misfire(domain):
    """Full-width letters normalize to the official domain; invalid or unrelated
    punycode neither crashes nor matches a brand."""
    assert find_lookalike(normalize_domain(domain)) is None
