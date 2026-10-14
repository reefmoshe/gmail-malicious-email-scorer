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
        ("upw1nd.io", "Upwind", "look-alike characters"),
        ("rnicrosoft.com", "Microsoft", "look-alike characters"),
        ("paypal.top", "PayPal", "different domain ending"),
        ("paypall.com", "PayPal", "typo"),
        ("micorsoft.com", "Microsoft", "typo"),
        ("paypal-secure-login.com", "PayPal", "security words"),
        ("secure-paypai.com", "PayPal", "security words"),
        ("paypal.com.account-verify.net", "PayPal", "subdomain"),
        ("bankhapoalim-online.co.il", "Bank Hapoalim", "security words"),
        ("leumi-update.com", "Bank Leumi", "security words"),
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
        "paypal.net",               # verified owner: PayPal Inc. (RDAP)
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


# --- Reliability safeguards (binary: reliable detection or nothing) -----------------

@pytest.mark.parametrize(
    "domain, reason",
    [
        ("google-analytics.com", "verified Google-owned"),
        ("paypal-community.com", "verified PayPal-owned"),
        ("linkedin-learning.com", "verified LinkedIn-owned"),
        ("amazon-adsystem.com", "verified Amazon-owned"),
        ("leumi-card.co.il", "benign exception: separate company"),
        ("paypay.ne.jp", "benign exception + not a keyboard typo (l vs y)"),
        ("unwind.com", "dictionary word + not a keyboard typo (p vs n)"),
        ("upwind.com", "brand token is a dictionary word: other domain ending is not enough"),
        ("apple.xyz", "dictionary-word brand under another ending"),
        ("apple-store.co.il", "brand + ordinary word, no account/security word"),
        ("microsoft-events.com", "brand + ordinary word"),
        ("amazon-river-tours.com", "brand + ordinary words"),
        ("goggle.com", "o vs g are not neighbouring keys"),
    ],
)
def test_reliability_safeguards_prevent_false_positives(domain, reason):
    assert find_lookalike(normalize_domain(domain)) is None, reason


@pytest.mark.parametrize(
    "domain",
    ["amazom.com", "paypalsecure.com", "rnicrosoftlogin.com", "paypal.secure-login.xyz", "linkedin-l0gin.com", "apple-id-verify.com"],
)
def test_reliable_attack_patterns_are_still_detected(domain):
    assert find_lookalike(normalize_domain(domain)) is not None


def test_benign_exceptions_are_not_brand_ownership():
    """An exception only suppresses look-alike detection; the domain is not treated as the brand."""
    from app.engine.brands import BENIGN_LOOKALIKE_EXCEPTIONS, OFFICIAL_DOMAINS

    assert not set(BENIGN_LOOKALIKE_EXCEPTIONS) & OFFICIAL_DOMAINS


def test_exception_list_suppresses_an_otherwise_reliable_match(monkeypatch):
    from app.engine import domains

    assert domains.find_lookalike("paypal-secure-login.com") is not None
    monkeypatch.setattr(domains, "BENIGN_LOOKALIKE_EXCEPTIONS", {"paypal-secure-login.com": "test"})
    assert domains.find_lookalike("paypal-secure-login.com") is None


def test_several_techniques_on_one_domain_produce_one_match():
    match = find_lookalike("paypal.com.paypal-secure.net")
    assert match.brand == "PayPal"
    assert len(match.techniques) == 2  # brand-with-security-word and embedded official domain
