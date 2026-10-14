import pytest

from app.engine.urls import domain_in_text, parse_link


def test_parses_minimized_link():
    link = parse_link("https://login.paypal.com", None)
    assert (link.scheme, link.domain, link.registered, link.ip) == ("https", "login.paypal.com", "paypal.com", None)


@pytest.mark.parametrize(
    "url, ip, obfuscated",
    [
        ("http://192.0.2.1", "192.0.2.1", False),
        ("http://3232235777", "192.168.1.1", True),
        ("http://0xC0A80101", "192.168.1.1", True),
        ("http://0300.0250.01.01", "192.168.1.1", True),
        ("http://[2001:db8::1]", "2001:db8::1", False),
    ],
)
def test_ip_hosts_in_any_notation(url, ip, obfuscated):
    link = parse_link(url, None)
    assert (link.ip, link.ip_obfuscated) == (ip, obfuscated)


def test_userinfo_is_exposed_for_the_at_trick():
    assert parse_link("https://paypal.com@evil.example", None).username == "paypal.com"


@pytest.mark.parametrize(
    "url",
    ["javascript:alert(1)", "mailto:a@b.com", "ftp://x.com", "http://", "https://[::1", "not a url", "http://bad_host.com", ""],
)
def test_non_web_or_malformed_links_are_skipped(url):
    assert parse_link(url, None) is None


@pytest.mark.parametrize(
    "text, domain",
    [
        ("www.paypal.com", "www.paypal.com"),
        ("https://PayPal.com/signin?x=1", "paypal.com"),
        ("paypal.com", "paypal.com"),
        ("file.pdf", None),  # unknown suffix: not a domain
        ("Click here", None),
        ("", None),
        (None, None),
    ],
)
def test_domain_in_link_text(text, domain):
    assert domain_in_text(text) == domain
