import pytest

from app.engine.auth_results import parse_authentication_results, policy_from_comment, property_domain
from helpers import gmail_auth


def test_parses_gmail_header():
    parsed = parse_authentication_results(gmail_auth("github.com"))
    assert parsed.authserv_id == "mx.google.com"
    assert [r.method for r in parsed.results] == ["dkim", "spf", "dmarc"]
    dmarc = parsed.first("dmarc")
    assert dmarc.result == "pass"
    assert dmarc.properties["header.from"] == "github.com"
    assert policy_from_comment(dmarc.comment) == {"p": "reject", "sp": "reject", "dis": "none"}
    assert parsed.first("spf").properties["smtp.mailfrom"] == "bounce@github.com"


def test_semicolon_inside_comment_does_not_split_results():
    raw = "mx.google.com; spf=pass (note; with semicolon) smtp.mailfrom=a@x.com; dmarc=fail header.from=x.com"
    parsed = parse_authentication_results(raw)
    assert [(r.method, r.result) for r in parsed.results] == [("spf", "pass"), ("dmarc", "fail")]


def test_multiple_dkim_signatures_are_kept():
    raw = "mx.google.com; dkim=pass header.i=@a.com; dkim=fail header.i=@b.com; spf=none"
    parsed = parse_authentication_results(raw)
    assert [d.result for d in parsed.all("dkim")] == ["pass", "fail"]


def test_missing_authserv_id_is_rejected():
    with pytest.raises(ValueError):
        parse_authentication_results("spf=pass smtp.mailfrom=a@x.com")


@pytest.mark.parametrize("raw", ["", "   ", ";;;", "mx.google.com; (unclosed comment", "mx.google.com; ===; spf"])
def test_malformed_headers_never_crash(raw):
    try:
        parse_authentication_results(raw)
    except ValueError:
        pass


def test_property_domain():
    assert property_domain("a@x.com") == "x.com"
    assert property_domain("@x.com") == "x.com"
    assert property_domain("x.com") == "x.com"
    assert property_domain(None) is None
