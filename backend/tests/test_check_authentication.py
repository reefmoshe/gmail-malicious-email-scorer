from helpers import check_status, counted, finding, gmail_auth, run

SENDER = "Acme Billing <billing@acme.com>"


def test_fully_authenticated_email_has_no_findings_and_a_positive():
    result = run(sender=SENDER, auth_results=gmail_auth("acme.com"))
    assert check_status(result, "authentication_results") == "completed"
    assert counted(result) == {}
    assert [p.id for p in result.positive_findings] == ["AUTH_DMARC_PASS"]
    assert result.verdict == "LOW_RISK"


def test_dmarc_fail_counts_once_and_components_are_correlated():
    auth = gmail_auth("acme.com", spf="softfail", dkim=None, dmarc="fail", policy="p=QUARANTINE dis=QUARANTINE")
    result = run(sender=SENDER, auth_results=auth)
    assert counted(result) == {"AUTH_DMARC_FAIL": 25}
    for component in ("AUTH_SPF_SOFTFAIL", "AUTH_DKIM_NONE"):
        f = finding(result, component)
        assert f.score_status == "correlated" and f.counted_points == 0
    assert "spam" in finding(result, "AUTH_DMARC_FAIL").evidence[0]


def test_dmarc_failure_alone_is_suspicious_not_malicious():
    result = run(sender=SENDER, auth_results=gmail_auth("acme.com", dmarc="fail"))
    assert result.verdict == "SUSPICIOUS"
    assert result.score == 25


def test_spf_failure_with_dmarc_pass_is_not_penalized():
    """Typical forwarded mail: SPF breaks, the DKIM signature still verifies the domain."""
    result = run(sender=SENDER, auth_results=gmail_auth("acme.com", spf="fail"))
    assert counted(result) == {}
    assert result.verdict == "LOW_RISK"
    assert any("forwarded" in e for e in result.positive_findings[0].evidence)


def test_without_dmarc_policy_spf_and_dkim_are_scored_independently():
    auth = gmail_auth("acme.com", spf="fail", dkim=None, dmarc="none", policy="")
    result = run(sender=SENDER, auth_results=auth)
    assert counted(result) == {"AUTH_SPF_FAIL": 10, "AUTH_DKIM_NONE": 3}
    assert result.verdict == "LOW_RISK"


def test_missing_dmarc_with_softfail_and_broken_signature():
    auth = gmail_auth("acme.com", spf="softfail", dkim="fail", dmarc=None)
    assert counted(run(sender=SENDER, auth_results=auth)) == {"AUTH_SPF_SOFTFAIL": 5, "AUTH_DKIM_FAIL": 8}


def test_one_valid_signature_outweighs_a_broken_one():
    auth = "mx.google.com; dkim=pass header.i=@acme.com; dkim=fail header.i=@esp.example; spf=pass smtp.mailfrom=a@acme.com"
    result = run(sender=SENDER, auth_results=auth)
    assert counted(result) == {}
    assert {p.id for p in result.positive_findings} == {"AUTH_DKIM_ALIGNED_PASS", "AUTH_SPF_ALIGNED_PASS"}


def test_temporary_dmarc_error_is_not_a_failure():
    result = run(sender=SENDER, auth_results=gmail_auth("acme.com", dmarc="temperror"))
    assert counted(result) == {}
    assert "temperror" in next(c.reason for c in result.checks if c.id == "authentication_results")


def test_missing_results_are_not_available_not_failed():
    result = run(sender=SENDER, auth_results=None)
    assert check_status(result, "authentication_results") == "not_available"
    assert counted(result) == {}
    assert any("authentication" in limitation.lower() for limitation in result.coverage.limitations)


def test_results_from_untrusted_server_are_ignored():
    """An attacker can add their own 'everything passed' header; it must not count."""
    forged = gmail_auth("acme.com", authserv_id="mail.attacker.example")
    result = run(sender=SENDER, auth_results=forged)
    assert check_status(result, "authentication_results") == "not_available"
    assert result.positive_findings == []


def test_results_for_a_different_sender_domain_are_ignored():
    result = run(sender=SENDER, auth_results=gmail_auth("other-domain.com"))
    assert check_status(result, "authentication_results") == "not_available"


def test_malformed_header_is_not_available():
    result = run(sender=SENDER, auth_results="spf=pass dmarc=pass")
    assert check_status(result, "authentication_results") == "not_available"
