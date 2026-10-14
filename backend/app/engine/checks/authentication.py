"""Sender authentication: interprets the SPF, DKIM and DMARC results recorded by Gmail.

Trust model: anyone can put an Authentication-Results header in a message they send,
so only results stamped with Gmail's own authserv-id are used. Missing or untrusted
results make the check "not_available" - never a pass and never a failure.

Correlation: DMARC is computed from SPF and DKIM (plus alignment with the From domain).
When Gmail evaluated DMARC, its result supersedes the individual mechanisms; SPF/DKIM
failures are still shown, but grouped under the DMARC finding so they are counted once.
"""

from ..auth_results import MethodResult, parse_authentication_results, policy_from_comment, property_domain
from ..context import EmailContext
from ..domains import describe_domain, normalize_domain, registered_domain
from ..models import CheckOutcome, Detection, PositiveFinding

TRUSTED_AUTHSERV_IDS = frozenset({"mx.google.com"})

_DKIM_FAILED = {"fail", "neutral", "permerror", "policy"}
_POLICY_WORDS = {
    "reject": "reject failing mail",
    "quarantine": "send failing mail to spam",
    "none": "only monitor failing mail",
}


def run(ctx: EmailContext) -> CheckOutcome:
    if not ctx.auth_results_raw:
        return CheckOutcome(
            "not_available",
            reason="The message carries no authentication results (normal for messages you sent yourself).",
        )
    try:
        parsed = parse_authentication_results(ctx.auth_results_raw)
    except ValueError:
        return CheckOutcome("not_available", reason="The authentication results could not be interpreted.")
    if parsed.authserv_id not in TRUSTED_AUTHSERV_IDS:
        return CheckOutcome(
            "not_available",
            reason="The authentication results were not added by Gmail, so they were ignored "
            "(senders can insert this header themselves).",
        )

    dmarc = parsed.first("dmarc")
    spf = parsed.first("spf")
    dkims = parsed.all("dkim")
    sender_registered = ctx.sender.registered_domain if ctx.sender else None

    header_from = registered_domain(normalize_domain(property_domain(dmarc.properties.get("header.from")))) if dmarc else None
    if header_from and sender_registered and header_from != sender_registered:
        return CheckOutcome(
            "not_available",
            reason="The authentication results refer to a different sender domain than the From address.",
        )

    summary = [_describe_spf(spf), _describe_dkim(dkims)]
    outcome = CheckOutcome("completed")

    if dmarc and dmarc.result == "pass":
        evidence = [f"DMARC: pass for {header_from or 'the sender domain'}", *summary]
        if not spf or spf.result != "pass":
            evidence.append("SPF did not pass, but the domain was verified through its signature (typical of forwarded mail).")
        outcome.positives.append(
            PositiveFinding(
                "AUTH_DMARC_PASS",
                "Sender domain verified (DMARC pass)",
                "Gmail confirmed the message really comes from the domain shown. This proves who sent "
                "it, not that the sender is trustworthy.",
                evidence,
            )
        )
        return outcome

    if dmarc and dmarc.result == "fail":
        policy = policy_from_comment(dmarc.comment)
        evidence = [_describe_dmarc_fail(header_from, policy), *summary]
        outcome.detections.append(Detection("AUTH_DMARC_FAIL", evidence, group="dmarc"))
        # The component failures explain the DMARC result; same group -> counted once.
        outcome.detections.extend(_component_detections(spf, dkims, group="dmarc"))
        return outcome

    # No DMARC verdict (no policy published, or a temporary/permanent error): SPF and DKIM
    # are independent mechanisms and are evaluated separately.
    outcome.detections.extend(_component_detections(spf, dkims, group=None))
    outcome.positives.extend(_aligned_passes(spf, dkims, sender_registered))
    if dmarc is None or dmarc.result == "none":
        outcome.reason = "The sender domain publishes no DMARC policy, so SPF and DKIM were evaluated individually."
    else:
        outcome.reason = f"DMARC could not be evaluated ({dmarc.result}); SPF and DKIM were evaluated individually."
    return outcome


def _component_detections(spf: MethodResult | None, dkims: list[MethodResult], group: str | None) -> list[Detection]:
    detections = []
    if spf and spf.result == "fail":
        detections.append(Detection("AUTH_SPF_FAIL", [_describe_spf(spf)], group=group))
    elif spf and spf.result == "softfail":
        detections.append(Detection("AUTH_SPF_SOFTFAIL", [_describe_spf(spf)], group=group))

    if not any(d.result == "pass" for d in dkims):
        failed = [d for d in dkims if d.result in _DKIM_FAILED]
        if failed:
            detections.append(Detection("AUTH_DKIM_FAIL", [_describe_one_dkim(d) for d in failed], group=group))
        elif not dkims or all(d.result == "none" for d in dkims):
            detections.append(Detection("AUTH_DKIM_NONE", ["DKIM: the message is not signed"], group=group))
    return detections


def _aligned_passes(spf: MethodResult | None, dkims: list[MethodResult], sender_registered: str | None) -> list[PositiveFinding]:
    positives = []
    aligned_dkim = [d for d in dkims if d.result == "pass" and _domain_of(d) == sender_registered]
    if sender_registered and aligned_dkim:
        positives.append(
            PositiveFinding(
                "AUTH_DKIM_ALIGNED_PASS",
                "Valid signature from the sender's domain (DKIM)",
                "The message is signed by the same domain it claims to come from.",
                [_describe_one_dkim(d) for d in aligned_dkim],
            )
        )
    if sender_registered and spf and spf.result == "pass" and _domain_of(spf) == sender_registered:
        positives.append(
            PositiveFinding(
                "AUTH_SPF_ALIGNED_PASS",
                "Sent from an authorized server (SPF)",
                "The delivering server is authorized by the sender's own domain.",
                [_describe_spf(spf)],
            )
        )
    return positives


def _domain_of(result: MethodResult) -> str | None:
    if result.method == "spf":
        raw = result.properties.get("smtp.mailfrom") or result.properties.get("smtp.helo")
    else:
        raw = result.properties.get("header.d") or result.properties.get("header.i")
    return registered_domain(normalize_domain(property_domain(raw)))


def _describe_dmarc_fail(header_from: str | None, policy: dict[str, str]) -> str:
    text = f"DMARC: fail for {describe_domain(header_from) if header_from else 'the sender domain'}"
    if policy.get("p") in _POLICY_WORDS:
        text += f" (the domain's policy is to {_POLICY_WORDS[policy['p']]})"
    return text


def _describe_spf(spf: MethodResult | None) -> str:
    if spf is None:
        return "SPF: no result"
    domain = _domain_of(spf)
    return f"SPF: {spf.result}" + (f" for {describe_domain(domain)}" if domain else "")


def _describe_one_dkim(dkim: MethodResult) -> str:
    domain = _domain_of(dkim)
    return f"DKIM: {dkim.result}" + (f" (signed by {describe_domain(domain)})" if domain else "")


def _describe_dkim(dkims: list[MethodResult]) -> str:
    if not dkims:
        return "DKIM: the message is not signed"
    return "; ".join(_describe_one_dkim(d) for d in dkims)
