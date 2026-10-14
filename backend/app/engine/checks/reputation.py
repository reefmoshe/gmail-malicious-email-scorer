"""Link reputation: domain-level threat intelligence for the hosts of the message's links.

Complements the heuristic link checks with independent, third-party evidence. Unknown,
unavailable or "no match" results are never treated as proof that a link is safe.
"""

import time

from ... import reputation
from ..context import EmailContext
from ..models import CheckOutcome, Detection
from ..urls import parse_link

_MAX_HOSTS = 50


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.links is None:
        return CheckOutcome("not_available", reason="Links were not collected by this version of the add-on.")
    if not ctx.links:
        return CheckOutcome("not_applicable", reason="The message contains no links.")
    if not reputation.is_configured():
        return CheckOutcome(
            "not_available",
            reason="Reputation lookups are switched off (no SAFE_BROWSING_API_KEY configured).",
        )

    hosts = []
    for link in ctx.links:
        parsed = parse_link(link.url, None)
        if parsed:
            hosts.append(parsed.domain or parsed.ip)
    hosts = list(dict.fromkeys(hosts))[:_MAX_HOSTS]
    if not hosts:
        return CheckOutcome("not_applicable", reason="No web links could be interpreted.")

    try:
        verdicts = reputation.lookup_hosts(hosts)
    except reputation.ReputationUnavailable as exc:
        return CheckOutcome("failed", reason=f"{reputation.PROVIDER_NAME} lookup unavailable: {exc}.")

    listed = [v for v in verdicts if v.threat_types]
    outcome = CheckOutcome(
        "completed",
        reason=f"{len(verdicts)} link host(s) checked at domain level with {reputation.PROVIDER_NAME}. "
        "No listing does not mean a link is safe: new phishing sites are often not listed yet, "
        "and specific pages are not checked.",
    )
    if listed:
        outcome.detections.append(
            Detection(
                "URL_REPUTATION_MALICIOUS",
                [
                    f"{reputation.PROVIDER_NAME} lists {v.host} as {', '.join(v.threat_types)} "
                    f"(domain-level match, {'cached result from' if v.from_cache else 'checked at'} "
                    f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(v.checked_at))})"
                    for v in listed[:5]
                ],
            )
        )
    return outcome
