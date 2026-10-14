"""Look-alike domains: sender and Reply-To domains that imitate a protected brand."""

from ..context import EmailContext
from ..domains import describe_domain, find_lookalike
from ..models import CheckOutcome, Detection


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.sender is None and not ctx.reply_to:
        return CheckOutcome("not_available", reason="No valid sender or Reply-To address was found.")

    outcome = CheckOutcome("completed")
    if ctx.sender:
        match = find_lookalike(ctx.sender.domain)
        if match:
            outcome.detections.append(
                Detection("SENDER_LOOKALIKE_DOMAIN", [_evidence(ctx.sender.domain, match)], subjects=frozenset({match.brand}))
            )

    reply_matches = [(addr, match) for addr in ctx.reply_to if (match := find_lookalike(addr.domain))]
    if reply_matches:
        outcome.detections.append(
            Detection(
                "SENDER_REPLYTO_LOOKALIKE",
                [_evidence(addr.domain, match) for addr, match in reply_matches],
                subjects=frozenset(match.brand for _, match in reply_matches),
            )
        )
    return outcome


def _evidence(domain: str, match) -> str:
    return f"{describe_domain(domain)} resembles {match.brand} ({match.official_domain}): it {match.technique}"
