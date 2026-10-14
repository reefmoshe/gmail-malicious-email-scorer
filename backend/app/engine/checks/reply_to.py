"""Reply-To diversion: replies would go to a different organization than the sender.

Common in legitimate mail (newsletters, ticketing systems, forms), hence a low weight.
Replies redirected to a free mailbox while the sender is an organization is the
business-email-compromise pattern and is called out explicitly in the evidence.
"""

from ..brands import FREEMAIL_DOMAINS
from ..context import EmailContext
from ..domains import describe_domain
from ..models import CheckOutcome, Detection


def run(ctx: EmailContext) -> CheckOutcome:
    if not ctx.reply_to:
        return CheckOutcome("not_applicable", reason="The message has no separate Reply-To address.")
    sender = ctx.sender
    if sender is None or sender.registered_domain is None:
        return CheckOutcome("not_available", reason="The sender domain could not be determined for comparison.")

    evidence, to_freemail = [], False
    for addr in ctx.reply_to:
        if addr.registered_domain and addr.registered_domain != sender.registered_domain:
            evidence.append(f"Replies go to {describe_domain(addr.domain)} instead of {describe_domain(sender.domain)}")
            to_freemail |= addr.registered_domain in FREEMAIL_DOMAINS

    outcome = CheckOutcome("completed")
    if evidence:
        detail = None
        if to_freemail and sender.registered_domain not in FREEMAIL_DOMAINS:
            detail = "Replies would go to a free personal mailbox although the sender appears to be an organization."
        outcome.detections.append(Detection("SENDER_REPLYTO_MISMATCH", evidence, detail=detail))
    return outcome
