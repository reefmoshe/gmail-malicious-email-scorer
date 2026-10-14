"""Combined indicators: what the message asks for, set against who it claims to be from.

Header-only evidence of business email compromise is weak (a different Reply-To is common),
and so is a payment request on its own (invoices are normal). The combination - money
requested while replies are diverted or a personal mailbox poses as a company or
executive - is specific, so it is scored as its own evidence.
"""

from ..brands import FREEMAIL_DOMAINS
from ..content import find_indicators
from ..context import EmailContext
from ..domains import describe_domain, find_lookalike
from ..models import CheckOutcome, Detection
from ..organization import configured_organization
from .display_name import claimed_brands, claimed_roles
from .organization import external_identity_claims


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.body_text is None:
        return CheckOutcome("not_available", reason="The message text was not collected by this version of the add-on.")
    sender = ctx.sender
    if sender is None:
        return CheckOutcome("not_available", reason="No valid sender address was found.")

    found = find_indicators(ctx.subject, ctx.body_text)
    outcome = CheckOutcome("completed")
    if not found.any_request:
        return outcome
    request = "a payment or bank-details change" if found.financial_request else "login details"

    identity_issues = []
    diverted = [a for a in ctx.reply_to if a.registered_domain and a.registered_domain != sender.registered_domain]
    if diverted:
        identity_issues.append(f"replies go to {describe_domain(diverted[0].domain)} instead of {describe_domain(sender.domain)}")
    if sender.registered_domain in FREEMAIL_DOMAINS:
        claims = [b.name for b in claimed_brands(sender.display)] + claimed_roles(sender.display)
        if claims or found.authority_claim:
            claimed = ", ".join(claims) if claims else "an executive or department (in the text)"
            identity_issues.append(f"a free {describe_domain(sender.domain)} mailbox presents itself as {claimed}")
    org = configured_organization()
    if org and external_identity_claims(sender, org):
        identity_issues.append(f"an external {describe_domain(sender.domain)} address presents itself as {org.name}")

    if found.financial_request and identity_issues:
        outcome.detections.append(
            Detection("COMBINED_BEC_PATTERN", [f"Asks for {request} while {issue}" for issue in identity_issues])
        )

    impersonated = _impersonated_brand(sender, org)
    if impersonated:
        outcome.detections.append(
            Detection(
                "COMBINED_IMPERSONATION_REQUEST",
                [f"Asks for {request} while the sender imitates {impersonated}"],
            )
        )
    return outcome


def _impersonated_brand(sender, org) -> str | None:
    match = find_lookalike(sender.domain) or (find_lookalike(sender.domain, brands=(org,)) if org else None)
    if match:
        return match.brand
    mismatched = [b.name for b in claimed_brands(sender.display) if sender.registered_domain not in b.owned_domains]
    return mismatched[0] if mismatched else None
