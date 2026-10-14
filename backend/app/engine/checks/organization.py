"""Impersonation of the user's own organization (only when ORG_DOMAINS is configured).

Reuses the binary look-alike detector with the organization as the only protected name.
Mail from outside the organization is normal and is never flagged for that alone.
"""

import re

from ..context import EmailContext, for_evidence
from ..domains import describe_domain, find_lookalike, normalize_domain, registered_domain, skeleton
from ..models import CheckOutcome, Detection
from ..organization import configured_organization

_EMBEDDED_ADDRESS_RE = re.compile(r"[^\s<>\"'@()]+@([^\s<>\"'@()]+)")


def run(ctx: EmailContext) -> CheckOutcome:
    org = configured_organization()
    if org is None:
        return CheckOutcome("not_applicable", reason="No organization domains are configured (ORG_DOMAINS).")
    if ctx.sender is None and not ctx.reply_to:
        return CheckOutcome("not_available", reason="No valid sender or Reply-To address was found.")

    outcome = CheckOutcome("completed")
    subject = frozenset({org.name})

    lookalikes = []
    for role, addr in [("Sender", ctx.sender)] + [("Reply-To", a) for a in ctx.reply_to]:
        if addr is None:
            continue
        match = find_lookalike(addr.domain, brands=(org,))
        if match:
            lookalikes.append(f"{role} domain {describe_domain(addr.domain)} resembles {org.name} ({match.official_domain}): it {match.technique}")
    if lookalikes:
        outcome.detections.append(Detection("ORG_LOOKALIKE_DOMAIN", lookalikes, subjects=subject))

    claims = external_identity_claims(ctx.sender, org)
    if claims:
        outcome.detections.append(
            Detection(
                "ORG_EXTERNAL_IDENTITY_CLAIM",
                [f"Sent from external {describe_domain(ctx.sender.domain)}, but {c}" for c in claims],
                subjects=subject,
            )
        )
    return outcome


def external_identity_claims(sender, org) -> list[str]:
    """How an external sender's display name claims to be the organization (empty if it does not)."""
    if sender is None or not sender.display or sender.registered_domain in org.domains:
        return []
    claims = []
    display_skeleton = skeleton(sender.display)
    if any(re.search(rf"(?<!\w){re.escape(skeleton(n))}(?!\w)", display_skeleton) for n in org.names):
        claims.append(f'the name "{for_evidence(sender.display)}" refers to {org.name}')
    for found in _EMBEDDED_ADDRESS_RE.finditer(sender.display):
        if registered_domain(normalize_domain(found.group(1))) in org.domains:
            claims.append(f'the name shows the internal address "{for_evidence(found.group(0))}"')
    return claims
