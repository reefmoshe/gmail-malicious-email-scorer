"""Display-name impersonation: what the sender name claims vs. the actual address.

All three signals interpret the same display-name claim, so they share a correlation
group in the registry and only the strongest one is counted.
"""

import re

from ..brands import FREEMAIL_DOMAINS, ORGANIZATION_ROLE_TERMS, PROTECTED_BRANDS
from ..context import EmailContext, for_evidence
from ..domains import describe_domain, find_lookalike, normalize_domain, registered_domain, skeleton
from ..models import CheckOutcome, Detection

_EMBEDDED_ADDRESS_RE = re.compile(r"[^\s<>\"'@()]+@([^\s<>\"'@()]+)")


def _mentions(text_skeleton: str, phrase: str) -> bool:
    """Whole-word match, so "amazon" does not match "amazonas"."""
    return re.search(rf"(?<!\w){re.escape(skeleton(phrase))}(?!\w)", text_skeleton) is not None


def run(ctx: EmailContext) -> CheckOutcome:
    sender = ctx.sender
    if sender is None:
        return CheckOutcome("not_available", reason="No valid sender address was found.")
    outcome = CheckOutcome("completed")
    if not sender.display:
        return outcome

    display_skeleton = skeleton(sender.display)
    shown_name = for_evidence(sender.display)
    sent_from = describe_domain(sender.domain)

    claimed_brands = [b for b in PROTECTED_BRANDS if any(_mentions(display_skeleton, n) for n in b.names)]
    mismatched = [b for b in claimed_brands if sender.registered_domain not in b.domains]
    if mismatched:
        outcome.detections.append(
            Detection(
                "SENDER_BRAND_DISPLAY_MISMATCH",
                [f'The name "{shown_name}" refers to {b.name}, but the message was sent from {sent_from}' for b in mismatched],
                subjects=frozenset(b.name for b in mismatched),
            )
        )

    foreign_addresses, address_brands = [], set()
    for match in _EMBEDDED_ADDRESS_RE.finditer(sender.display):
        embedded = normalize_domain(match.group(1))
        if embedded and registered_domain(embedded) != sender.registered_domain:
            foreign_addresses.append(f'The name shows "{for_evidence(match.group(0))}", but the real address is {sender.address}')
            if brand := _brand_of_domain(embedded):
                address_brands.add(brand)
    if foreign_addresses:
        outcome.detections.append(
            Detection("SENDER_DISPLAY_HAS_ADDRESS", foreign_addresses, subjects=frozenset(address_brands))
        )

    if sender.registered_domain in FREEMAIL_DOMAINS:
        claims = [b.name for b in claimed_brands] + [t for t in ORGANIZATION_ROLE_TERMS if _mentions(display_skeleton, t)]
        if claims:
            outcome.detections.append(
                Detection(
                    "SENDER_FREEMAIL_ORG_CLAIM",
                    [f'Sent from a free {sent_from} account while the name "{shown_name}" suggests: {", ".join(claims)}'],
                    subjects=frozenset(b.name for b in claimed_brands),
                )
            )
    return outcome


def _brand_of_domain(ascii_domain: str) -> str | None:
    """Brand an embedded address claims: one of its official domains, or a look-alike of it."""
    registered = registered_domain(ascii_domain)
    official = next((b.name for b in PROTECTED_BRANDS if registered in b.domains), None)
    if official:
        return official
    match = find_lookalike(ascii_domain)
    return match.brand if match else None
