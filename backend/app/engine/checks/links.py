"""Links: deceptive or hidden destinations, judged from the link text only (never fetched).

Correlation with sender identity: a link to the sender's own registered domain is not
scored again as a look-alike - that domain is already assessed by the sender checks.
"""

import unicodedata

from ..brands import PROTECTED_BRANDS
from ..context import EmailContext, for_evidence
from ..domains import describe_domain, find_lookalike, registered_domain, to_unicode
from ..link_data import LINK_REWRITERS, SUSPICIOUS_TLDS, URL_SHORTENERS, host_in
from ..models import CheckOutcome, Detection
from ..urls import ParsedLink, parse_link

_MAX_EVIDENCE = 5
_DEEP_SUBDOMAIN_LEVELS = 5


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.links is None:
        return CheckOutcome("not_available", reason="Links were not collected by this version of the add-on.")
    if not ctx.links:
        return CheckOutcome("not_applicable", reason="The message contains no links.")

    parsed = [p for link in ctx.links if (p := parse_link(link.url, link.text))]
    sender_registered = ctx.sender.registered_domain if ctx.sender else None
    found: dict[str, tuple[list[str], set[str]]] = {}

    def add(signal_id: str, evidence: str, subjects: set[str] = frozenset()) -> None:
        entry = found.setdefault(signal_id, ([], set()))
        if evidence not in entry[0]:
            entry[0].append(evidence)
        entry[1].update(subjects)

    for link in parsed:
        destination = describe_domain(link.domain) if link.domain else link.ip
        own_domain = link.registered is not None and link.registered == sender_registered

        if link.text_domain and not _same_owner(link.text_domain, link.registered) and not _is_rewriter(link):
            note = " (the sender's own domain)" if own_domain else ""
            add(
                "URL_TEXT_HREF_MISMATCH",
                f"Link text shows {describe_domain(link.text_domain)} but leads to {destination}{note}",
                _brands_owning(link.text_domain),
            )

        lookalike = find_lookalike(link.domain) if link.domain and not own_domain else None
        if lookalike:
            add(
                "URL_LOOKALIKE_DOMAIN",
                f"{destination} resembles {lookalike.brand} ({lookalike.official_domain}): it {lookalike.technique}",
                {lookalike.brand},
            )

        if link.ip:
            disguise = f' (written as "{for_evidence(link.host)}" to disguise it)' if link.ip_obfuscated else ""
            add("URL_IP_HOST", f"Link leads to the numeric address {link.ip}{disguise}")

        if link.username:
            add("URL_USERINFO_AT", f'Link starts with "{for_evidence(link.username)}@" but actually opens {destination}')

        for reason in _deceptive_structure(link, skip_mixed_script=lookalike is not None):
            add("URL_DECEPTIVE_STRUCTURE", f"{destination}: {reason}")

        if link.domain and link.domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("URL_SUSPICIOUS_TLD", f"{destination} ends in .{link.domain.rsplit('.', 1)[-1]}")

        if link.domain and host_in(link.domain, URL_SHORTENERS):
            add("URL_SHORTENER", f"{destination} is a link shortener; the real destination is hidden")

        if link.scheme == "http":
            add("URL_PLAIN_HTTP", f"{destination} uses unencrypted http")

    outcome = CheckOutcome("completed")
    if len(parsed) < len(ctx.links):
        outcome.reason = f"{len(ctx.links) - len(parsed)} link(s) could not be interpreted and were skipped."
    for signal_id, (evidence, subjects) in found.items():
        outcome.detections.append(Detection(signal_id, _bounded(evidence), subjects=frozenset(subjects)))
    return outcome


def _same_owner(text_domain: str, destination_registered: str | None) -> bool:
    shown = registered_domain(text_domain)
    if destination_registered is None:
        return False
    if shown == destination_registered:
        return True
    return any(shown in b.owned_domains and destination_registered in b.owned_domains for b in PROTECTED_BRANDS)


def _is_rewriter(link: ParsedLink) -> bool:
    return link.domain is not None and host_in(link.domain, LINK_REWRITERS)


def _brands_owning(domain: str) -> set[str]:
    shown = registered_domain(domain)
    return {b.name for b in PROTECTED_BRANDS if shown in b.owned_domains}


def _deceptive_structure(link: ParsedLink, skip_mixed_script: bool) -> list[str]:
    if not link.domain or not link.registered:
        return []
    reasons = []
    levels = link.domain.count(".") - link.registered.count(".")
    if levels >= _DEEP_SUBDOMAIN_LEVELS:
        reasons.append(f"the real website ({link.registered}) is hidden behind {levels} sub-levels")
    if not skip_mixed_script and any(len(_scripts(label)) > 1 for label in to_unicode(link.domain).split(".")):
        reasons.append("mixes letters from different alphabets")
    return reasons


def _scripts(label: str) -> set[str]:
    return {unicodedata.name(c, "UNKNOWN").split(" ")[0] for c in label if c.isalpha()}


def _bounded(evidence: list[str]) -> list[str]:
    if len(evidence) <= _MAX_EVIDENCE:
        return evidence
    return evidence[:_MAX_EVIDENCE] + [f"...and {len(evidence) - _MAX_EVIDENCE} more links"]
