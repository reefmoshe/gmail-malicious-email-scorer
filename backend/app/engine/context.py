"""Parses the untrusted request once into a normalized view that all checks share.

Parsing never raises on malformed input: unparseable values become None/empty and the
checks that need them report "not_available" instead of guessing.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from email.utils import getaddresses

from ..schemas import EmailMessage, Link
from .domains import normalize_domain, registered_domain

# Zero-width and bidirectional-control characters can hide or reorder text in a display name.
_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍‎‏‪‫‬‭‮⁠⁦⁧⁨⁩﻿")
)
_MAX_EVIDENCE_CHARS = 200


def clean_text(value: str | None) -> str:
    """NFKC-normalize, drop invisible/control characters and collapse whitespace."""
    if not value:
        return ""
    text = unicodedata.normalize("NFKC", value).translate(_INVISIBLE)
    text = "".join(" " if unicodedata.category(c) == "Cc" else c for c in text)
    return re.sub(r"\s+", " ", text).strip()


def for_evidence(value: str) -> str:
    """Bound user-visible snippets taken from the email."""
    value = clean_text(value)
    return value if len(value) <= _MAX_EVIDENCE_CHARS else value[: _MAX_EVIDENCE_CHARS - 1] + "…"


@dataclass(frozen=True)
class Address:
    display: str
    address: str
    domain: str  # ASCII / punycode, lowercase
    registered_domain: str | None


@dataclass
class EmailContext:
    sender: Address | None
    reply_to: list[Address] = field(default_factory=list)
    auth_results_raw: str | None = None
    links: list[Link] | None = None  # None = not collected by the add-on


def parse_addresses(raw: str | None) -> list[Address]:
    """Parse an address header; entries without a valid domain are dropped."""
    if not raw:
        return []
    parsed = []
    for name, addr in getaddresses([raw]):
        _, at, domain_part = addr.rpartition("@")
        domain = normalize_domain(domain_part) if at else None
        if domain:
            parsed.append(Address(clean_text(name), addr.strip().lower(), domain, registered_domain(domain)))
    return parsed


def build_context(message: EmailMessage) -> EmailContext:
    senders = parse_addresses(message.sender)
    return EmailContext(
        sender=senders[0] if senders else None,
        reply_to=parse_addresses(message.reply_to),
        auth_results_raw=message.auth_results,
        links=message.links,
    )
