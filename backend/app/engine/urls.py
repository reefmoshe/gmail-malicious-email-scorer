"""Safe, offline parsing of links. Links are parsed as text only - never fetched or followed.

The add-on sends only scheme://[user@]host[:port] per link (no path, query or fragment)
plus the visible link text when that text is itself a URL or domain.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from publicsuffixlist import PublicSuffixList

from .domains import normalize_domain, registered_domain

# Strict list (unknown TLDs rejected) so that "file.pdf" in link text is not a domain.
_STRICT_PSL = PublicSuffixList(accept_unknown=False)
_NUMERIC_HOST_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)
_TEXT_HOST_RE = re.compile(r"^\s*(?:https?://)?([^\s/?#:@]+)", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedLink:
    scheme: str  # http | https
    host: str  # domain (ASCII/punycode) or IP address as written
    domain: str | None  # normalized domain; None for IP hosts
    registered: str | None
    ip: str | None  # canonical IP when the host is an IP address (any notation)
    ip_obfuscated: bool  # IP written as an integer, hex or octal instead of dotted decimal
    username: str | None  # userinfo before "@" (password removed by the add-on)
    text_domain: str | None  # domain shown in the link text, if the text is a URL/domain


def parse_link(url: str, text: str | None) -> ParsedLink | None:
    """Return None for anything that is not a well-formed http(s) link."""
    try:
        parts = urlsplit(url.strip())
        hostname = parts.hostname
        username = parts.username
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not hostname:
        return None

    ip, obfuscated = _parse_ip(hostname)
    domain = None if ip else normalize_domain(hostname)
    if not ip and not domain:
        return None
    return ParsedLink(
        scheme=parts.scheme.lower(),
        host=hostname,
        domain=domain,
        registered=registered_domain(domain) if domain else None,
        ip=ip,
        ip_obfuscated=obfuscated,
        username=username or None,
        text_domain=domain_in_text(text),
    )


def _parse_ip(host: str) -> tuple[str | None, bool]:
    try:
        return str(ipaddress.ip_address(host)), False
    except ValueError:
        pass
    if _NUMERIC_HOST_RE.match(host):
        # Browsers accept 3232235777, 0xC0A80001 or 0300.0250.0.1 for 192.168.0.1.
        try:
            parts = [_number(p) for p in host.split(".")]
            if len(parts) == 1:
                return str(ipaddress.ip_address(parts[0])), True
            if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
                return str(ipaddress.ip_address(".".join(map(str, parts)))), True
        except ValueError:
            pass
    return None, False


def _number(part: str) -> int:
    if part.lower().startswith("0x"):
        return int(part, 16)
    if len(part) > 1 and part.startswith("0"):
        return int(part, 8)  # leading zero = octal in browsers' IPv4 parsing
    return int(part)


def domain_in_text(text: str | None) -> str | None:
    """The domain a link's visible text presents ("www.paypal.com", "https://paypal.com/login")."""
    if not text:
        return None
    match = _TEXT_HOST_RE.match(text)
    if not match:
        return None
    domain = normalize_domain(match.group(1))
    if not domain or _STRICT_PSL.privatesuffix(domain) is None:
        return None
    return domain
