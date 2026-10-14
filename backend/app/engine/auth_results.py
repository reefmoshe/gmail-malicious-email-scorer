"""Tolerant parser for the Authentication-Results header (RFC 8601).

Example (as added by Gmail):
    mx.google.com; dkim=pass header.i=@example.com header.s=s1;
    spf=pass (google.com: domain of a@example.com designates 1.2.3.4 as permitted sender)
    smtp.mailfrom=a@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com

Single linear pass over input whose length is already capped by the API schema.
"""

import re
from dataclasses import dataclass

_RESULT_RE = re.compile(r"^\s*([a-z][a-z0-9_-]*)\s*=\s*([a-z0-9_]+)(.*)$", re.IGNORECASE | re.DOTALL)
_PROPERTY_RE = re.compile(r"([a-z][a-z0-9_-]*\.[a-z0-9_-]+)\s*=\s*([^\s;]+)", re.IGNORECASE)


@dataclass(frozen=True)
class MethodResult:
    method: str  # spf | dkim | dmarc | arc | ...
    result: str  # pass | fail | softfail | neutral | none | temperror | permerror | ...
    properties: dict[str, str]  # e.g. {"header.from": "example.com"}
    comment: str  # parenthesized text, e.g. "p=REJECT sp=REJECT dis=NONE"


@dataclass(frozen=True)
class AuthenticationResults:
    authserv_id: str
    results: list[MethodResult]

    def first(self, method: str) -> MethodResult | None:
        return next((r for r in self.results if r.method == method), None)

    def all(self, method: str) -> list[MethodResult]:
        return [r for r in self.results if r.method == method]


def _split_outside_comments(text: str) -> list[str]:
    """Split on ';' that is not inside a (comment) or "quoted string"."""
    parts, current, depth, quoted = [], [], 0, False
    for char in text:
        if char == '"' and depth == 0:
            quoted = not quoted
        elif char == "(" and not quoted:
            depth += 1
        elif char == ")" and not quoted and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0 and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _strip_comments(text: str) -> tuple[str, str]:
    """Return (text without comments, concatenated comment text)."""
    body, comments, depth = [], [], 0
    for char in text:
        if char == "(":
            depth += 1
            if depth == 1:
                continue
        elif char == ")" and depth > 0:
            depth -= 1
            if depth == 0:
                comments.append(" ")
                continue
        (comments if depth else body).append(char)
    return "".join(body), " ".join("".join(comments).split())


def parse_authentication_results(raw: str) -> AuthenticationResults:
    """Raise ValueError when the header has no authserv-id (i.e. is not interpretable)."""
    segments = _split_outside_comments(" ".join(raw.split()))
    head, _ = _strip_comments(segments[0])
    tokens = head.split()
    if not tokens or "=" in tokens[0]:
        raise ValueError("Authentication-Results header has no authserv-id")

    results = []
    for segment in segments[1:]:
        body, comment = _strip_comments(segment)
        match = _RESULT_RE.match(body)
        if not match:
            continue
        properties = {k.lower(): v.strip('"') for k, v in _PROPERTY_RE.findall(match.group(3))}
        results.append(MethodResult(match.group(1).lower(), match.group(2).lower(), properties, comment))
    return AuthenticationResults(tokens[0].lower(), results)


def property_domain(value: str | None) -> str | None:
    """Domain part of a property such as smtp.mailfrom=a@x.com, header.i=@x.com or header.d=x.com."""
    if not value:
        return None
    return value.rpartition("@")[2] or None


def policy_from_comment(comment: str) -> dict[str, str]:
    """Extract DMARC policy fields such as p=REJECT and dis=NONE from a result comment."""
    return {k.lower(): v.lower() for k, v in re.findall(r"\b(p|sp|dis)=([a-z]+)", comment, re.IGNORECASE)}
