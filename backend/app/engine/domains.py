"""Domain normalization and look-alike detection.

Everything here is offline and deterministic: the Public Suffix List snapshot ships
with the publicsuffixlist package, and no DNS or HTTP lookups are ever made.
"""

import re
import unicodedata
from dataclasses import dataclass

from publicsuffixlist import PublicSuffixList

from .brands import OFFICIAL_DOMAINS, PROTECTED_BRANDS

_PSL = PublicSuffixList()
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# Characters that render (nearly) identically to Latin letters. Applied to BOTH sides
# of every comparison, so "paypa1", "pаypal" (Cyrillic а) and "paypal" share a skeleton.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "l",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t",
        # Greek
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "l", "κ": "k", "χ": "x",
        "υ": "u",
        # Latin homoglyphs: i / l / 1 / | collapse to "l", digits to similar letters
        "ɡ": "g", "i": "l", "1": "l", "|": "l", "0": "o", "3": "e", "5": "s",
    }
)


def normalize_domain(raw: str | None) -> str | None:
    """Lowercase ASCII (punycode) form of a domain, or None if it is not a valid hostname."""
    if not raw:
        return None
    domain = raw.strip().strip(".").lower()
    if not domain or len(domain) > 253:
        return None
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    return ascii_domain


def to_unicode(ascii_domain: str) -> str:
    """Decode punycode labels for comparison; undecodable labels are kept as-is."""
    labels = []
    for label in ascii_domain.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def registered_domain(ascii_domain: str | None) -> str | None:
    """The domain an organization registers (eTLD+1), e.g. mail.paypal.com -> paypal.com."""
    if not ascii_domain:
        return None
    return _PSL.privatesuffix(ascii_domain)


def _registered_label(registered: str) -> str:
    suffix = _PSL.publicsuffix(registered) or ""
    if suffix and registered.endswith("." + suffix):
        return registered[: -len(suffix) - 1]
    return registered.split(".")[0]


def skeleton(text: str) -> str:
    """Visual skeleton: case-folded, accents removed, look-alike characters unified."""
    text = unicodedata.normalize("NFKC", text).casefold()
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return text.translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (insert, delete, substitute, swap adjacent)."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


@dataclass(frozen=True)
class LookalikeMatch:
    brand: str
    official_domain: str
    technique: str


def find_lookalike(ascii_domain: str | None) -> LookalikeMatch | None:
    """Return how a domain imitates a protected brand, or None.

    Only whole-label comparisons are used, so legitimate domains that merely contain
    a brand name as a substring (e.g. "applebees.com") are not flagged.
    """
    registered = registered_domain(ascii_domain)
    if not ascii_domain or not registered or registered in OFFICIAL_DOMAINS:
        return None

    label = to_unicode(_registered_label(registered))
    label_skeleton = skeleton(label)
    label_parts = [p for p in re.split(r"[-.]", label_skeleton) if p]
    subdomain = ascii_domain[: -len(registered)].rstrip(".")
    subdomain_skeletons = {skeleton(to_unicode(p)) for p in subdomain.split(".") if p}

    for brand in PROTECTED_BRANDS:
        official = brand.domains[0]
        for token in brand.domain_tokens:
            token_skeleton = skeleton(token)
            if len(token) >= 4 and label_skeleton == token_skeleton:
                technique = (
                    "same name under a different domain ending"
                    if label == token
                    else "uses look-alike characters"
                )
                return LookalikeMatch(brand.name, official, technique)
            if _is_typo(label_skeleton, token_skeleton):
                return LookalikeMatch(brand.name, official, "differs by a small typo")
            if len(label_parts) > 1 and any(
                part == token_skeleton or _is_typo(part, token_skeleton) for part in label_parts
            ):
                return LookalikeMatch(brand.name, official, "combines the brand name with other words")
            if token_skeleton in subdomain_skeletons:
                return LookalikeMatch(
                    brand.name, official, "uses the brand name as a subdomain of an unrelated domain"
                )
    return None


def _is_typo(candidate: str, token: str) -> bool:
    """One edit away (two for long names). Short names are excluded: too many collisions."""
    if len(token) < 6:
        return False
    max_distance = 2 if len(token) >= 10 else 1
    if candidate == token or abs(len(candidate) - len(token)) > max_distance:
        return False
    return edit_distance(candidate, token) <= max_distance


def describe_domain(ascii_domain: str) -> str:
    """Domain for evidence text. Internationalized domains are shown in punycode as well,
    so our own UI never renders a deceptive Unicode look-alike as if it were genuine."""
    unicode_form = to_unicode(ascii_domain)
    return ascii_domain if unicode_form == ascii_domain else f"{ascii_domain} (displayed as {unicode_form})"
