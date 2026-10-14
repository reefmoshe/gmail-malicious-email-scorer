"""Domain normalization and look-alike detection.

Everything here is offline and deterministic: the Public Suffix List snapshot ships
with the publicsuffixlist package, and no DNS or HTTP lookups are ever made.
"""

import re
import unicodedata
from dataclasses import dataclass

from publicsuffixlist import PublicSuffixList

from .brands import (
    BENIGN_LOOKALIKE_EXCEPTIONS,
    DICTIONARY_WORD_TOKENS,
    LOOKALIKE_CONTEXT_WORDS,
    OFFICIAL_DOMAINS,
    PROTECTED_BRANDS,
)

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
    techniques: tuple[str, ...]  # every technique that matched; metadata only, never weighted

    @property
    def technique(self) -> str:
        return " and ".join(self.techniques)


def find_lookalike(ascii_domain: str | None) -> LookalikeMatch | None:
    """Return a reliable impersonation of a protected brand, or None.

    Detection is binary: either a supported technique matched with enough evidence, or
    nothing is reported. Safeguards against accidental similarity:
      - domains owned by the brand (official or verified) and explicit benign exceptions
        are never flagged;
      - only whole labels are compared ("applebees.com" is not Apple);
      - typos must follow a realistic typing error (adjacent key, missing/extra/swapped
        letter), so "unwind" is not "upwind" and "paypay" is not "paypal";
      - a brand combined with other words, or used as a subdomain, needs an account /
        security word ("paypal-secure-login") - "apple-store" or "microsoft-events" is not
        enough;
      - a brand that is also a dictionary word is not flagged just for using another
        domain ending ("upwind.com").
    """
    registered = registered_domain(ascii_domain)
    if not ascii_domain or not registered:
        return None
    if registered in OFFICIAL_DOMAINS or registered in BENIGN_LOOKALIKE_EXCEPTIONS:
        return None

    label = to_unicode(_registered_label(registered)).casefold()
    label_skeleton = skeleton(label)
    parts = [p for p in label.split("-") if p]
    subdomain_labels = [to_unicode(p).casefold() for p in ascii_domain[: -len(registered)].split(".") if p]
    has_context = any(_is_context_word(p) for p in parts + subdomain_labels)

    for brand in PROTECTED_BRANDS:
        techniques = []
        for token in brand.domain_tokens:
            token_skeleton = skeleton(token)
            if len(token) >= 4 and label_skeleton == token_skeleton and label != token:
                techniques.append("uses look-alike characters")
            if label == token and token not in DICTIONARY_WORD_TOKENS:
                techniques.append("uses the brand name under a different domain ending")
            if _is_typo(label, token):
                techniques.append("is a likely typo of the brand name")
            if len(parts) > 1 and has_context and any(_contains_brand(p, token) for p in parts):
                techniques.append("combines the brand name with account or security words")
            elif len(parts) == 1 and _brand_with_context_word(label, token):
                techniques.append("combines the brand name with account or security words")
            if _embeds_official_domain(subdomain_labels, brand) or (
                has_context and any(skeleton(p) == token_skeleton for p in subdomain_labels)
            ):
                techniques.append("uses the brand name as a subdomain of an unrelated domain")
        if techniques:
            return LookalikeMatch(brand.name, brand.domains[0], tuple(dict.fromkeys(techniques)))
    return None


def _contains_brand(part: str, token: str) -> bool:
    """A label part that is the brand, in look-alike characters, or with a typo."""
    return skeleton(part) == skeleton(token) or _is_typo(part, token)


def _is_context_word(text: str) -> bool:
    """Compared in skeleton form, so "l0gin" or "secur3" still count."""
    return skeleton(text) in _CONTEXT_SKELETONS


def _brand_with_context_word(label: str, token: str) -> bool:
    """Brand fused with an account/security word without a hyphen: "paypalsecure", "securepaypal"."""
    skel, token_skel = skeleton(label), skeleton(token)
    if len(skel) <= len(token_skel):
        return False
    if skel.startswith(token_skel):
        return skel[len(token_skel):] in _CONTEXT_SKELETONS
    if skel.endswith(token_skel):
        return skel[: -len(token_skel)] in _CONTEXT_SKELETONS
    return False


def _embeds_official_domain(subdomain_labels: list[str], brand) -> bool:
    """E.g. "paypal.com.account-verify.net": the full official domain inside the subdomain."""
    joined = "." + ".".join(subdomain_labels) + "."
    return any(f".{official}." in joined for official in brand.owned_domains)


_CONTEXT_SKELETONS = frozenset(skeleton(w) for w in LOOKALIKE_CONTEXT_WORDS)

# Physical neighbours on a QWERTY keyboard (rows staggered by a quarter key).
_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
_KEY_POS = {c: (r, i + (0, 0.25, 0.75)[r]) for r, row in enumerate(_ROWS) for i, c in enumerate(row)}


def _adjacent_keys(a: str, b: str) -> bool:
    if a not in _KEY_POS or b not in _KEY_POS:
        return False
    (ra, xa), (rb, xb) = _KEY_POS[a], _KEY_POS[b]
    return abs(ra - rb) <= 1 and abs(xa - xb) <= 1


def _is_typo(candidate: str, token: str) -> bool:
    """A realistic single typing error on a brand name of 6+ characters: a missing,
    extra or swapped letter, or a letter replaced by a neighbouring key. Arbitrary
    one-letter differences are not enough ("unwind" vs "upwind", "paypay" vs "paypal")."""
    if len(token) < 6 or candidate == token or abs(len(candidate) - len(token)) > 1:
        return False
    if edit_distance(candidate, token) != 1:
        return False
    if len(candidate) != len(token):
        return True  # one missing or extra letter
    diffs = [i for i, (x, y) in enumerate(zip(candidate, token)) if x != y]
    if len(diffs) == 2:
        return True  # adjacent swap (edit distance 1 with two differing positions)
    i = diffs[0]
    return _adjacent_keys(candidate[i], token[i])


def describe_domain(ascii_domain: str) -> str:
    """Domain for evidence text. Internationalized domains are shown in punycode as well,
    so our own UI never renders a deceptive Unicode look-alike as if it were genuine."""
    unicode_form = to_unicode(ascii_domain)
    return ascii_domain if unicode_form == ascii_domain else f"{ascii_domain} (displayed as {unicode_form})"
