"""Signal registry: the single source of truth for categories, weights and wording.

Weights are initial heuristic values chosen by how specific each signal is to
malicious mail (how rarely it appears in legitimate mail). They are not
statistically validated probabilities, and the score is a heuristic risk score.
"""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    cap: int


@dataclass(frozen=True)
class Signal:
    id: str
    category: str
    points: int
    severity: Severity
    title: str
    explanation: str
    # Signals in the same group describe the same underlying behaviour: only the
    # strongest one is counted. Defaults to the signal's own id (independent).
    group: str | None = None


CATEGORIES: dict[str, Category] = {
    c.id: c
    for c in (
        Category("authentication", "Sender authentication", 30),
        Category("sender_identity", "Sender identity", 25),
        Category("urls", "Links", 35),
        Category("attachments", "Attachments", 35),
        Category("content", "Message content", 15),
    )
}

_SIGNALS = (
    # --- Authentication -------------------------------------------------------------
    Signal(
        "AUTH_DMARC_FAIL", "authentication", 25, "high",
        "Sender domain failed verification (DMARC)",
        "The message claims to come from a domain whose owner publishes a verification "
        "policy, and it failed that policy. This happens with spoofed mail, but also with "
        "some forwarded or misconfigured legitimate mail.",
    ),
    Signal(
        "AUTH_SPF_FAIL", "authentication", 10, "medium",
        "Sending server not authorized (SPF fail)",
        "The server that delivered this message is not on the sending domain's list of "
        "allowed servers.",
    ),
    Signal(
        "AUTH_SPF_SOFTFAIL", "authentication", 5, "low",
        "Sending server probably not authorized (SPF softfail)",
        "The sending domain says this server is probably not allowed to send its mail. "
        "This is a weaker statement than a hard SPF failure.",
    ),
    Signal(
        "AUTH_DKIM_FAIL", "authentication", 8, "medium",
        "Digital signature did not verify (DKIM)",
        "The message carries a digital signature that does not verify. The message may have "
        "been altered in transit, or the signature may be forged.",
    ),
    Signal(
        "AUTH_DKIM_NONE", "authentication", 3, "low",
        "No digital signature (DKIM)",
        "The message is not digitally signed, so its origin cannot be confirmed this way. "
        "Many small senders do not sign their mail.",
    ),
    # --- Sender identity ------------------------------------------------------------
    Signal(
        "SENDER_LOOKALIKE_DOMAIN", "sender_identity", 15, "high",
        "Sender domain imitates a known brand",
        "The sending domain closely resembles a well-known brand's domain but is not one of "
        "its official domains. Look-alike domains are a common phishing technique.",
    ),
    Signal(
        "SENDER_REPLYTO_LOOKALIKE", "sender_identity", 15, "high",
        "Replies go to a domain imitating a known brand",
        "Replies to this message would be sent to a domain that resembles a well-known "
        "brand but is not one of its official domains.",
        group="reply_diversion",
    ),
    Signal(
        "SENDER_BRAND_DISPLAY_MISMATCH", "sender_identity", 10, "medium",
        "Sender name claims a brand the address does not belong to",
        "The sender's display name mentions a known brand, but the email address is not "
        "from that brand's official domains.",
        group="display_name_claim",
    ),
    Signal(
        "SENDER_DISPLAY_HAS_ADDRESS", "sender_identity", 10, "medium",
        "Sender name contains a different email address",
        "The display name shows an email address from a different domain than the one the "
        "message was actually sent from. This is a common way to disguise the real sender.",
        group="display_name_claim",
    ),
    Signal(
        "SENDER_REPLYTO_MISMATCH", "sender_identity", 8, "low",
        "Replies go to a different domain",
        "Replying to this message would send your answer to a different domain than the "
        "sender's. Newsletters and support systems do this legitimately; fraudsters use it "
        "to receive replies on an address they control.",
        group="reply_diversion",
    ),
    Signal(
        "SENDER_FREEMAIL_ORG_CLAIM", "sender_identity", 8, "low",
        "Free email account presents itself as an organization",
        "The message comes from a free personal email service, but the sender name presents "
        "it as a company, bank or internal department.",
        group="display_name_claim",
    ),
)

SIGNALS: dict[str, Signal] = {s.id: s for s in _SIGNALS}

# Verdict thresholds on the 0-100 heuristic risk score.
SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 70
