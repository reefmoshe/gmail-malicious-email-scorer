"""Check registry. Adding a check = writing one module and adding one line here."""

from ..models import Check
from . import authentication, display_name, lookalike, reply_to

CHECKS: tuple[Check, ...] = (
    Check("authentication_results", "authentication", "Sender authentication (SPF, DKIM, DMARC)", authentication.run),
    Check("lookalike_domains", "sender_identity", "Look-alike sender domains", lookalike.run),
    Check("display_name", "sender_identity", "Sender name impersonation", display_name.run),
    Check("reply_to", "sender_identity", "Reply-To address", reply_to.run),
    # Planned (Phase 2): listed so coverage reporting is honest about what was not analyzed.
    Check("links", "urls", "Links in the message", None),
    Check("attachments", "attachments", "Attachment metadata", None),
    Check("content", "content", "Message wording", None),
)
