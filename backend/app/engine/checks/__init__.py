"""Check registry. Adding a check = writing one module and adding one line here."""

from ..models import Check
from . import (
    attachments,
    authentication,
    combined,
    content,
    display_name,
    links,
    lookalike,
    organization,
    reply_to,
    reputation,
)

CHECKS: tuple[Check, ...] = (
    Check("authentication_results", "authentication", "Sender authentication (SPF, DKIM, DMARC)", authentication.run),
    Check("lookalike_domains", "sender_identity", "Look-alike sender domains", lookalike.run),
    Check("display_name", "sender_identity", "Sender name impersonation", display_name.run),
    Check("reply_to", "sender_identity", "Reply-To address", reply_to.run),
    Check("links", "urls", "Links in the message", links.run),
    Check("url_reputation", "urls", "Link reputation (domain level)", reputation.run),
    Check("attachments", "attachments", "Attachment metadata", attachments.run),
    Check("content", "content", "Message wording", content.run),
    Check("combined", "combined", "Request vs. sender identity", combined.run),
    Check("organization", "organization", "Impersonation of your organization", organization.run),
)
