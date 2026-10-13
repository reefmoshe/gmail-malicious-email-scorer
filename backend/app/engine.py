"""Analysis engine.

MVP: connectivity test only. It proves the add-on <-> backend round trip and
deliberately returns no score, so it can never be mistaken for a real verdict.
Detection rules and scoring are added on top of this module.
"""

from email.utils import parseaddr

from . import __version__
from .schemas import AnalyzeResponse, EmailMessage, ReceivedSummary


def _sender_domain(sender: str) -> str | None:
    _, address = parseaddr(sender)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower() or None


def analyze(message: EmailMessage) -> AnalyzeResponse:
    fields_present = [
        name for name, value in message.model_dump().items() if value not in (None, "")
    ]
    return AnalyzeResponse(
        analysis_mode="connectivity_test",
        score=None,
        verdict="TEST",
        summary="Connectivity test - backend received the message metadata. "
        "This is NOT a security verdict.",
        received=ReceivedSummary(
            subject_length=len(message.subject),
            sender_domain=_sender_domain(message.sender),
            fields_present=fields_present,
        ),
        engine_version=__version__,
    )
