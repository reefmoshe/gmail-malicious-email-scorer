"""Message wording: requests for credentials or money, with pressure tactics as context.

Pressure tactics (urgency, threats, secrecy) and generic greetings are common in
legitimate mail, so they are only reported when the message also asks for credentials
or money. They share the "pressure" correlation group: several phrases of the same
tactic never add up.
"""

from ..content import find_indicators
from ..context import EmailContext
from ..models import CheckOutcome, Detection


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.body_text is None:
        return CheckOutcome("not_available", reason="The message text was not collected by this version of the add-on.")

    found = find_indicators(ctx.subject, ctx.body_text)
    outcome = CheckOutcome("completed")
    if not found.any_request:
        return outcome

    if found.credential_request:
        outcome.detections.append(Detection("CONTENT_CREDENTIAL_REQUEST", _quote(found.credential_request)))
    if found.financial_request:
        evidence = _quote(found.bank_change, "Bank details change: ") + _quote(found.payment_request, "Payment request: ")
        outcome.detections.append(Detection("CONTENT_FINANCIAL_REQUEST", evidence[:4]))

    for signal_id, snippets in (
        ("CONTENT_ACCOUNT_THREAT", found.account_threat),
        ("CONTENT_URGENCY", found.urgency),
        ("CONTENT_GENERIC_GREETING", found.generic_greeting),
    ):
        if snippets:
            outcome.detections.append(Detection(signal_id, _quote(snippets)))
    # Secrecy is a fraud marker around money; around a login request it is rare and noisy.
    if found.secrecy and found.financial_request:
        outcome.detections.append(Detection("CONTENT_SECRECY", _quote(found.secrecy)))
    return outcome


def _quote(snippets: list[str], prefix: str = "") -> list[str]:
    return [f'{prefix}"{s}"' for s in snippets]
