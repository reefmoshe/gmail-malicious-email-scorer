"""Message wording: requests for credentials or money, with pressure as supporting context.

Urgency and threats are common in legitimate mail, so pressure is only reported when the
message also asks for credentials or money.
"""

from ..content import find_indicators
from ..context import EmailContext
from ..models import CheckOutcome, Detection


def run(ctx: EmailContext) -> CheckOutcome:
    if ctx.body_text is None:
        return CheckOutcome("not_available", reason="The message text was not collected by this version of the add-on.")

    found = find_indicators(ctx.subject, ctx.body_text)
    outcome = CheckOutcome("completed")
    for signal_id, snippets in (
        ("CONTENT_CREDENTIAL_REQUEST", found.credential_request),
        ("CONTENT_FINANCIAL_REQUEST", found.money_request),
        ("CONTENT_PRESSURE", found.pressure if found.any_request else []),
    ):
        if snippets:
            outcome.detections.append(Detection(signal_id, [f'"{s}"' for s in snippets]))
    return outcome
