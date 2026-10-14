"""Detection pipeline: parse once -> run every registered check in isolation -> score.

A failing check never breaks the analysis and is never read as "safe": its status is
reported, and the coverage section states what was and was not analyzed.
"""

import logging

from .. import __version__
from ..schemas import (
    AnalyzeResponse,
    CategoryResult,
    CheckResult,
    Coverage,
    EmailMessage,
    FindingOut,
    PositiveFindingOut,
)
from .checks import CHECKS
from .context import build_context
from .models import CheckOutcome
from .scoring import decide_verdict, score
from .signals import CATEGORIES, MALICIOUS_THRESHOLD

logger = logging.getLogger("scorer.engine")

_SUMMARIES = {
    "LOW_RISK": "No strong warning signs in the parts of the email that were analyzed. "
    "This is not a guarantee that the email is safe.",
    "SUSPICIOUS": "Warning signs found. Verify the sender through another channel before "
    "clicking links, opening attachments or replying.",
    "MALICIOUS": "Strong, corroborating warning signs. Do not click links, open attachments or reply.",
    "INCONCLUSIVE": "There was not enough information to assess this email.",
}


def _run_check(check, ctx) -> CheckOutcome:
    if check.run is None:
        return CheckOutcome("not_implemented", reason="Planned; not analyzed yet.")
    try:
        return check.run(ctx)
    except Exception as exc:  # noqa: BLE001 - isolate checks from each other
        # Log the exception type only: messages may contain email data.
        logger.warning("check %s failed: %s", check.id, type(exc).__name__)
        return CheckOutcome("failed", reason="This check failed unexpectedly and was skipped.")


def _category_status(statuses: list[str]) -> str:
    if all(s == "not_implemented" for s in statuses):
        return "not_implemented"
    if "completed" in statuses:
        return "partial" if ("failed" in statuses or "not_available" in statuses) else "completed"
    if "failed" in statuses:
        return "failed"
    if "not_available" in statuses:
        return "not_available"
    return "not_applicable"


def analyze(message: EmailMessage) -> AnalyzeResponse:
    ctx = build_context(message)
    outcomes = [(check, _run_check(check, ctx)) for check in CHECKS]

    scored = score([d for _, o in outcomes for d in o.detections])
    completed_any = any(o.status == "completed" for _, o in outcomes)

    categories = []
    analyzed_caps = 0
    for category in CATEGORIES.values():
        statuses = [o.status for c, o in outcomes if c.category == category.id]
        status = _category_status(statuses)
        if status in ("completed", "partial"):
            analyzed_caps += category.cap
        categories.append(
            CategoryResult(
                id=category.id, title=category.title, status=status,
                score=scored.category_scores[category.id], cap=category.cap,
            )
        )

    limitations = []
    for check, outcome in outcomes:
        if outcome.status in ("failed", "not_available"):
            limitations.append(f"{check.title}: {outcome.reason}")
    not_analyzed = [c.title for c in categories if c.status == "not_implemented"]
    if not_analyzed:
        limitations.append(f"Not analyzed yet: {', '.join(not_analyzed)}.")
    max_attainable = min(100, analyzed_caps)
    if completed_any and max_attainable < MALICIOUS_THRESHOLD:
        limitations.append(
            f"The categories analyzed can contribute at most {max_attainable} points, so this "
            f"analysis can flag an email as SUSPICIOUS but not MALICIOUS (requires {MALICIOUS_THRESHOLD}). "
            "Stronger verdicts need evidence from links, attachments or content."
        )

    if completed_any:
        verdict, verdict_reason = decide_verdict(scored.total, scored.findings)
        risk_score = scored.total
    else:
        verdict, verdict_reason = "INCONCLUSIVE", "None of the checks had enough data to run."
        risk_score = None

    findings = [
        FindingOut(
            signal_id=f.signal.id, category=f.signal.category, severity=f.signal.severity,
            title=f.signal.title,
            explanation=f.signal.explanation + (f" {f.detail}" if f.detail else ""),
            evidence=f.evidence, points=f.signal.points, counted_points=f.counted_points,
            score_status=f.score_status, note=f.note,
        )
        for f in scored.findings
    ]
    return AnalyzeResponse(
        analysis_mode="live",
        score=risk_score,
        verdict=verdict,
        verdict_reason=verdict_reason,
        summary=_SUMMARIES[verdict],
        top_reasons=[f.title for f in findings if f.counted_points > 0][:3],
        findings=findings,
        positive_findings=[
            PositiveFindingOut(id=p.id, title=p.title, explanation=p.explanation, evidence=p.evidence)
            for _, o in outcomes for p in o.positives
        ],
        categories=categories,
        checks=[
            CheckResult(id=c.id, category=c.category, title=c.title, status=o.status, reason=o.reason)
            for c, o in outcomes
        ],
        coverage=Coverage(
            checks_completed=sum(o.status == "completed" for _, o in outcomes),
            checks_total=len(outcomes),
            max_attainable_score=max_attainable,
            limitations=limitations,
        ),
        engine_version=__version__,
    )
