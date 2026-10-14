"""Deterministic explanation built only from the engine's own fields. Always available."""

from ..schemas import AnalyzeResponse, Explanation

TEMPLATE_NOTICE = "Summary generated from the rule-based result above."

_OPENINGS = {
    "LOW_RISK": "This email shows no strong warning signs in the parts we could check.",
    "SUSPICIOUS": "This email shows warning signs that deserve caution.",
    "MALICIOUS": "This email shows several strong warning signs that point to a likely scam or attack.",
    "INCONCLUSIVE": "There was not enough information to judge this email.",
}
_RECOMMENDATIONS = {
    "LOW_RISK": "You can treat it normally, but stay alert: no automated check can guarantee an email is safe.",
    "SUSPICIOUS": "Do not click links, open attachments or reply with information until you confirm the sender "
    "through a channel you already trust, such as their official website or a known phone number.",
    "MALICIOUS": "Do not click any links, open attachments or reply. Report the email as phishing and delete it.",
    "INCONCLUSIVE": "Be careful with links and attachments, and confirm the sender another way if anything is requested.",
}


def template_explanation(result: AnalyzeResponse) -> Explanation:
    counted = [f for f in result.findings if f.counted_points > 0]
    reasons = [f"{f.title}: {_first_sentence(f.explanation)}" for f in counted[:3]]
    if not reasons and result.positive_findings:
        reasons = [f"{p.title}: {_first_sentence(p.explanation)}" for p in result.positive_findings[:1]]

    summary = _OPENINGS[result.verdict]
    if counted:
        summary += f" The main concern: {counted[0].title.lower()}."

    return Explanation(
        source="template",
        summary=summary,
        key_reasons=[_bound(r, 240) for r in reasons],
        recommendation=_RECOMMENDATIONS[result.verdict],
        limitations=_limitations(result),
        notice=TEMPLATE_NOTICE,
    )


def _limitations(result: AnalyzeResponse) -> str | None:
    missing = [c.title for c in result.checks if c.status in ("failed", "not_available")]
    if not missing:
        return None
    return _bound(f"Not everything could be checked ({', '.join(missing[:4])}), so the result may miss some risks.", 400)


def _first_sentence(text: str) -> str:
    return text.split(". ")[0].rstrip(".") + "."


def _bound(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
