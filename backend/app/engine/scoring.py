"""Explainable scoring: detections -> per-finding contribution -> category scores -> verdict.

Rules, in order:
  1. Each signal id counts once; repeated detections are merged and keep all evidence.
  2. Within a category, signals in the same correlation group describe one underlying
     behaviour: only the strongest counts, the others are marked "correlated".
  3. Each category is capped; contributions above the cap are marked "capped".
  4. Category scores are summed and capped at 100. Positive evidence never subtracts.

The verdict follows the score thresholds, with one floor: a single high-severity finding
makes the email at least SUSPICIOUS (never MALICIOUS on its own), because such signals
are rare in legitimate mail even when the additive score is still low.
"""

from dataclasses import dataclass, field

from .models import Detection
from .signals import CATEGORIES, MALICIOUS_THRESHOLD, SIGNALS, SUSPICIOUS_THRESHOLD, Signal


@dataclass
class ScoredFinding:
    signal: Signal
    evidence: list[str]
    detail: str | None
    group: str
    counted_points: int = 0
    score_status: str = "counted"  # counted | correlated | capped
    note: str | None = None


@dataclass
class ScoreResult:
    findings: list[ScoredFinding]
    category_scores: dict[str, int] = field(default_factory=dict)
    total: int = 0


def score(detections: list[Detection]) -> ScoreResult:
    merged: dict[str, ScoredFinding] = {}
    for detection in detections:
        signal = SIGNALS[detection.signal_id]
        if detection.signal_id in merged:
            existing = merged[detection.signal_id]
            existing.evidence.extend(e for e in detection.evidence if e not in existing.evidence)
            existing.detail = existing.detail or detection.detail
        else:
            group = detection.group or signal.group or signal.id
            merged[detection.signal_id] = ScoredFinding(signal, list(detection.evidence), detection.detail, group)

    result = ScoreResult(findings=list(merged.values()))
    for category in CATEGORIES.values():
        in_category = [f for f in result.findings if f.signal.category == category.id]

        winners: dict[str, ScoredFinding] = {}
        for finding in sorted(in_category, key=lambda f: -f.signal.points):
            winner = winners.setdefault(finding.group, finding)
            if winner is not finding:
                finding.score_status = "correlated"
                finding.note = f'Counted as part of "{winner.signal.title}".'

        remaining = category.cap
        for finding in sorted(winners.values(), key=lambda f: -f.signal.points):
            finding.counted_points = min(finding.signal.points, remaining)
            remaining -= finding.counted_points
            if finding.counted_points < finding.signal.points:
                finding.score_status = "capped"
                finding.note = f"{category.title} is capped at {category.cap} points; {finding.counted_points} counted."
        result.category_scores[category.id] = category.cap - remaining

    result.total = min(100, sum(result.category_scores.values()))
    result.findings.sort(key=lambda f: (-f.counted_points, -f.signal.points))
    return result


def decide_verdict(total: int, findings: list[ScoredFinding]) -> tuple[str, str]:
    if total >= MALICIOUS_THRESHOLD:
        return "MALICIOUS", f"The risk score reached the malicious threshold ({MALICIOUS_THRESHOLD})."
    if total >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS", f"The risk score reached the suspicious threshold ({SUSPICIOUS_THRESHOLD})."
    high = [f for f in findings if f.counted_points > 0 and f.signal.severity == "high"]
    if high:
        return (
            "SUSPICIOUS",
            f'A high-severity indicator was found ("{high[0].signal.title}"). It is rare in legitimate '
            "mail, but on its own it is not enough for a MALICIOUS verdict.",
        )
    if any(f.counted_points > 0 for f in findings):
        return "LOW_RISK", "Only minor indicators were found; on their own they are common in legitimate mail."
    return "LOW_RISK", "No risk indicators were found in the checks that ran."
