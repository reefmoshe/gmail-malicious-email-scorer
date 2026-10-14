"""Internal data types shared by the checks, the scoring engine and the pipeline."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

CheckStatus = Literal["completed", "failed", "not_applicable", "not_available", "not_implemented"]


@dataclass
class Detection:
    """A risk signal raised by a check. Points come from the signal registry, never from the check."""

    signal_id: str
    evidence: list[str]
    detail: str | None = None
    # Overrides the registry's correlation group when the correlation depends on context
    # (e.g. SPF/DKIM failures are part of the DMARC result only when DMARC was evaluated).
    group: str | None = None
    # Brands this finding is about (e.g. {"PayPal"}); used to detect reinforcing findings.
    subjects: frozenset[str] = frozenset()


@dataclass
class PositiveFinding:
    """Evidence that lowers concern. Reported to the user but never subtracted from the score."""

    id: str
    title: str
    explanation: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class CheckOutcome:
    status: CheckStatus
    detections: list[Detection] = field(default_factory=list)
    positives: list[PositiveFinding] = field(default_factory=list)
    reason: str | None = None


@dataclass(frozen=True)
class Check:
    id: str
    category: str
    title: str
    run: Callable[..., CheckOutcome] | None  # None = planned but not implemented yet
