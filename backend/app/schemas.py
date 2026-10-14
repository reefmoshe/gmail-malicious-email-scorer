"""Request/response models for the analysis API.

All email-derived fields are untrusted input: every field has a hard length
limit, and unknown fields are rejected so the contract stays explicit.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CheckStatus = Literal["completed", "failed", "not_applicable", "not_available", "not_implemented"]
CategoryStatus = Literal["completed", "partial", "failed", "not_applicable", "not_available", "not_implemented"]


class Link(BaseModel):
    """One link, already minimized by the add-on: scheme://[user@]host[:port] only."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(max_length=600)
    text: str | None = Field(default=None, max_length=200, description="Only when the text is a URL/domain")


class Attachment(BaseModel):
    """Attachment metadata only - the add-on never reads or sends file contents."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(max_length=255)
    content_type: str | None = Field(default=None, max_length=200)
    size: int | None = Field(default=None, ge=0)


class EmailMessage(BaseModel):
    """Minimal metadata extracted by the add-on from the currently opened email."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(default="", max_length=1000)
    sender: str = Field(default="", max_length=500, description="Raw From header")
    reply_to: str | None = Field(default=None, max_length=500)
    return_path: str | None = Field(default=None, max_length=500)
    date: str | None = Field(default=None, max_length=100)
    auth_results: str | None = Field(
        default=None, max_length=5000, description="Raw Authentication-Results header"
    )
    links: list[Link] | None = Field(
        default=None, max_length=50, description="None = not collected (older add-on); [] = no links"
    )
    attachments: list[Attachment] | None = Field(
        default=None, max_length=30, description="None = not collected; [] = no attachments"
    )
    body_text: str | None = Field(
        default=None, max_length=10000, description="Truncated plain text, links removed; None = not collected"
    )


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: EmailMessage


class FindingOut(BaseModel):
    signal_id: str
    category: str
    severity: Literal["low", "medium", "high"]
    title: str
    explanation: str
    evidence: list[str]
    points: int = Field(description="Nominal weight of the signal")
    counted_points: int = Field(description="Points actually added to the score")
    score_status: Literal["counted", "correlated", "reinforcing", "capped"]
    note: str | None = None


class PositiveFindingOut(BaseModel):
    id: str
    title: str
    explanation: str
    evidence: list[str]


class CategoryResult(BaseModel):
    id: str
    title: str
    status: CategoryStatus
    score: int
    cap: int


class CheckResult(BaseModel):
    id: str
    category: str
    title: str
    status: CheckStatus
    reason: str | None = None


class Coverage(BaseModel):
    checks_completed: int
    checks_total: int
    max_attainable_score: int = Field(description="Highest score the analyzed categories can produce")
    limitations: list[str]


class Explanation(BaseModel):
    """Plain-language wording of the engine's result. Never an input to scoring."""

    source: Literal["ai", "template"]
    summary: str = Field(max_length=600)
    key_reasons: list[str] = Field(max_length=3)
    recommendation: str = Field(max_length=400)
    limitations: str | None = Field(default=None, max_length=400)
    notice: str


class AnalyzeResponse(BaseModel):
    analysis_mode: Literal["live"]
    score_type: Literal["heuristic_risk_score"] = "heuristic_risk_score"
    score: int | None = Field(default=None, ge=0, le=100, description="Null when INCONCLUSIVE")
    verdict: Literal["LOW_RISK", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"]
    verdict_reason: str
    summary: str
    top_reasons: list[str]
    findings: list[FindingOut]
    positive_findings: list[PositiveFindingOut]
    categories: list[CategoryResult]
    checks: list[CheckResult]
    coverage: Coverage
    engine_version: str
    explanation: Explanation | None = Field(
        default=None, description="Added after scoring; wording only, never changes the fields above"
    )
