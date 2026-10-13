"""Request/response models for the analysis API.

All email-derived fields are untrusted input: every field has a hard length
limit, and unknown fields are rejected so the contract stays explicit.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: EmailMessage


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["low", "medium", "high"]
    points: int = Field(ge=0, le=100)
    evidence: str


class ReceivedSummary(BaseModel):
    """Proof-of-receipt for connectivity tests. Contains no email content."""

    subject_length: int
    sender_domain: str | None
    fields_present: list[str]


class AnalyzeResponse(BaseModel):
    analysis_mode: Literal["connectivity_test", "live"]
    score: int | None = Field(default=None, ge=0, le=100)
    verdict: Literal["SAFE", "SUSPICIOUS", "MALICIOUS", "TEST"]
    summary: str
    findings: list[Finding] = []
    received: ReceivedSummary | None = None
    engine_version: str
