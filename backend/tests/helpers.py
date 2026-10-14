"""Shared builders for realistic test emails."""

from app.engine import analyze
from app.schemas import AnalyzeResponse, EmailMessage


def gmail_auth(
    domain: str,
    spf: str | None = "pass",
    dkim: str | None = "pass",
    dmarc: str | None = "pass",
    policy: str = "p=REJECT sp=REJECT dis=NONE",
    dkim_domain: str | None = None,
    spf_domain: str | None = None,
    authserv_id: str = "mx.google.com",
) -> str:
    """An Authentication-Results header formatted the way Gmail writes it (folded lines)."""
    parts = [authserv_id]
    if dkim:
        parts.append(f"dkim={dkim} header.i=@{dkim_domain or domain} header.s=s1 header.b=AbC123")
    if spf:
        mailfrom = spf_domain or domain
        parts.append(
            f"spf={spf} (google.com: domain of bounce@{mailfrom} designates 192.0.2.10 as permitted sender) "
            f"smtp.mailfrom=bounce@{mailfrom}"
        )
    if dmarc:
        parts.append(f"dmarc={dmarc} ({policy}) header.from={domain}")
    return ";\r\n       ".join(parts)


def run(**fields) -> AnalyzeResponse:
    return analyze(EmailMessage(**fields))


def finding(result: AnalyzeResponse, signal_id: str):
    return next((f for f in result.findings if f.signal_id == signal_id), None)


def counted(result: AnalyzeResponse) -> dict[str, int]:
    return {f.signal_id: f.counted_points for f in result.findings if f.counted_points > 0}


def check_status(result: AnalyzeResponse, check_id: str) -> str:
    return next(c.status for c in result.checks if c.id == check_id)
