"""Offline demonstration of the detection engine on harmless, fabricated test messages.

    cd backend
    python -m demo.run_demo            # all scenarios
    python -m demo.run_demo bec        # one scenario

No network access. The explanation is the deterministic template unless ANTHROPIC_API_KEY
is set. All domains are fictitious or reserved for documentation (example.com, 192.0.2.x).
"""

import sys

from app.engine import analyze
from app.explain import explain
from app.schemas import EmailMessage

_GOOD_AUTH = "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom=bounce@{d}; dmarc=pass (p=REJECT) header.from={d}"


def _message(sender, domain=None, **fields):
    defaults = dict(subject="Hello", body_text="", links=[], attachments=[])
    auth = _GOOD_AUTH.format(d=domain) if domain else None
    return EmailMessage(sender=sender, auth_results=auth, **{**defaults, **fields})


SCENARIOS = {
    "legitimate": (
        "Legitimate, authenticated notification",
        _message("GitHub <noreply@github.com>", "github.com", subject="Your pull request was merged",
                 body_text="Your pull request #42 was merged.", links=[{"url": "https://github.com", "text": "github.com"}]),
    ),
    "impersonation": (
        "Brand impersonation from a look-alike domain",
        _message("PayPal Service <service@paypa1-secure.com>", "paypa1-secure.com", body_text="We noticed a change on your account."),
    ),
    "url": (
        "Deceptive links: text shows paypal.com, plus a disguised numeric address",
        _message("Notifications <alerts@example.com>", "example.com",
                 links=[{"url": "https://paypal-verify-login.com", "text": "https://www.paypal.com"},
                        {"url": "http://3232235777", "text": None}]),
    ),
    "attachment": (
        "Executable disguised as a PDF",
        _message("Billing <billing@example.com>", "example.com", body_text="Invoice attached.",
                 attachments=[{"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload", "size": 48213}]),
    ),
    "content": (
        "Phishing language alone - reported, but kept low by design",
        _message("Mail Admin <admin@example.com>", "example.com",
                 body_text="Your mailbox will be suspended within 24 hours. Verify your password now to keep access."),
    ),
    "bec": (
        "Payment request with replies diverted to a free mailbox (known limitation: stays low)",
        _message("Dana Levi (CFO) <dana@example.com>", "example.com", reply_to="dana.cfo.office@gmail.com",
                 body_text="Please update our supplier's bank account details to the new IBAN today. It is urgent."),
    ),
    "upwind": (
        "Upwind impersonation with a password request",
        _message("Upwind IT Support <it-support@upw1nd.io>", None,
                 body_text="Your Upwind password expires today. Please confirm your password to keep access."),
    ),
    "full": (
        "Phishing across all categories",
        _message("PayPal Service <service@paypa1-secure.com>", "paypa1-secure.com",
                 body_text="Your account will be suspended within 24 hours. Please verify your password.",
                 links=[{"url": "https://paypal-verify-login.com", "text": "https://www.paypal.com"}],
                 attachments=[{"filename": "PayPal_Form.html", "content_type": "text/html", "size": 2048}]),
    ),
}


def run(name: str) -> None:
    title, message = SCENARIOS[name]
    result = analyze(message)
    result.explanation = explain(result)

    print(f"\n=== {name}: {title}")
    print(f"Verdict: {result.verdict}   Risk score: {result.score}/100   ({result.verdict_reason})")
    for f in result.findings:
        print(f"  [{f.severity:6}] +{f.counted_points:<2} {f.score_status:11} {f.title}")
        for e in f.evidence[:2]:
            print(f"        - {e}")
    print(f"Explanation ({result.explanation.source}): {result.explanation.summary}")
    print(f"What to do: {result.explanation.recommendation}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    for scenario in sys.argv[1:] or SCENARIOS:
        run(scenario)
