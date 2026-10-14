"""Offline demonstration of the detection engine on harmless, fabricated test messages.

    cd backend
    python -m demo.run_demo            # all scenarios
    python -m demo.run_demo bec        # one scenario

No network access: the reputation scenario uses a simulated provider answer, and the
explanation is the deterministic template unless an LLM is explicitly configured.
All domains below are fictitious or reserved for documentation (example.com, 192.0.2.x).
"""

import os
import sys

from app import reputation
from app.engine import analyze
from app.explain import explain
from app.schemas import EmailMessage

_GOOD_AUTH = "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom=bounce@{d}; dmarc=pass (p=REJECT) header.from={d}"

SCENARIOS = {
    "legitimate": (
        "Legitimate, authenticated notification",
        dict(sender="GitHub <noreply@github.com>", auth_results=_GOOD_AUTH.format(d="github.com"),
             subject="Your pull request was merged", body_text="Your pull request #42 was merged.",
             links=[{"url": "https://github.com", "text": "github.com"}], attachments=[]),
    ),
    "impersonation": (
        "Brand impersonation from a look-alike domain",
        dict(sender="PayPal Service <service@paypa1-secure.com>", auth_results=_GOOD_AUTH.format(d="paypa1-secure.com"),
             subject="Account notice", body_text="We noticed a change on your account.", links=[], attachments=[]),
    ),
    "url": (
        "Deceptive link: shows paypal.com, leads elsewhere",
        dict(sender="Notifications <alerts@example.com>", auth_results=_GOOD_AUTH.format(d="example.com"),
             subject="Action needed", body_text="See the link below.",
             links=[{"url": "https://paypal-verify-login.com", "text": "https://www.paypal.com"},
                    {"url": "http://3232235777", "text": None}], attachments=[]),
    ),
    "attachment": (
        "Executable disguised as a PDF",
        dict(sender="Billing <billing@example.com>", auth_results=_GOOD_AUTH.format(d="example.com"),
             subject="Invoice", body_text="Invoice attached.", links=[],
             attachments=[{"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload", "size": 48213}]),
    ),
    "content": (
        "Phishing language alone - reported, but kept low by design",
        dict(sender="Mail Admin <admin@example.com>", auth_results=_GOOD_AUTH.format(d="example.com"),
             subject="Mailbox suspension", links=[], attachments=[],
             body_text="Dear user, your mailbox will be suspended within 24 hours. Verify your password now to keep access."),
    ),
    "bec": (
        "Business email compromise: payment request, replies diverted",
        dict(sender="Dana Levi (CFO) <dana@example.com>", reply_to="dana.cfo.office@gmail.com",
             auth_results=_GOOD_AUTH.format(d="example.com"), subject="Urgent payment", links=[], attachments=[],
             body_text="Please update our supplier's bank account details to the new IBAN and process the wire transfer today. Keep this confidential."),
    ),
    "reputation": (
        "Threat-intelligence listing (SIMULATED provider answer)",
        dict(sender="Team <team@example.com>", auth_results=_GOOD_AUTH.format(d="example.com"), subject="Hello",
             body_text="Take a look.", links=[{"url": "https://malware.testing.example", "text": None}], attachments=[]),
    ),
    "organization": (
        "Impersonation of your organization (ORG_DOMAINS=upwind.io)",
        dict(sender="Upwind IT Support <it-support@upw1nd.io>", subject="Password expiry", links=[], attachments=[],
             body_text="Your Upwind password expires today. Please confirm your password to keep access."),
    ),
}


def _simulated_safe_browsing(url, body, timeout):
    entries = body["threatInfo"]["threatEntries"]
    return {"matches": [{"threatType": "MALWARE", "threat": e, "cacheDuration": "300s"} for e in entries
                        if "malware.testing" in e["url"]]}


def run(name: str) -> None:
    title, fields = SCENARIOS[name]
    saved = dict(os.environ)
    if name == "reputation":
        os.environ["SAFE_BROWSING_API_KEY"] = "simulated"
        reputation._post_json = _simulated_safe_browsing  # demo only: no network call
    if name == "organization":
        os.environ.update(ORG_DOMAINS="upwind.io", ORG_NAME="Upwind")
    try:
        result = analyze(EmailMessage(**fields))
        result.explanation = explain(result)
    finally:
        os.environ.clear()
        os.environ.update(saved)
        reputation.reset_state()

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
