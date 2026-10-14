# Detection engine reference

The complete list of signals, weights and rules. For the overview, see the [README](../README.md).

Every weight is an **explainable security heuristic**, chosen by asking: how strong is the
evidence, how often does it appear in legitimate mail, is it independent of other findings, and
what is the impact if it is true. No weight is statistically calibrated. The score is a heuristic
risk score, not a probability.

## Pipeline

```
build_context()  ->  run each check in isolation  ->  score()  ->  decide_verdict()  ->  explain()
parse once,          exception -> "failed",          dedup,        thresholds +        wording only,
never raises         other checks continue            groups,       severity floor      after scoring
                                                      reinforcement,
                                                      caps
```

Check statuses: `completed`, `failed`, `not_applicable` (e.g. no attachments), `not_available`
(data missing, e.g. no authentication results), `not_implemented`. Missing data never adds points
and is never reported as "safe".

## Scoring rules (`engine/scoring.py`)

1. **Dedup** - a signal id counts once; repeated detections merge their evidence (max 5 examples).
2. **Correlation groups** - signals describing one behaviour share a group; only the strongest
   counts, the others are shown as `correlated` with 0 points.
3. **Reinforcement** - a weaker finding about the *same* brand or file as a stronger finding in the
   same category corroborates it: it adds only its `reinforcing_points` (5), status `reinforcing`.
4. **Category caps** - each kind of evidence has a ceiling; the excess is marked `capped`.
5. **Sum, capped at 100.** Positive evidence (e.g. DMARC pass) is reported but never subtracted,
   because attackers authenticate their own look-alike domains.

**Verdicts** - 0-29 `LOW_RISK` (worded "no strong warning signs", never "safe"), 30-69
`SUSPICIOUS`, 70-100 `MALICIOUS`; `INCONCLUSIVE` with score `null` when no check could run.
**Severity floor** - a single counted high-severity finding raises `LOW_RISK` to `SUSPICIOUS`,
never higher. **Coverage** - the score is never rescaled to the checks that ran;
`coverage.max_attainable_score` and `coverage.limitations` say what could not be assessed.

## Signals

### Sender authentication - cap 30 (`checks/authentication.py`)

| Signal | Pts | Sev | Notes |
|---|---|---|---|
| `AUTH_DMARC_FAIL` | 25 | high | Group `dmarc` when Gmail evaluated DMARC: SPF/DKIM failures are its components and are correlated into it |
| `AUTH_SPF_FAIL` / `AUTH_SPF_SOFTFAIL` | 10 / 5 | med / low | Scored independently only when there is no DMARC verdict (forwarding breaks SPF) |
| `AUTH_DKIM_FAIL` / `AUTH_DKIM_NONE` | 8 / 3 | med / low | Only if no signature passed |

Trust model: only results stamped by Gmail (`authserv-id = mx.google.com`) whose `header.from`
matches the From domain are used - anyone can add an `Authentication-Results` header.

### Sender identity - cap 45 (`checks/lookalike.py`, `display_name.py`, `reply_to.py`)

| Signal | Pts | Sev | Group / notes |
|---|---|---|---|
| `SENDER_LOOKALIKE_DOMAIN` | 35 | high | Binary detector below; any technique = 35 |
| `SENDER_REPLYTO_LOOKALIKE` | 20 | high | `reply_diversion` |
| `SENDER_FREEMAIL_ORG_CLAIM` | 12 (5) | med | `display_name_claim`, reinforcing |
| `SENDER_BRAND_DISPLAY_MISMATCH` | 10 (5) | med | `display_name_claim`, reinforcing |
| `SENDER_DISPLAY_HAS_ADDRESS` | 10 (5) | med | `display_name_claim`, reinforcing |
| `SENDER_REPLYTO_MISMATCH` | 6 | low | `reply_diversion`; free-mailbox diversion called out in the text |

Example: "PayPal Service" <service@paypa1-secure.com> = 35 (look-alike) + 5 (name reinforces the
same brand) = 40. A name claiming a *different* brand keeps its full 10.

**Look-alike detection (`domains.py`) is binary**: a technique matches with enough evidence, or
nothing is reported. Techniques: look-alike characters and IDN homographs (compared in a
confusable "skeleton"), realistic typos (one adjacent-key, missing, extra or swapped letter on
names of 6+ characters), the brand under another domain ending, the brand plus an account/security
word (`paypal-secure-login`), the brand as a subdomain (`paypal.com.account-verify.net`).
Safeguards: official and RDAP-verified brand-owned domains are never flagged; a separate list of
benign exceptions (unrelated owners - not treated as the brand); whole-label comparison
(`applebees.com` is not Apple); no "other ending" match for dictionary-word brands (`upwind.com`);
registered domains from the offline Public Suffix List; punycode shown in evidence.

### Links - cap 35 (`checks/links.py`, `urls.py`)

| Signal | Pts | Sev | Notes |
|---|---|---|---|
| `URL_TEXT_HREF_MISMATCH` | 25 | high | Visible text is a URL/domain and the destination's registered domain differs. Not raised for the same organization, brand-owned pairs, or click-tracking / security link rewriters. Group `obscured_destination` |
| `URL_LOOKALIKE_DOMAIN` | 15 (5) | high | Same detector; not raised for the sender's own domain (already scored) |
| `URL_IP_HOST` | 15 | med | Incl. integer / hex / octal-disguised addresses |
| `URL_USERINFO_AT` | 15 | high | `https://paypal.com@evil.example` |
| `URL_DECEPTIVE_STRUCTURE` | 8 | med | 5+ subdomain levels, or mixed alphabets in one label |
| `URL_SUSPICIOUS_TLD` | 5 | low | Static list of frequently abused endings |
| `URL_SHORTENER` | 5 | low | Group `obscured_destination` |
| `URL_PLAIN_HTTP` | 3 | low | |

Links are parsed as text only and are never fetched.

### Attachments - cap 35, metadata only (`checks/attachments.py`)

| Signal | Pts | Sev | Notes |
|---|---|---|---|
| `ATT_EXECUTABLE` | 30 | high | Programs, scripts, installers, shortcuts |
| `ATT_MACRO_DOC` | 20 | med | Macro-enabled Office formats |
| `ATT_RISKY_FORMAT` | 15 | med | Web pages (html, svg) and disk images (iso, img, vhd) |
| `ATT_DOUBLE_EXTENSION` | 15 (5) | high | `invoice.pdf.exe`; reinforces the type finding for the same file |
| `ATT_TYPE_MISMATCH` | 5 (5) | low | Extension family vs declared MIME type; generic types ignored |

Extensions are read the way Windows reads them: hidden/right-to-left characters removed and
trailing dots or spaces stripped. An executable alone is `SUSPICIOUS` (max 35), never `MALICIOUS`.

### Message content - cap 15, English and Hebrew (`content.py`, `checks/content.py`)

| Signal | Pts | Sev | Rule |
|---|---|---|---|
| `CONTENT_CREDENTIAL_REQUEST` | 10 | med | Credential word + action verb in one sentence |
| `CONTENT_FINANCIAL_REQUEST` | 10 | med | Payment word + action verb, or bank details + change word |
| `CONTENT_PRESSURE` | 5 | low | Urgency or account threat - only reported next to a request |

Single words never count. The low cap keeps language - which legitimate mail also uses - from
dominating the score.

## Explanation layer (`explain/`)

Runs after scoring on a deep copy and returns wording only. The template explanation is always
available; the LLM explanation is produced only by `POST /explain` (the "Explain with AI" button)
when `ANTHROPIC_API_KEY` is set - `/analyze` never calls it. The LLM receives trusted
engine fields and redacted evidence in a separate `untrusted_evidence` field (no message text,
mailbox names or display names), answers in a JSON schema, and its output is rejected - falling
back to the template - on certainty claims, a different score, refusals, timeouts or invalid JSON.
The system prompt is versioned in `explain/system_prompt.md`.

## Deliberately out of scope

Preserved in git (`full-scope-v0.4.0` tag) and listed as future work in the README:
Google Safe Browsing reputation, configurable organization-domain protection, and combined
"request + identity" indicators (business email compromise).
