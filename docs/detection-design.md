# Detection engine design

## Principles

1. **Unusual is not malicious.** Many signals (a different Reply-To, an SPF failure) are common
   in legitimate mail. Weights reflect how *specific* a signal is to malicious mail.
2. **Missing data is never evidence of safety.** Checks that cannot run report
   `not_available` / `failed` / `not_implemented`, and the response says what was not analyzed.
3. **Count each behaviour once.** Correlated signals are grouped; only the strongest counts.
4. **Explain everything.** Every point in the score maps to a finding with evidence.
5. **Least data, no outbound calls.** The backend analyzes header metadata only, makes no DNS/HTTP
   requests, stores nothing, and logs no email content.

## Pipeline

```
add-on (Extract.gs)  ->  POST /analyze  ->  build_context()      parse once, never raises
                                        ->  run each check        isolated; exceptions -> "failed"
                                        ->  score()               merge, correlate, cap, sum
                                        ->  decide_verdict()      thresholds + severity floor
                                        ->  response              findings, positives, coverage
```

| File | Responsibility |
|---|---|
| `engine/signals.py` | Single source of truth: categories, caps, signal weights, wording, correlation groups |
| `engine/checks/*.py` | One module per check; returns a `CheckOutcome` (status, detections, positives) |
| `engine/checks/__init__.py` | Check registry (adding a check = one line) |
| `engine/context.py` | Safe parsing of untrusted header values |
| `engine/domains.py` | Registered domains (offline Public Suffix List), IDN, confusables, look-alikes |
| `engine/auth_results.py` | Tolerant `Authentication-Results` parser |
| `engine/brands.py` | Protected brands, free-mail providers, organizational role terms |
| `engine/scoring.py` | Scoring and verdict rules |

## Scoring

Score = sum over categories of `min(cap, sum of counted findings)`, capped at 100.
It is a **heuristic risk score**, not a probability. Weights are initial heuristics, not
statistically validated.

1. **Dedup by signal id**: a signal counts once; repeated detections merge their evidence.
2. **Correlation groups**: signals describing the same underlying behaviour share a group;
   only the strongest counts and the others are shown as `correlated` (0 points).
   - `dmarc`: DMARC is computed from SPF + DKIM + alignment, so when Gmail evaluated DMARC
     its result supersedes the component failures.
   - `display_name_claim`: brand-in-name, address-in-name and free-mail-org-claim all
     interpret the same display name.
   - `reply_diversion`: a look-alike Reply-To is also a mismatching Reply-To.
   - Not correlated on purpose: a look-alike sender *domain* and a brand *display name* are
     two separate deceptive choices by the sender.
3. **Reinforcement**: a weaker finding about the same impersonated brand as a stronger
   finding in the same category corroborates it rather than adding independent evidence,
   so it adds only its signal's `reinforcing_points` (status `reinforcing`). Display-name
   claims declare 5: "PayPal Service" <service@paypa1-secure.com> = 35 (look-alike) + 5 = 40,
   while a display name naming a *different* brand keeps its full 10. Signals without
   `reinforcing_points` (e.g. Reply-To look-alike) are never reduced.
4. **Category caps** bound how much one kind of evidence can contribute (`capped` status).
5. **Positive evidence never subtracts** (e.g. DMARC pass) - it is reported separately,
   because authenticated attacker-owned domains are common.

### Verdicts

| Score | Verdict |
|---|---|
| 0-29 | `LOW_RISK` (worded as "no strong warning signs", never "safe") |
| 30-69 | `SUSPICIOUS` |
| 70-100 | `MALICIOUS` |
| no check could run | `INCONCLUSIVE` (score `null`) |

**Severity floor:** a single counted *high*-severity finding (DMARC fail, look-alike domain)
raises `LOW_RISK` to `SUSPICIOUS`, never higher. These signals are rare in legitimate mail,
but one signal alone is never enough for `MALICIOUS`. The score itself is not changed.

**Coverage and reachability.** Authentication (cap 30) + sender identity (cap 45) can reach
75, so a header-only `MALICIOUS` verdict is possible but requires a strong impersonation
*and* failed authentication (e.g. look-alike domain + DMARC fail + Reply-To look-alike = 70).
We deliberately do **not** rescale the score to the implemented categories. When a category
could not run (e.g. no authentication results), the response reports
`coverage.max_attainable_score` and states when `MALICIOUS` is unreachable.

**Detection confidence** is not reported: without labelled data we cannot compute a
meaningful confidence, so we report *analysis completeness* (which checks ran) instead.

## Phase 1 signals (implemented)

| Signal | Pts | Sev | Notes / false positives |
|---|---|---|---|
| `AUTH_DMARC_FAIL` | 25 | high | Only from Gmail-stamped results. FP: forwarding, mailing lists, misconfigured senders |
| `AUTH_SPF_FAIL` | 10 | med | Only scored when DMARC was not evaluated. FP: forwarding |
| `AUTH_SPF_SOFTFAIL` | 5 | low | Weaker `~all` assertion |
| `AUTH_DKIM_FAIL` | 8 | med | Only if no signature passed. FP: mail modified by list servers |
| `AUTH_DKIM_NONE` | 3 | low | Many small senders do not sign |
| `SENDER_LOOKALIKE_DOMAIN` | 35 | high | Homoglyphs/IDN, typos, TLD swap, combosquatting, brand-as-subdomain |
| `SENDER_REPLYTO_LOOKALIKE` | 20 | high | Same detection on Reply-To |
| `SENDER_BRAND_DISPLAY_MISMATCH` | 10 (5 reinforcing) | med | FP: brands sending via third parties, resellers |
| `SENDER_DISPLAY_HAS_ADDRESS` | 10 (5 reinforcing) | med | Address in display name from another domain |
| `SENDER_REPLYTO_MISMATCH` | 6 | low | FP: newsletters, ticketing; free-mailbox diversion called out |
| `SENDER_FREEMAIL_ORG_CLAIM` | 12 (5 reinforcing) | med | FP: freelancers using e.g. "Support" in their name |

Sender identity category cap: 45.

**Authentication trust model.** Anyone can add an `Authentication-Results` header. Only
results whose authserv-id is `mx.google.com` are used, and results whose `header.from`
does not match the From domain are ignored. Gmail prepends its own header, and
`getHeader()` returns the first occurrence; a stricter variant (all headers via
`getRawContent()`) is listed below.

**Look-alike false-positive controls.** Whole-label comparison only (`applebees.com` is
not Apple); typo distance only for names of 6+ characters; generic words (e.g. "office")
are not brand tokens; brands can list several official domains; IDNs are shown in
punycode in evidence so the UI never renders a deceptive look-alike as genuine.

## Phase 2 (planned, not implemented)

None of the following needs a new OAuth scope: `gmail.addons.current.message.readonly`
already grants read access to the open message's body and attachments. Each item still
changes what data leaves Gmail, so each is a privacy decision.

### URLs (cap 35)
- **Add-on**: parse `message.getBody()` for up to 50 `<a href>` + visible text (bounded input,
  hrefs <= 2048 chars). Strip query strings and fragments before sending (they can carry
  personal tokens); trade-off: open-redirect parameters are not inspected.
- **Backend**: `urllib.parse` only - links are never fetched or followed.
  `URL_TEXT_HREF_MISMATCH` only when the visible text is itself a URL/domain (not "click here");
  ESP click-tracking rewrites links in legitimate newsletters, so tracker domains need care.
  Reuse `find_lookalike` for `URL_LOOKALIKE_DOMAIN`; static lists for shorteners and TLDs.
- **Reputation (optional)**: Google Safe Browsing (API key in Render env; prefer the hash-prefix
  Update API so full URLs are not disclosed). VirusTotal is unsuitable: submitted URLs become
  visible to its community, and rate limits are low. A confirmed Safe Browsing match is the only
  candidate for the score override to 90. Strict timeout; a failed lookup is `failed`, not clean.

### Attachments (cap 35)
- **Add-on**: `getAttachments({includeInlineImages: false})` -> name, content type, size only.
  Never `getBytes()`.
- Signals: executable / script / disk-image / shortcut types, macro-enabled Office, HTML/SVG
  attachments (credential phishing), double extensions, extension vs declared type mismatch,
  archives. Metadata is not proof: no override, and Gmail already blocks many executables.

### Content (cap 15)
- Needs body text. Options: (A) send truncated plain text (<= 10k chars), processed in memory,
  never logged; (B) compute features in Apps Script and send only matched categories (keeps the
  body inside Google, but splits detection logic). Recommendation: A, disclosed in the README.
- Contextual rules (e.g. credential noun + action verb + link in the same sentence), English
  and Hebrew phrase lists; the low cap bounds keyword noise.

### Other improvements
- All `Authentication-Results` headers via `getRawContent()` (same scope, heavier call).
- Protect the recipient's own organization domain: requires the `userinfo.email` scope
  (new consent) and only helps Workspace accounts.
- Weight review: header-only BEC (Reply-To diverted to a free mailbox) scores only 8 with the
  current weights. Candidate: a dedicated `SENDER_REPLYTO_FREEMAIL` signal in the
  `reply_diversion` group.
