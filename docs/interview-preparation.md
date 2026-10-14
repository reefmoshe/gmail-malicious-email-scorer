# Interview preparation

A guide to defending the implementation. Every statement refers to the actual code.

## 1. Files that matter

| File | Responsibility |
|---|---|
| `addon/appsscript.json` | Manifest: contextual trigger, 3 OAuth scopes, `urlFetchWhitelist` (only our backend) |
| `addon/Code.gs` | Entry points: `onGmailMessageOpen` (trigger), `onHomepage`, `onRetry` |
| `addon/Extract.gs` | Reads the open message with the event's access token; minimizes data (headers, link origins, attachment metadata, text without URLs) |
| `addon/Api.gs` | `UrlFetchApp` call with `X-API-Key` from Script Properties; never throws, returns `{ok, data/error}` |
| `addon/Cards.gs` | Card UI; `escape_()` on every email-derived string |
| `backend/app/main.py` | `/health`, `/analyze`; body-size limit; content-free logging |
| `backend/app/security.py` | `require_api_key`: constant-time compare, fails closed if unset |
| `backend/app/schemas.py` | API contract: max lengths, `extra="forbid"`, response model |
| `backend/app/engine/__init__.py` | `analyze()`: parse once, run checks isolated, score, coverage |
| `backend/app/engine/signals.py` | **Single source of truth** for categories, caps, weights, groups, wording |
| `backend/app/engine/scoring.py` | `score()` (dedup, groups, reinforcement, caps) and `decide_verdict()` |
| `backend/app/engine/context.py` | Safe parsing of headers into `EmailContext`; never raises |
| `backend/app/engine/domains.py` | Registered domains, IDN, confusable skeleton, `find_lookalike()` |
| `backend/app/engine/brands.py` | Protected brands, RDAP-verified domains, benign exceptions, free-mail list |
| `backend/app/engine/checks/*.py` | One module per check: authentication, lookalike, display_name, reply_to, links, attachments, content |
| `backend/app/explain/` | `explain()` after scoring; template fallback; LLM adapter; versioned system prompt |

## 2. Libraries and why

- **FastAPI + Pydantic** - typed contract and validation (length limits, unknown fields rejected) for little code.
- **publicsuffixlist** - correct registered domains (`a.b.co.il` -> `b.co.il`), offline snapshot, no dependencies. Hand-written suffix lists are a classic source of bugs.
- **Python standard library** - `email.utils.getaddresses` (address parsing), `urllib.parse`, `ipaddress` (incl. disguised IP notations), `unicodedata` (NFKC, confusables).
- **anthropic** - official SDK for the optional explanation, imported lazily inside `call_provider`.
- Deliberately **no** ML/NLP libraries, no database, no Docker.

## 3. Data flow

1. Gmail opens a message -> `onGmailMessageOpen(e)` with `e.gmail.messageId` and a short-lived `accessToken`.
2. `GmailApp.setCurrentMessageAccessToken` -> read only that message (scope `gmail.addons.current.message.readonly`).
3. `extractMessageMetadata` builds the payload: subject, From, Reply-To, Return-Path, date, `Authentication-Results`; links as `scheme://[user@]host` + text only if the text is an address; attachments as name/type/size; up to 8,000 chars of text with URLs replaced by `[link]`. Failed extractions are sent as `null` ("not collected"), never as empty.
4. `POST /analyze` over HTTPS with `X-API-Key` - deterministic only, no LLM. If a key is configured the card offers "Explain with AI"; clicking it calls `POST /explain`, which re-runs the engine on the same message and only then asks the LLM (model `claude-haiku-5-5`, `LLM_MAX_TOKENS` default 400, cached per result).
5. Backend: size check -> API key -> Pydantic validation -> `analyze()` -> `explain()` -> JSON.
6. Card: verdict section (engine), explanation section (labelled), technical findings, reassuring signs, what was checked.

## 4. How each check works

- **Authentication** (`checks/authentication.py`): parses `Authentication-Results` with a comment-aware splitter. Trusts it only if `authserv-id == mx.google.com` and `header.from` matches the From domain. If DMARC was evaluated, its result decides and SPF/DKIM failures are correlated into it (group `dmarc`); if not, SPF and DKIM are scored independently. Missing header -> `not_available`, not a failure.
- **Look-alike domains** (`domains.find_lookalike`): exits early for official/verified/benign domains; then per brand token: skeleton equality (homoglyphs, IDN), same name under another ending (not for dictionary words), a realistic typo (`_is_typo`: missing/extra/swapped letter or adjacent QWERTY key, names of 6+ characters), brand + account/security word, brand as subdomain. Any match = one finding, 35 points.
- **Display name** (`checks/display_name.py`): brand named in the display name but the address is not the brand's; an email address inside the display name from another domain; a free mailbox claiming a brand or role. All three share the group `display_name_claim`.
- **Reply-To** (`checks/reply_to.py`): replies go to a different registered domain (6, low); a look-alike Reply-To (20) supersedes it (group `reply_diversion`).
- **Links** (`checks/links.py`): visible text domain vs destination (excluding same owner and link-rewriting services), look-alike destination (not for the sender's own domain), IP host, `@` trick, deep or mixed-alphabet hosts, abused TLDs, shorteners, plain http. Never fetched.
- **Attachments** (`checks/attachments.py`): final extension read like Windows (hidden characters and trailing dots removed): executable 30, macro document 20, web page/disk image 15, double extension 15, name vs declared type 5.
- **Content** (`content.py`): per sentence - credential word + action verb; payment word + action verb or bank details + change word; urgency/threat only if a request exists. Single words never count.

## 5. Scoring in one minute

`score()`: merge by signal id -> in each category keep the strongest finding per correlation group -> reduce weaker findings about the same brand/file to 5 (reinforcement) -> apply the category cap -> sum, cap at 100. `decide_verdict()`: >=70 Malicious, >=30 Suspicious, otherwise Low risk - but one counted high-severity finding lifts Low risk to Suspicious. If no check could run: Inconclusive with no score.

Worked example: "PayPal Service" <service@paypa1-secure.com>, link text `www.paypal.com` -> `paypal-verify-login.com`, "verify your password ... suspended in 24 hours", attachment `PayPal_Form.html`:
sender 35 + 5 (reinforcing) = 40; links 25 + 5 (reinforcing) = 30; attachment 15; content 10 + 5 = 15 -> 100 -> Likely malicious.

## 6. Key architecture decisions

1. **Collect in the add-on, decide in the backend** - only the add-on can read Gmail; logic in Python is testable and has one source of truth.
2. **Deterministic rules, not ML** - explainable, testable, no training data available.
3. **Registry-driven scoring** - weights live only in `signals.py`; checks report evidence, never points.
4. **Missing data is explicit** - five check statuses and a coverage section; no rescaling.
5. **Binary look-alike detection** - accuracy improved with safeguards instead of low-confidence tiers.
6. **The LLM explains, never decides** - runs after scoring on a copy, validated output, template fallback.
7. **Data minimization by design** - host-only links, metadata-only attachments, text without URLs.

## 7. Advantages and disadvantages

| Advantages | Disadvantages |
|---|---|
| Every point traceable to evidence | Heuristic weights, not calibrated |
| Low false-positive design (correlation, caps, safeguards) | Misses attacks that look ordinary (BEC without link/attachment) |
| Least-privilege Gmail access, minimized data | Paths/parameters of links not analyzed |
| 341 tests, deterministic results | Brand list and phrase lists need maintenance |
| Works with no external service | Free hosting sleeps when idle |

## 8. Trade-offs to be ready to discuss

- **Privacy vs detection depth**: sending only link hosts protects reset tokens but loses redirect detection.
- **Simplicity vs coverage**: reputation, organization protection and a BEC combination rule were built, evaluated and removed to keep the product explainable (tag `full-scope-v0.4.0`).
- **False positives vs false negatives**: low weights for common signals; a single high-severity signal gives Suspicious, never Malicious.
- **LLM value vs risk**: better wording vs data sharing, cost and prompt injection - mitigated by redaction, validation, fallback, and an explicit opt-in (setting the key).

## 9. Known limitations

BEC without links or attachments stays Low risk (~21); only listed brands are protected; no reputation data; phrase-based content can be paraphrased; only the first `Authentication-Results` header; broken HTML can hide links; cold starts on the free tier.

## 10. With more time

Labelled dataset and weight tuning (precision/recall per signal); Safe Browsing Update API (hash prefixes); organization-domain protection; a BEC combination rule; redirect-parameter analysis inside the add-on; rate limiting, key rotation, monitoring; always-on hosting.

## 11. Likely interview questions (with short answers)

1. **Why not just trust Gmail's spam filter?** It already blocks most spam; this targets the explanation gap - showing *why* an email that reached the inbox is risky - and phishing that passes filters (look-alike domains with valid authentication).
2. **Anyone can write an `Authentication-Results` header. How do you trust it?** Only results with `authserv-id = mx.google.com` and a `header.from` matching the From domain (`checks/authentication.py`); otherwise `not_available`.
3. **Why doesn't SPF failure count when DMARC passes?** DMARC already combines SPF and DKIM with alignment; forwarding breaks SPF while DKIM still verifies. Counting both would penalize legitimate forwarded mail.
4. **Why is DMARC pass not subtracted from the score?** Attackers pass DMARC on their own look-alike domains. Authentication proves who sent it, not that they are trustworthy.
5. **How do you avoid flagging `google-analytics.com` as a Google look-alike?** RDAP-verified owned domains, a separate benign-exception list, whole-label matching, realistic-typo rules, and requiring an account/security word for brand + word.
6. **Walk me through `paypa1-secure.com`.** Registered domain `paypa1-secure.com`, label parts `paypa1`, `secure`; skeleton(`paypa1`) == skeleton(`paypal`) and `secure` is a context word -> "combines the brand name with account or security words" -> 35.
7. **What prevents double counting?** Dedup by signal id, correlation groups, reinforcement, category caps - all in `scoring.py`, all tested in `test_scoring.py`.
8. **Why can't one finding make an email Malicious?** Category caps are below 70, and the severity floor only lifts to Suspicious. Malicious requires independent evidence from several categories.
9. **Why are the weights what they are?** Specificity to malicious mail, frequency in legitimate mail, independence and impact; they are explainable heuristics, not statistics. I'd tune them on labelled data.
10. **How do you handle hostile input?** Length limits and unknown-field rejection, 64 KB body cap, parsers that never raise, bounded regexes (tested with hostile input), escaping in the card, punycode in evidence.
11. **What does the backend log?** Verdict, score, signal ids, number of checks, explanation source, duration - never content or addresses (tested in `test_pipeline.py` and `test_explanation.py`).
12. **How do you stop the LLM from changing the verdict?** It runs after scoring on a deep copy and returns only text; the response's engine fields are never derived from it. Tests compare the engine result before and after.
13. **And prompt injection through the email?** Email-derived text is redacted, bounded and isolated in `untrusted_evidence`; the system prompt marks it as data; the output is schema-validated and rejected for certainty claims or a different score; no tools. Worst case, the template is shown.
14. **What happens if the backend is asleep or down?** `Api.gs` catches the error and the card shows a message with "Analyze again"; nothing is treated as safe.
15. **What would you change for production?** Calibration on labelled data, reputation lookups with hashed prefixes, organization configuration, rate limiting and key rotation, monitoring, always-on hosting, and the Marketplace OAuth verification process.
16. **Why Apps Script and not a Chrome extension?** Native Gmail integration, Google-managed OAuth with per-message tokens, works in web and mobile Gmail, no page scraping.
17. **What's your biggest known gap?** Business email compromise without a link or attachment - each signal is common in legitimate mail. I built a combination rule and removed it to keep the scoring model simple; it's the first thing I'd add back, with data to justify its weight.
