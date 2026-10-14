"""Optional LLM wording of the engine's result. The engine decides; the LLM only explains.

Trust boundary:
  - Trusted input: verdict, score, finding titles and explanations - all written by us.
  - Untrusted input: evidence snippets derived from the email (domains, file names). They are
    redacted, bounded, kept out of content-derived categories, sent in a separate field,
    and the model is told to treat them as data. Message text is never sent.
  - Output is schema-validated and checked against the engine result; any problem -> None,
    and the caller falls back to the deterministic template.

The provider adapter is the only vendor-specific code; nothing else depends on it.
"""

import hashlib
import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from ..schemas import AnalyzeResponse

logger = logging.getLogger("scorer.explain")

# Rewording a finished result needs no deep reasoning: a fast, low-cost model is enough.
DEFAULT_MODEL = "claude-haiku-5-5"
DEFAULT_MAX_TOKENS = 400
_MAX_TOKENS_RANGE = (100, 4000)
_DEFAULT_TIMEOUT_SECONDS = 12.0
_CACHE_SECONDS = 3600
_CACHE_ENTRIES = 256
_EVIDENCE_CATEGORIES = {"authentication", "sender_identity", "urls", "attachments"}


class UnusableResponse(Exception):
    """The provider answered, but the answer cannot be used (truncated, refused, no text)."""

# Version-controlled system prompt, kept in its own file so it can be reviewed on its own.
SYSTEM_PROMPT = (Path(__file__).parent / "system_prompt.md").read_text(encoding="utf-8").strip()

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "2-3 sentences: what the result means for the user"},
        "key_reasons": {
            "type": "array",
            "items": {"type": "string"},
            "description": "The 1-3 most important reasons, one short sentence each",
        },
        "recommendation": {"type": "string", "description": "One or two sentences: what the user should do"},
        "limitations": {"type": ["string", "null"], "description": "Important checks that could not run, or null"},
    },
    "required": ["summary", "key_reasons", "recommendation", "limitations"],
    "additionalProperties": False,
}

# Claims the engine never makes; an output containing them is rejected.
_CERTAINTY_RE = re.compile(
    r"\b(?:definitely|certainly|guaranteed|100\s?%|completely|totally|absolutely)\s+(?:safe|legitimate|harmless|malicious|a scam|fraud)",
    re.IGNORECASE,
)
_SAFE_CLAIM_RE = re.compile(r"\b(?:is|looks|appears)\s+(?:completely\s+|totally\s+)?safe\b", re.IGNORECASE)
# A cautious sentence ("this does not mean it is definitely safe") is the desired wording,
# so a claim preceded by a negation in the same sentence is not a claim.
_NEGATION_RE = re.compile(r"\b(?:not|no|never|cannot|without)\b|n't\b", re.IGNORECASE)
_SCORE_RE = re.compile(r"\b(\d{1,3})\s*(?:/\s*100|out of 100)", re.IGNORECASE)


def _asserts(pattern: re.Pattern, text: str) -> bool:
    for match in pattern.finditer(text):
        sentence_start = max(text.rfind(c, 0, match.start()) for c in ".!?;")
        if not _NEGATION_RE.search(text[sentence_start + 1 : match.start()]):
            return True
    return False


class LlmExplanation(BaseModel):
    summary: str = Field(min_length=1, max_length=600)
    key_reasons: list[str] = Field(min_length=1, max_length=3)
    recommendation: str = Field(min_length=1, max_length=400)
    limitations: str | None = Field(default=None, max_length=400)


def is_enabled() -> bool:
    """Setting ANTHROPIC_API_KEY is the explicit opt-in to send redacted findings to Anthropic."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def build_input(result: AnalyzeResponse) -> dict:
    counted = [f for f in result.findings if f.counted_points > 0][:6]
    evidence = []
    for f in counted:
        if f.category in _EVIDENCE_CATEGORIES:
            evidence.extend(redact(e, f.category) for e in f.evidence[:2])
    return {
        "engine_result": {
            "verdict": result.verdict,
            "risk_score": result.score,
            "score_meaning": "heuristic risk score from 0 to 100, not a probability",
            "verdict_reason": result.verdict_reason,
        },
        "findings": [
            # First sentence of our own explanation only: enough meaning, fewer input tokens.
            {"title": f.title, "severity": f.severity, "points": f.counted_points, "meaning": f.explanation.split(". ")[0]}
            for f in counted
        ],
        "reassuring_signs": [p.title for p in result.positive_findings[:3]],
        "limitations": result.coverage.limitations[:4],
        "untrusted_evidence": evidence[:8],
    }


_EMAIL_RE = re.compile(r"[^\s\"'<>()@]+@([^\s\"'<>()@]+)")
_QUOTED_RE = re.compile(r'"[^"]*"')


def redact(evidence: str, category: str) -> str:
    """Drop personal parts: mailbox names, and quoted display names (which may be people's names)."""
    text = _EMAIL_RE.sub(r"[address]@\1", evidence)
    if category in ("sender_identity", "organization"):
        text = _QUOTED_RE.sub('"[sender name]"', text)
    return text[:160]


def validate(raw: object, result: AnalyzeResponse) -> LlmExplanation | None:
    try:
        explanation = LlmExplanation.model_validate(raw)
    except ValidationError:
        return None
    text = " ".join([explanation.summary, *explanation.key_reasons, explanation.recommendation, explanation.limitations or ""])
    if _asserts(_CERTAINTY_RE, text):
        return None
    if result.verdict != "LOW_RISK" and _asserts(_SAFE_CLAIM_RE, text):
        return None
    for match in _SCORE_RE.finditer(text):
        if result.score is None or int(match.group(1)) != result.score:
            return None  # the explanation must not restate a different score
    return explanation


# Identical engine results get the identical explanation: repeated clicks or re-opened emails
# never pay twice. Keyed by a hash of the (already sanitized) model input; memory only.
_cache: "OrderedDict[str, tuple[float, LlmExplanation]]" = OrderedDict()
_cache_lock = threading.Lock()
_inflight: dict[str, threading.Lock] = {}


def generate(result: AnalyzeResponse) -> LlmExplanation | None:
    """Return a validated explanation, or None on any failure. Never raises."""
    payload = build_input(result)
    key = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    with _cache_lock:
        lock = _inflight.setdefault(key, threading.Lock())
    try:
        with lock:  # a concurrent duplicate request waits for the first one instead of paying again
            cached = _cached(key)
            if cached:
                return cached
            explanation = _request(payload, result)
            if explanation:
                with _cache_lock:
                    _cache[key] = (time.time() + _CACHE_SECONDS, explanation)
                    while len(_cache) > _CACHE_ENTRIES:
                        _cache.popitem(last=False)
            return explanation
    finally:
        with _cache_lock:
            _inflight.pop(key, None)


def _request(payload: dict, result: AnalyzeResponse) -> LlmExplanation | None:
    try:
        raw = call_provider(payload)
    except UnusableResponse as exc:
        logger.warning("llm explanation unusable: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001 - any provider failure means "use the template"
        logger.warning("llm explanation unavailable: %s", type(exc).__name__)
        return None
    explanation = validate(raw, result)
    if explanation is None:
        logger.warning("llm explanation rejected by validation")
    return explanation


def _cached(key: str) -> LlmExplanation | None:
    with _cache_lock:
        entry = _cache.get(key)
        if entry and entry[0] > time.time():
            return entry[1]
        return None


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()
        _inflight.clear()


def call_provider(payload: dict) -> object:
    """Anthropic adapter (official SDK). Swap this function to use another provider."""
    import anthropic  # optional dependency, loaded only when explanations are requested

    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)
    request = {
        "model": model,
        "max_tokens": max_tokens(),
        "system": SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": "Explain this result to the user. The JSON below is the complete input.\n"
                "<engine_output>\n" + json.dumps(payload, ensure_ascii=False) + "\n</engine_output>",
            }
        ],
        "output_config": {"effort": "low", "format": {"type": "json_schema", "schema": _OUTPUT_SCHEMA}},
    }
    if model.startswith("claude-haiku"):
        # Thinking tokens count against max_tokens; this task needs none, so the whole
        # budget goes to the answer. (Opus/Sonnet 5.5 cannot disable thinking.)
        request["thinking"] = {"type": "disabled"}

    client = anthropic.Anthropic(timeout=_timeout(), max_retries=0)
    response = client.messages.create(**request)
    usage = getattr(response, "usage", None)
    if usage is not None:  # token counts only - used to check that the output budget is sufficient
        logger.info("llm model=%s input_tokens=%s output_tokens=%s max_tokens=%s stop_reason=%s",
                    model, usage.input_tokens, usage.output_tokens, request["max_tokens"], response.stop_reason)
    if response.stop_reason == "max_tokens":
        raise UnusableResponse("truncated at max_tokens")
    if response.stop_reason != "end_turn":
        raise UnusableResponse(f"stop_reason {response.stop_reason}")
    text = next((block.text for block in response.content if block.type == "text"), None)
    if text is None:
        raise UnusableResponse("no text block")
    return json.loads(text)


def max_tokens() -> int:
    """LLM_MAX_TOKENS, default 400; invalid or out-of-range values fall back to the default."""
    raw = os.environ.get("LLM_MAX_TOKENS")
    if raw is None:
        return DEFAULT_MAX_TOKENS
    try:
        value = int(raw)
    except ValueError:
        logger.warning("invalid LLM_MAX_TOKENS; using %d", DEFAULT_MAX_TOKENS)
        return DEFAULT_MAX_TOKENS
    low, high = _MAX_TOKENS_RANGE
    if not low <= value <= high:
        logger.warning("LLM_MAX_TOKENS outside %d-%d; using %d", low, high, DEFAULT_MAX_TOKENS)
        return DEFAULT_MAX_TOKENS
    return value


def _timeout() -> float:
    try:
        return float(os.environ.get("LLM_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        return _DEFAULT_TIMEOUT_SECONDS
