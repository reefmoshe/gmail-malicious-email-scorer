"""FastAPI entry point for the Malicious Email Scorer backend."""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .engine import analyze
from .explain import explain, llm
from .explain.template import template_explanation
from .schemas import AnalyzeRequest, AnalyzeResponse
from .security import require_api_key

# Requests are small metadata payloads; anything bigger is rejected before parsing.
MAX_BODY_BYTES = 64 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scorer")

@asynccontextmanager
async def lifespan(_: FastAPI):
    llm.warm_up()  # background SDK import; the first "Explain with AI" click stays fast
    yield


app = FastAPI(title="Malicious Email Scorer API", version=__version__, lifespan=lifespan)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_api_key)])
def analyze_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Runs on every opened email: deterministic result + template explanation. No LLM call."""
    started = time.perf_counter()
    result = analyze(request.message)
    result.explanation = template_explanation(result)
    result.ai_explanation_available = llm.is_enabled()
    _log("analyze", result, started)
    return result


@app.post("/explain", response_model=AnalyzeResponse, dependencies=[Depends(require_api_key)])
def explain_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """Runs only when the user clicks "Explain with AI".

    The client sends the same minimized message, never a score or verdict (the schema rejects
    unknown fields), so the explanation is always about the engine's own, authoritative
    result - recomputed here, deterministically identical to what /analyze returned.
    """
    started = time.perf_counter()
    result = analyze(request.message)
    result.explanation = explain(result)
    result.ai_explanation_available = llm.is_enabled()
    _log("explain", result, started)
    return result


def _log(action: str, result: AnalyzeResponse, started: float) -> None:
    # Outcome, signal ids and timing only - never evidence, email content or addresses.
    logger.info(
        "%s verdict=%s score=%s signals=%s checks_completed=%d/%d explanation=%s duration_ms=%.1f",
        action,
        result.verdict,
        result.score,
        ",".join(f.signal_id for f in result.findings) or "-",
        result.coverage.checks_completed,
        result.coverage.checks_total,
        result.explanation.source,
        (time.perf_counter() - started) * 1000,
    )
