"""FastAPI entry point for the Malicious Email Scorer backend."""

import logging
import time

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .engine import analyze
from .schemas import AnalyzeRequest, AnalyzeResponse
from .security import require_api_key

# Requests are small metadata payloads; anything bigger is rejected before parsing.
MAX_BODY_BYTES = 64 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("scorer")

app = FastAPI(title="Malicious Email Scorer API", version=__version__)


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
    started = time.perf_counter()
    result = analyze(request.message)
    # Log outcome and timing only - never email content or addresses.
    logger.info(
        "analyze mode=%s verdict=%s score=%s duration_ms=%.1f",
        result.analysis_mode,
        result.verdict,
        result.score,
        (time.perf_counter() - started) * 1000,
    )
    return result
