"""Shared-secret authentication between the Gmail add-on and the backend."""

import hmac
import os

from fastapi import Header, HTTPException, status


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Reject requests that do not carry the expected X-API-Key header.

    Fails closed: if the server has no API_KEY configured, nothing is accepted.
    """
    expected = os.environ.get("API_KEY")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server authentication is not configured",
        )
    # Constant-time comparison to avoid leaking the key through timing.
    if not x_api_key or not hmac.compare_digest(
        x_api_key.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
