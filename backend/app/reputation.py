"""Optional threat-intelligence lookups for link hosts (Google Safe Browsing Lookup API v4).

Privacy: only host names are sent, as "http://host/" - never paths, queries or any other
email data - so this is a DOMAIN-level reputation check, not a full-URL check. A host can
be clean at domain level while a specific page on it is listed.

Disabled unless SAFE_BROWSING_API_KEY is set (setting it is the explicit opt-in to send
link host names to Google). Failures raise ReputationUnavailable; they are never treated
as "clean".
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import __version__

logger = logging.getLogger("scorer.reputation")

PROVIDER_NAME = "Google Safe Browsing"
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
_DEFAULT_TIMEOUT_SECONDS = 3.0
_CLEAN_CACHE_SECONDS = 300  # "no match" answers are cached briefly; listings use the API's cacheDuration
_MAX_CACHE_ENTRIES = 2000
_DEFAULT_BACKOFF_SECONDS = 60


class ReputationUnavailable(Exception):
    """The provider could not give an answer (not configured, timeout, rate limit, bad reply)."""


@dataclass(frozen=True)
class HostVerdict:
    host: str
    threat_types: tuple[str, ...]  # empty = no listing at domain level
    checked_at: float  # epoch seconds of the provider answer (freshness)
    from_cache: bool


_cache: dict[str, tuple[float, tuple[str, ...], float]] = {}  # host -> (expires, threats, checked_at)
_cache_lock = threading.Lock()
_backoff_until = 0.0


def is_configured() -> bool:
    return bool(os.environ.get("SAFE_BROWSING_API_KEY"))


def lookup_hosts(hosts: list[str]) -> list[HostVerdict]:
    api_key = os.environ.get("SAFE_BROWSING_API_KEY")
    if not api_key:
        raise ReputationUnavailable("not configured")
    now = time.time()
    if now < _backoff_until:
        raise ReputationUnavailable("rate-limited by the provider; retrying later")

    verdicts, pending = [], []
    with _cache_lock:
        for host in dict.fromkeys(hosts):
            cached = _cache.get(host)
            if cached and cached[0] > now:
                verdicts.append(HostVerdict(host, cached[1], cached[2], True))
            else:
                pending.append(host)
    if pending:
        verdicts.extend(_query(api_key, pending))
    return verdicts


def _query(api_key: str, hosts: list[str]) -> list[HostVerdict]:
    global _backoff_until
    body = {
        "client": {"clientId": "gmail-malicious-email-scorer", "clientVersion": __version__},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{host}/"} for host in hosts],
        },
    }
    try:
        reply = _post_json(f"{_ENDPOINT}?key={api_key}", body, _timeout())
    except urllib.error.HTTPError as exc:
        if exc.code in (429, 503):
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            _backoff_until = time.time() + (int(retry_after) if retry_after and retry_after.isdigit() else _DEFAULT_BACKOFF_SECONDS)
            raise ReputationUnavailable("rate-limited by the provider") from None
        raise ReputationUnavailable(f"provider returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ReputationUnavailable("provider unreachable or timed out") from None
    except ValueError:
        raise ReputationUnavailable("provider returned an invalid response") from None

    if not isinstance(reply, dict):
        raise ReputationUnavailable("provider returned an invalid response")
    checked_at = time.time()
    threats: dict[str, list[str]] = {host: [] for host in hosts}
    cache_seconds: dict[str, float] = {}
    for match in reply.get("matches", []) or []:
        try:
            host = match["threat"]["url"].split("//", 1)[1].rstrip("/")
            threat_type = str(match["threatType"])
            cache_seconds[host] = float(str(match.get("cacheDuration", "300s")).rstrip("s"))
        except (KeyError, TypeError, ValueError, IndexError):
            continue
        if host in threats and threat_type not in threats[host]:
            threats[host].append(threat_type)

    verdicts = []
    with _cache_lock:
        if len(_cache) > _MAX_CACHE_ENTRIES:
            _cache.clear()
        for host, types in threats.items():
            ttl = cache_seconds.get(host, _CLEAN_CACHE_SECONDS)
            _cache[host] = (checked_at + ttl, tuple(types), checked_at)
            verdicts.append(HostVerdict(host, tuple(types), checked_at, False))
    return verdicts


def _post_json(url: str, body: dict, timeout: float) -> dict:
    """Network boundary (replaced by a fake in tests). The URL contains the API key: never log it."""
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https endpoint
        return json.loads(response.read(1_000_000).decode("utf-8"))


def _timeout() -> float:
    try:
        return float(os.environ.get("REPUTATION_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        return _DEFAULT_TIMEOUT_SECONDS


def reset_state() -> None:
    """Clear cache and back-off (tests)."""
    global _backoff_until
    with _cache_lock:
        _cache.clear()
    _backoff_until = 0.0
