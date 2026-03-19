"""
argus.core.http
~~~~~~~~~~~~~~~~
Enhanced shared HTTP client with:

  • Configurable exponential-backoff retry
  • Per-domain rate limiting (via ``core.rate_limiter``)
  • Proper User-Agent and default headers
  • SSL verification controls
  • Increased connection-pool sizes
  • Disk-cache integration (via ``core.cache``)
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from argus.config.settings import DEFAULT_TIMEOUT, HEADERS, USER_AGENT
from argus.core.cache import get as _cache_get, put as _cache_put
from argus.core.rate_limiter import rate_limit

logger = logging.getLogger("argus.core.http")


# ── Retry strategy ──────────────────────────────────────────────────────────

_RETRY = Retry(
    total=3,
    backoff_factor=0.5,              # 0s → 0.5s → 1s → 2s
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"],
    raise_on_status=False,
)


# ── Session factory ─────────────────────────────────────────────────────────

def _build_session(
    pool_connections: int = 50,
    pool_maxsize: int = 100,
    max_retries: Retry | None = None,
    verify_ssl: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> requests.Session:
    session = requests.Session()

    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=max_retries or _RETRY,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update({
        "User-Agent": USER_AGENT,
        **HEADERS,
        **(extra_headers or {}),
    })
    session.verify = verify_ssl
    return session


# ── Module-level shared session ─────────────────────────────────────────────

_session: requests.Session | None = None


def get_session(
    *,
    verify_ssl: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> requests.Session:
    """Return (or create) the shared HTTP session."""
    global _session
    if _session is None:
        _session = _build_session(verify_ssl=verify_ssl, extra_headers=extra_headers)
    return _session


def new_session(**kwargs: Any) -> requests.Session:
    """Create an isolated session (useful for modules needing different retry/SSL)."""
    return _build_session(**kwargs)


# ── Convenience helpers ─────────────────────────────────────────────────────

def cached_get(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    cache_ttl: float = 86400,
    respect_rate_limit: bool = True,
    **kwargs: Any,
) -> requests.Response | None:
    """GET with disk cache.  Returns a ``Response`` (real or mock) or ``None``."""

    # 1. Check cache
    cached_text = _cache_get(url)
    if cached_text is not None:
        mock = requests.models.Response()
        mock.status_code = 200
        mock._content = cached_text.encode("utf-8")
        mock.encoding = "utf-8"
        mock.url = url
        return mock

    # 2. Rate-limit
    if respect_rate_limit:
        domain = urlparse(url).netloc
        if domain:
            rate_limit(domain)

    # 3. Actual request
    session = get_session()
    try:
        resp = session.get(url, timeout=timeout, **kwargs)
        if resp.status_code == 200:
            _cache_put(url, resp.text, ttl=cache_ttl)
        return resp
    except requests.RequestException as exc:
        logger.warning("HTTP GET failed for %s: %s", url, exc)
        return None


def safe_get(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    respect_rate_limit: bool = True,
    **kwargs: Any,
) -> requests.Response | None:
    """GET without caching.  Returns a ``Response`` or ``None``."""
    if respect_rate_limit:
        domain = urlparse(url).netloc
        if domain:
            rate_limit(domain)
    session = get_session()
    try:
        return session.get(url, timeout=timeout, **kwargs)
    except requests.RequestException as exc:
        logger.warning("HTTP GET failed for %s: %s", url, exc)
        return None
