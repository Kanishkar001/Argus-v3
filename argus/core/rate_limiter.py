"""
argus.core.rate_limiter
~~~~~~~~~~~~~~~~~~~~~~~~
Per-domain token-bucket rate limiter for outbound HTTP requests.

Usage::

    from argus.core.rate_limiter import rate_limit

    rate_limit("api.shodan.io")   # blocks until a token is available
    requests.get(...)
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict


class _TokenBucket:
    """Thread-safe token bucket."""

    __slots__ = ("_rate", "_capacity", "_tokens", "_ts", "_lock")

    def __init__(self, rate: float = 10.0, capacity: int = 10) -> None:
        self._rate = rate          # tokens / second
        self._capacity = capacity
        self._tokens = float(capacity)
        self._ts = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._ts
                self._ts = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)


class RateLimiterRegistry:
    """One bucket per domain, auto-created on first access."""

    def __init__(
        self,
        default_rate: float = 10.0,
        default_capacity: int = 10,
    ) -> None:
        self._default_rate = default_rate
        self._default_cap = default_capacity
        self._buckets: dict[str, _TokenBucket] = {}
        self._overrides: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def set_limit(self, domain: str, rate: float, capacity: int = 10) -> None:
        """Override the rate for a specific domain."""
        with self._lock:
            self._overrides[domain] = (rate, capacity)
            if domain in self._buckets:
                # replace the bucket with the new settings
                self._buckets[domain] = _TokenBucket(rate, capacity)

    def acquire(self, domain: str, timeout: float = 30.0) -> bool:
        with self._lock:
            if domain not in self._buckets:
                rate, cap = self._overrides.get(
                    domain, (self._default_rate, self._default_cap)
                )
                self._buckets[domain] = _TokenBucket(rate, cap)
            bucket = self._buckets[domain]
        return bucket.acquire(timeout)


# ── Module-level singleton ───────────────────────────────────────────────────
_registry = RateLimiterRegistry()


def rate_limit(domain: str, timeout: float = 30.0) -> bool:
    """Block until a rate-limit token is available for *domain*."""
    return _registry.acquire(domain, timeout)


def set_domain_limit(domain: str, rate: float, capacity: int = 10) -> None:
    """Configure a per-domain rate limit (tokens/second)."""
    _registry.set_limit(domain, rate, capacity)
