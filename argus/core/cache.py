"""
argus.core.cache
~~~~~~~~~~~~~~~~~
Thread-safe SQLite-backed cache with LRU eviction and per-entry TTL.

Replaces the old ``shelve``-based cache which was not thread-safe and
had unbounded growth.

Key improvements:
  • SQLite WAL mode → concurrent readers + single writer without corruption
  • Per-entry TTL (default 24 h, configurable per ``put()`` call)
  • Max size with LRU eviction (default 2 000 entries)
  • Optional zlib compression for large payloads
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
import zlib
from pathlib import Path
from typing import Any

CACHE_DIR = Path.home() / ".argus"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DB = CACHE_DIR / "cache.db"

DEFAULT_TTL = 86400      # 24 hours
MAX_ENTRIES = 2000       # LRU eviction threshold
COMPRESS_THRESHOLD = 1024  # bytes – compress values bigger than this

_local = threading.local()
_init_lock = threading.Lock()
_db_initialized = False


def _get_conn() -> sqlite3.Connection:
    """Return a per-thread SQLite connection (created lazily)."""
    conn: sqlite3.Connection | None = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(str(CACHE_DB), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _init_lock:
        if _db_initialized:
            return
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key        TEXT PRIMARY KEY,
                value      BLOB NOT NULL,
                compressed INTEGER NOT NULL DEFAULT 0,
                ttl        REAL NOT NULL,
                created_at REAL NOT NULL,
                accessed_at REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS ix_cache_accessed ON cache(accessed_at)")
        conn.commit()
        _db_initialized = True


# ── Helpers ──────────────────────────────────────────────────────────────────

def _key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _encode(data: str) -> tuple[bytes, bool]:
    raw = data.encode("utf-8")
    if len(raw) >= COMPRESS_THRESHOLD:
        return zlib.compress(raw), True
    return raw, False


def _decode(blob: bytes, compressed: bool) -> str:
    if compressed:
        blob = zlib.decompress(blob)
    return blob.decode("utf-8")


# ── Public API ───────────────────────────────────────────────────────────────

def get(url: str) -> str | None:
    """Retrieve a cached value.  Returns ``None`` on miss or expiry."""
    conn = _get_conn()
    key = _key(url)
    now = time.time()
    row = conn.execute(
        "SELECT value, compressed, ttl, created_at FROM cache WHERE key = ?", (key,)
    ).fetchone()
    if row is None:
        return None
    value, compressed, ttl, created_at = row
    if now - created_at > ttl:
        conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        conn.commit()
        return None
    # update access time for LRU
    conn.execute("UPDATE cache SET accessed_at = ? WHERE key = ?", (now, key))
    conn.commit()
    return _decode(value, bool(compressed))


def put(url: str, content: str, ttl: float = DEFAULT_TTL) -> None:
    """Store a value with a TTL (seconds).  Evicts LRU entries if over max."""
    conn = _get_conn()
    key = _key(url)
    blob, compressed = _encode(content)
    now = time.time()
    conn.execute(
        """INSERT OR REPLACE INTO cache (key, value, compressed, ttl, created_at, accessed_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (key, blob, int(compressed), ttl, now, now),
    )
    conn.commit()
    _evict_if_needed(conn)


def clear() -> int:
    """Delete all entries.  Returns count deleted."""
    conn = _get_conn()
    count = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
    conn.execute("DELETE FROM cache")
    conn.commit()
    return count


def stats() -> dict[str, Any]:
    """Return cache statistics."""
    conn = _get_conn()
    now = time.time()
    total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
    valid = conn.execute(
        "SELECT COUNT(*) FROM cache WHERE (? - created_at) <= ttl", (now,)
    ).fetchone()[0]
    size_bytes = conn.execute(
        "SELECT COALESCE(SUM(LENGTH(value)), 0) FROM cache"
    ).fetchone()[0]
    return {
        "total": total,
        "valid": valid,
        "expired": total - valid,
        "size_bytes": size_bytes,
    }


# ── Internal ─────────────────────────────────────────────────────────────────

def _evict_if_needed(conn: sqlite3.Connection) -> None:
    """Remove oldest-accessed entries when the cache exceeds ``MAX_ENTRIES``."""
    count = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
    if count <= MAX_ENTRIES:
        return
    excess = count - MAX_ENTRIES
    conn.execute(
        "DELETE FROM cache WHERE key IN "
        "(SELECT key FROM cache ORDER BY accessed_at ASC LIMIT ?)",
        (excess,),
    )
    conn.commit()
