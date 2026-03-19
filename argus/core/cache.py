import shelve, time, pathlib, hashlib, threading

CACHE_FILE = pathlib.Path.home() / ".argus_cache"
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
TTL = 86400  # 24 hours

_lock = threading.RLock()


def _key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def get(url: str):
    key = _key(url)
    with _lock:
        with shelve.open(str(CACHE_FILE)) as db:
            data = db.get(key)
            if not data:
                return None
            if time.time() - data["t"] > TTL:
                return None
            return data["d"]


def put(url: str, content: str) -> None:
    key = _key(url)
    with _lock:
        with shelve.open(str(CACHE_FILE)) as db:
            db[key] = {"d": content, "t": time.time()}


def clear() -> int:
    """Clear all cached entries. Returns number of entries cleared."""
    with _lock:
        with shelve.open(str(CACHE_FILE)) as db:
            count = len(db)
            db.clear()
            return count


def stats() -> dict:
    """Return cache statistics."""
    with _lock:
        with shelve.open(str(CACHE_FILE)) as db:
            total = len(db)
            now = time.time()
            valid = sum(1 for v in db.values() if now - v["t"] <= TTL)
            return {"total": total, "valid": valid, "expired": total - valid}
