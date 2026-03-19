import requests
from requests.adapters import HTTPAdapter
from .cache import get as _cget, put as _cput

_session = requests.Session()
adapter = HTTPAdapter(pool_maxsize=20, max_retries=2)
_session.mount("https://", adapter)
_session.mount("http://", adapter)


def get_session() -> requests.Session:
    return _session


def cached_get(url: str, **kwargs) -> requests.Response | None:
    """GET with 24h cache. Always returns a Response-like object or None."""
    cached_text = _cget(url)
    if cached_text is not None:
        # Wrap cached text in a mock Response so callers always get .text / .json()
        mock = requests.models.Response()
        mock.status_code = 200
        mock._content = cached_text.encode("utf-8")
        mock.encoding = "utf-8"
        return mock
    try:
        resp = _session.get(url, **kwargs)
        if resp.status_code == 200:
            _cput(url, resp.text)
        return resp
    except requests.RequestException:
        return None
