"""HTTP GET with the stdlib only.

* HTTPS is required, except plain HTTP to a loopback host (local testing).
* Redirects are not followed: a 3xx comes back as a status (tlog-tiles
  resources and checkpoints must not redirect, AICS-1 §6.1, §12.2).
* Responses are size-capped.  HTTP error statuses are returned, not raised;
  only transport failures raise :class:`FetchError`.
* Nothing fetched here is trusted: every caller verifies what it gets
  against keys pinned out of band.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

from . import __version__
from .errors import FetchError

DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_BYTES = 4 * 1024 * 1024


@dataclass
class Response:
    status: int
    body: bytes
    url: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()


class Fetcher(Protocol):
    def get(self, url: str, *, max_bytes: int = DEFAULT_MAX_BYTES, accept: str | None = None) -> Response: ...


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> str:
    """Raise FetchError unless ``url`` is https, or http to a loopback host."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise FetchError(f"bad URL {url!r}: {exc}") from None
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and _is_loopback(parts.hostname):
        return url
    raise FetchError(f"refusing {url!r}: only https:// (or http:// to localhost) is allowed")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError, returned to the caller as a 3xx status


class HttpFetcher:
    """urllib-based fetcher with a timeout, a size cap and no redirects."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, user_agent: str | None = None) -> None:
        self.timeout = timeout
        self.user_agent = user_agent or f"aics/{__version__} (+https://wesupport-ai.com/card)"
        self._opener = urllib.request.build_opener(
            _NoRedirects(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def get(self, url: str, *, max_bytes: int = DEFAULT_MAX_BYTES, accept: str | None = None) -> Response:
        check_url(url)
        headers = {"User-Agent": self.user_agent}
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(max_bytes + 1)
                status = resp.status
                final_url = resp.geturl()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(min(max_bytes, 65536))
            except Exception:
                body = b""
            return Response(
                status=exc.code, body=body, url=url, headers={k.lower(): v for k, v in (exc.headers or {}).items()}
            )
        except FetchError:
            raise
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise FetchError(f"cannot fetch {url}: {reason}") from None
        if len(body) > max_bytes:
            raise FetchError(f"response from {url} exceeds {max_bytes} bytes")
        return Response(status=status, body=body, url=final_url, headers=hdrs)


def join_url(base: str, path: str) -> str:
    """``base`` + ``path`` with exactly one slash between them."""
    return base.rstrip("/") + "/" + path.lstrip("/")
