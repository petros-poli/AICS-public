"""Reading tiles over HTTP(S) from a log and its mirrors (c2sp.org/tlog-tiles).

:class:`HttpTileReader` implements the :class:`~aics_tlog.tiles.TileReader`
protocol over one or more URL prefixes.  Each resource is requested from the
prefixes in order; a prefix that answers 404/410, fails, times out, redirects
or serves a malformed resource is skipped in favour of the next one.

Nothing a mirror serves is trusted: tiles are authenticated against a signed
checkpoint by :class:`~aics_tlog.verified.VerifiedTileReader`, which tells
this reader (``save_*``) which resources proved valid -- only those go to the
on-disk cache -- and which did not (``reject_*``), so the next read of that
resource skips the source that served it.  A bad mirror therefore cannot
poison the cache, and verification routes around it when another mirror is
good.

``file://`` prefixes are read from the local filesystem, so a local copy of
the tiles can be mixed with remote mirrors.

Transport rules from the spec: requests advertise ``gzip, identity``;
redirects are refused (tlog-tiles resources must not redirect); the
checkpoint is fetched with ``Cache-Control: no-cache``; responses are size
capped before and after decompression.
"""

from __future__ import annotations

import http.client
import os
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener, url2pathname

from .tiles import (
    FULL_TILE_BYTES,
    MAX_ENTRY_BYTES,
    TILE_ENTRIES,
    TileUnavailableError,
    entry_bundle_path,
    parse_entry_bundle,
    tile_path,
)

__all__ = [
    "BUNDLE_MAX_BYTES",
    "CHECKPOINT_MAX_BYTES",
    "CheckpointFetch",
    "HttpTileReader",
    "tile_source_url",
]

BUNDLE_MAX_BYTES = TILE_ENTRIES * (2 + MAX_ENTRY_BYTES)  # protocol maximum
CHECKPOINT_MAX_BYTES = 1 << 20


def _version() -> str:
    from . import __version__

    return __version__


class _FetchError(Exception):
    """A transport-level failure for one source (try the next one)."""


class _NoRedirect(HTTPRedirectHandler):
    """tlog-tiles resources must not redirect; treat a redirect as a failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _normalise_base(url: str) -> str:
    u = url.strip()
    parts = urlsplit(u)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https", "file"):
        raise ValueError(f"tile source must be an http(s):// or file:// URL prefix: {url!r}")
    if parts.query or parts.fragment:
        raise ValueError(f"tile source must not carry a query or fragment: {url!r}")
    if scheme != "file" and not parts.netloc:
        raise ValueError(f"tile source has no host: {url!r}")
    return u if u.endswith("/") else u + "/"


def tile_source_url(value: str) -> str:
    """Turn a CLI tile source (URL prefix or local directory) into a URL prefix."""
    v = value.strip()
    scheme = urlsplit(v).scheme.lower()
    if scheme in ("http", "https", "file"):
        return _normalise_base(v)
    path = Path(v).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"tile source is neither a URL nor an existing directory: {value!r}")
    return path.as_uri().rstrip("/") + "/"


def _gunzip(raw: bytes, max_bytes: int) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(raw, max_bytes + 1)
    except zlib.error as e:
        raise _FetchError(f"bad gzip body: {e}") from None
    if len(out) > max_bytes or d.unconsumed_tail:
        raise _FetchError("decompressed response too large")
    if not d.eof or d.unused_data:
        raise _FetchError("truncated or multi-member gzip body")
    return out


@dataclass(frozen=True)
class CheckpointFetch:
    source: str
    data: bytes | None
    error: str | None = None


class HttpTileReader:
    """TileReader over HTTP(S) URL prefixes with mirror fallback and a cache.

    ``base_urls`` are tlog-tiles URL prefixes, tried in order (the log first,
    then its mirrors).  ``cache_dir`` holds authenticated resources: full
    tiles and full entry bundles by default, partial ones too with
    ``cache_partials``.  With ``cache_unverified`` every full resource is
    cached as soon as it is fetched, for callers that do not authenticate
    (a poisoned entry then costs a failed verification until it is rejected).
    ``proxies`` follows :class:`urllib.request.ProxyHandler` (None: use the
    environment; ``{}``: no proxy).
    """

    def __init__(
        self,
        base_urls: list[str] | tuple[str, ...] | str,
        cache_dir: str | Path | None = None,
        *,
        timeout: float = 15.0,
        cache_partials: bool = False,
        cache_unverified: bool = False,
        proxies: dict[str, str] | None = None,
        user_agent: str | None = None,
        max_bundle_bytes: int = BUNDLE_MAX_BYTES,
    ) -> None:
        if isinstance(base_urls, str):
            base_urls = [base_urls]
        bases = tuple(_normalise_base(u) for u in base_urls)
        if not bases:
            raise ValueError("at least one tile source URL is required")
        self.base_urls = bases
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.timeout = timeout
        self.cache_partials = cache_partials
        self.cache_unverified = cache_unverified
        self.user_agent = user_agent or f"aics-tlog/{_version()}"
        self.max_bundle_bytes = max_bundle_bytes
        handlers: list = [_NoRedirect()]
        if proxies is not None:
            handlers.append(ProxyHandler(proxies))
        self._opener = build_opener(*handlers)
        # Per resource path: which source served the last read (0 = cache,
        # i >= 1 = base_urls[i-1]) and the first source still allowed.
        self._served: dict[str, int] = {}
        self._skip: dict[str, int] = {}
        self.stats = {"cache_hits": 0, "requests": 0, "not_found": 0, "errors": 0, "cache_writes": 0}
        self.last_errors: list[str] = []

    # -- TileReader protocol -------------------------------------------------

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
        path = tile_path(level, index, width)
        expected = (width or TILE_ENTRIES) * 32
        return self._read(path, FULL_TILE_BYTES, lambda d: len(d) == expected, width is None)

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
        path = entry_bundle_path(index, width)
        count = width or TILE_ENTRIES

        def plausible(data: bytes) -> bool:
            try:
                return len(parse_entry_bundle(data)) == count
            except ValueError:
                return False

        return self._read(path, self.max_bundle_bytes, plausible, width is None)

    # -- verification feedback (called by VerifiedTileReader) ----------------

    def save_tile(self, level: int, index: int, width: int | None, data: bytes) -> None:
        """Record an authenticated tile in the on-disk cache."""
        if width is None or self.cache_partials:
            self._cache_put(tile_path(level, index, width), data)

    def save_entry_bundle(self, index: int, width: int | None, data: bytes) -> None:
        """Record an authenticated entry bundle in the on-disk cache."""
        if width is None or self.cache_partials:
            self._cache_put(entry_bundle_path(index, width), data)

    def reject_tile(self, level: int, index: int, width: int | None) -> bool:
        """The last data returned for this tile failed authentication: drop it
        (and its cached copy) and use the next source on the next read.
        Returns False when no source is left to try."""
        return self._reject(tile_path(level, index, width))

    def reject_entry_bundle(self, index: int, width: int | None) -> bool:
        return self._reject(entry_bundle_path(index, width))

    # -- checkpoints -------------------------------------------------------------

    def fetch_checkpoints(self) -> list[CheckpointFetch]:
        """GET ``<prefix>/checkpoint`` from every source (never cached)."""
        out: list[CheckpointFetch] = []
        for base in self.base_urls:
            try:
                data = self._fetch(base, "checkpoint", CHECKPOINT_MAX_BYTES, no_cache=True)
            except _FetchError as e:
                out.append(CheckpointFetch(base, None, str(e)))
                continue
            out.append(CheckpointFetch(base, data, None if data is not None else "not found"))
        return out

    def read_checkpoint(self) -> bytes:
        """The checkpoint from the first source that serves one."""
        fetches = self.fetch_checkpoints()
        for f in fetches:
            if f.data is not None:
                return f.data
        raise TileUnavailableError(
            "no source served a checkpoint: " + "; ".join(f"{f.source}: {f.error}" for f in fetches)
        )

    # -- internals ------------------------------------------------------------

    def _read(self, path: str, max_bytes: int, plausible, full: bool) -> bytes | None:
        first = self._skip.get(path, 0)
        if first == 0 and self.cache_dir is not None:
            data = self._cache_get(path, max_bytes)
            if data is not None:
                if plausible(data):
                    self.stats["cache_hits"] += 1
                    self._served[path] = 0
                    return data
                self._cache_delete(path)
        not_found = False
        errors: list[str] = []
        for i, base in enumerate(self.base_urls, start=1):
            if i < first:
                continue
            try:
                data = self._fetch(base, path, max_bytes)
            except _FetchError as e:
                errors.append(f"{base}{path}: {e}")
                continue
            if data is None:
                not_found = True
                continue
            if not plausible(data):
                errors.append(f"{base}{path}: malformed resource")
                continue
            self._served[path] = i
            if full and self.cache_unverified:
                self._cache_put(path, data)
            return data
        self._served.pop(path, None)
        self.stats["errors"] += len(errors)
        self.last_errors = errors
        if not_found or not errors:
            return None
        raise TileUnavailableError(f"{path}: every source failed: " + "; ".join(errors))

    def _reject(self, path: str) -> bool:
        served = self._served.pop(path, None)
        if served is None:
            return False
        if served == 0:
            self._cache_delete(path)
        self._skip[path] = served + 1
        return served < len(self.base_urls)

    def _fetch(self, base: str, path: str, max_bytes: int, *, no_cache: bool = False) -> bytes | None:
        """One source.  Returns None for "not found"; raises _FetchError."""
        url = base + path
        if base.lower().startswith("file:"):
            local = Path(url2pathname(urlsplit(url).path))
            try:
                with open(local, "rb") as fh:
                    data = fh.read(max_bytes + 1)
            except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
                return None
            except OSError as e:
                raise _FetchError(str(e)) from None
            if len(data) > max_bytes:
                raise _FetchError("resource too large")
            return data
        headers = {"User-Agent": self.user_agent, "Accept-Encoding": "gzip, identity"}
        if no_cache:
            headers["Cache-Control"] = "no-cache"
        request = Request(url, headers=headers, method="GET")
        self.stats["requests"] += 1
        try:
            with self._opener.open(request, timeout=self.timeout) as resp:
                status = resp.status
                encoding = (resp.headers.get("Content-Encoding") or "identity").strip().lower()
                limit = max_bytes + max_bytes // 64 + 4096 if encoding == "gzip" else max_bytes
                raw = resp.read(limit + 1)
        except HTTPError as e:
            code = e.code
            e.close()
            if code in (404, 410):
                self.stats["not_found"] += 1
                return None
            if 300 <= code < 400:
                raise _FetchError(f"HTTP {code}: redirects are not allowed for tlog resources") from None
            raise _FetchError(f"HTTP {code}") from None
        except (URLError, OSError, http.client.HTTPException, ValueError) as e:
            raise _FetchError(f"{type(e).__name__}: {e}") from None
        if status != 200:
            raise _FetchError(f"HTTP {status}")
        if len(raw) > limit:
            raise _FetchError("response too large")
        if encoding == "gzip":
            return _gunzip(raw, max_bytes)
        if encoding in ("identity", ""):
            return raw
        raise _FetchError(f"unsupported Content-Encoding {encoding!r}")

    def _cache_file(self, path: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / path

    def _cache_get(self, path: str, max_bytes: int) -> bytes | None:
        f = self._cache_file(path)
        if f is None:
            return None
        try:
            with open(f, "rb") as fh:
                data = fh.read(max_bytes + 1)
        except OSError:
            return None
        return data if len(data) <= max_bytes else None

    def _cache_put(self, path: str, data: bytes) -> None:
        f = self._cache_file(path)
        if f is None:
            return
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=f".{f.name}.", suffix=".tmp", dir=f.parent)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                os.replace(tmp, f)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            self.stats["cache_writes"] += 1
        except OSError:
            pass  # the cache is an optimisation; never fail a read because of it

    def _cache_delete(self, path: str) -> None:
        f = self._cache_file(path)
        if f is None:
            return
        try:
            f.unlink()
        except OSError:
            pass
