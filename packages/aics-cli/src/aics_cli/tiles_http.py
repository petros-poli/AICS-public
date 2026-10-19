"""A tile reader over HTTP implementing ``aics_tlog``'s ``TileReader``
protocol (``read_tile`` / ``read_entry_bundle``), for a C2SP tlog-tiles
prefix: resources at ``<base>/tile/<L>/<N>[.p/<W>]`` and
``<base>/tile/entries/<N>[.p/<W>]``.

404 and 410 mean "not there" (the reader returns None, and aics-tlog falls
back from a partial to the full tile as the spec allows); any other failure,
including a redirect, raises :class:`TileSourceError`.  Tiles are untrusted:
:mod:`aics_cli.consistency` reads them through ``aics_tlog.VerifiedTileReader``,
which authenticates each one up to a signed checkpoint before it is used.
"""

from __future__ import annotations

from aics_tlog.tiles import entry_bundle_path, tile_path

from .errors import FetchError
from .net import Fetcher, join_url

FULL_TILE_BYTES = 256 * 32
BUNDLE_MAX_BYTES = 256 * (2 + 0xFFFF)


class TileSourceError(RuntimeError):
    """A tile could not be fetched for a reason other than "not found"."""


class HttpTileReader:
    def __init__(self, base_url: str, fetcher: Fetcher) -> None:
        self.base_url = base_url
        self.fetcher = fetcher
        self._cache: dict[str, bytes | None] = {}
        self.fetched: list[str] = []
        self.missing: list[str] = []

    def _get(self, path: str, max_bytes: int) -> bytes | None:
        if path in self._cache:
            return self._cache[path]
        url = join_url(self.base_url, path)
        try:
            resp = self.fetcher.get(url, max_bytes=max_bytes)
        except FetchError as exc:
            raise TileSourceError(exc.message) from None
        if resp.status == 200:
            data: bytes | None = resp.body
            self.fetched.append(path)
        elif resp.status in (404, 410):
            data = None
            self.missing.append(path)
        else:
            raise TileSourceError(f"{url}: HTTP {resp.status}")
        self._cache[path] = data
        return data

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
        return self._get(tile_path(level, index, width), FULL_TILE_BYTES)

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
        return self._get(entry_bundle_path(index, width), BUNDLE_MAX_BYTES)
