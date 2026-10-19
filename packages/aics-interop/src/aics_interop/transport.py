"""One fake web serving the same bytes to aics-cli and aics-conformance.

* aics-cli ``Fetcher``: ``get(url, *, max_bytes, accept)`` -> ``aics_cli.net.Response``;
* aics-conformance transport: ``request(method, url, body, headers)`` ->
  ``aics_conformance.client.Response`` and ``tile_reader(url)`` for raw
  (unauthenticated) tiles, which both clients authenticate themselves.
Unknown URLs answer 404.  Every request is recorded.
"""

from __future__ import annotations

import json
from typing import Any


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


class FakeWeb:
    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, bytes]] = {}
        self.requests: list[str] = []
        self.offline = False

    # -- configuration -------------------------------------------------

    def set(self, url: str, body: bytes | str, status: int = 200) -> None:
        self.routes[url] = (status, body.encode("utf-8") if isinstance(body, str) else bytes(body))

    def drop(self, url: str) -> None:
        self.routes.pop(url, None)

    def serve_log(self, prefix: str, note: bytes, tiles: dict[str, bytes] | None) -> None:
        """A C2SP tlog-tiles prefix: ``<prefix>checkpoint`` and ``<prefix>tile/...``."""
        for url in [u for u in self.routes if u.startswith(_join(prefix, "tile/"))]:
            del self.routes[url]
        self.set(_join(prefix, "checkpoint"), note)
        for path, data in (tiles or {}).items():
            self.set(_join(prefix, path), data)

    def serve_consistency(self, template: str, proofs: dict[tuple[int, int], list[bytes]]) -> None:
        import base64

        for (old, new), hashes in proofs.items():
            url = template.replace("{old}", str(old)).replace("{new}", str(new))
            self.set(url, json.dumps({"from": old, "to": new,
                                      "hashes": [base64.b64encode(h).decode() for h in hashes]}))

    # -- shared lookup -------------------------------------------------

    def _lookup(self, url: str) -> tuple[int, bytes]:
        self.requests.append(url)
        if self.offline:
            raise OSError(f"offline: refusing {url}")
        return self.routes.get(url, (404, b"not found"))

    # -- aics-cli Fetcher -------------------------------------------------

    def get(self, url: str, *, max_bytes: int = 1 << 22, accept: str | None = None) -> Any:
        from aics_cli.errors import FetchError
        from aics_cli.net import Response

        try:
            status, body = self._lookup(url)
        except OSError as exc:
            raise FetchError(str(exc)) from None
        return Response(status, body, url, {})

    # -- aics-conformance transport -----------------------------------------

    def request(self, method: str, url: str, body: bytes | None = None, headers: dict | None = None) -> Any:
        from aics_conformance.client import Response

        status, data = self._lookup(url)
        return Response(status, data, {})

    def tile_reader(self, base: str) -> Any:
        web = self

        class Reader:
            def read_tile(self, level: int, index: int, width: int | None):
                from aics_tlog.tiles import tile_path

                status, data = web._lookup(_join(base, tile_path(level, index, width)))
                return data if status == 200 else None

            def read_entry_bundle(self, index: int, width: int | None):
                from aics_tlog.tiles import entry_bundle_path

                status, data = web._lookup(_join(base, entry_bundle_path(index, width)))
                return data if status == 200 else None

        return Reader()
