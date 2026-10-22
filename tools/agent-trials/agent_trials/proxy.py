"""A loopback credential-injecting proxy, run by the runner outside every sandbox.

The Claude-based agents' CLI gets ``ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/r/<route>`` and a
per-run dummy token.  The proxy accepts a request only with that dummy token, sends it on to the
one upstream fixed for the route (z.ai, or api.anthropic.com for the OAuth-backed sonnet route)
and puts the real credential in its place.  So neither the agent's CLI process nor anything it
starts holds a secret: reading the CLI's environment (KERN_PROCARGS2) or its memory yields only
the dummy, which works only through this proxy, only for that model API, and only while the
run lasts.

Nothing is logged: no path, header or body.
"""

from __future__ import annotations

import hmac
import http.client
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

#: Hop-by-hop headers and the ones the proxy sets itself.
_DROP_REQUEST = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
                 "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
                 "authorization", "x-api-key"}
_DROP_RESPONSE = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
                  "trailers", "transfer-encoding", "upgrade", "content-length"}
MAX_BODY = 32 * 1024 * 1024


@dataclass
class Route:
    upstream: str  # https://host[/base/path]
    #: Headers that replace the client's credential (e.g. {"authorization": "Bearer <real>"}).
    inject: dict[str, str]
    #: Values appended (comma-separated) to a header the client sent, e.g. anthropic-beta for OAuth.
    append: dict[str, str] = field(default_factory=dict)
    dummy: str = field(default_factory=lambda: "agent-trials-" + secrets.token_urlsafe(24))
    route_id: str = field(default_factory=lambda: secrets.token_hex(8))

    def __post_init__(self):
        parts = urlsplit(self.upstream)
        if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
            raise ValueError("a proxy upstream must be https://host[/path]")
        self.host = parts.hostname
        self.port = parts.port or 443
        self.base_path = parts.path.rstrip("/")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "_Server"

    def log_message(self, format, *args):  # noqa: A002 - never log a request
        return

    def _refuse(self, code: int, text: str) -> None:
        body = (text + "\n").encode()
        self.send_response(code)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _route(self) -> tuple[Route, str] | None:
        if not self.path.startswith("/r/"):
            return None
        route_id, _, rest = self.path[3:].partition("/")
        route = self.server.routes.get(route_id)
        if route is None:
            return None
        return route, "/" + rest

    def _authorised(self, route: Route) -> bool:
        presented = self.headers.get("x-api-key") or ""
        auth = self.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            presented = presented or auth[7:].strip()
        return bool(presented) and hmac.compare_digest(presented.encode(), route.dummy.encode())

    def _body(self) -> bytes | None:
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            chunks = []
            total = 0
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    break
                total += size
                if total > MAX_BODY:
                    return None
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)
        length = int(self.headers.get("content-length") or 0)
        if length > MAX_BODY:
            return None
        return self.rfile.read(length) if length else b""

    def _forward(self) -> None:
        found = self._route()
        if found is None:
            return self._refuse(404, "no such route")
        route, rest = found
        if not self._authorised(route):
            return self._refuse(401, "wrong token")
        body = self._body()
        if body is None:
            return self._refuse(413, "body too large")
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _DROP_REQUEST}
        for name, value in route.append.items():
            current = next((v for k, v in headers.items() if k.lower() == name), "")
            headers = {k: v for k, v in headers.items() if k.lower() != name}
            headers[name] = ",".join(x for x in (current, value) if x)
        headers.update(route.inject)
        headers["host"] = route.host if route.port == 443 else f"{route.host}:{route.port}"
        if body or self.command in ("POST", "PUT", "PATCH"):
            headers["content-length"] = str(len(body))
        upstream = http.client.HTTPSConnection(route.host, route.port, timeout=self.server.timeout_s)
        started = False
        try:
            upstream.request(self.command, route.base_path + rest, body=body or None, headers=headers)
            response = upstream.getresponse()
            started = True
            self.send_response(response.status, response.reason)
            length = response.getheader("content-length")
            for name, value in response.getheaders():
                if name.lower() not in _DROP_RESPONSE:
                    self.send_header(name, value)
            if length is not None:
                self.send_header("content-length", length)
            self.send_header("connection", "close")
            self.end_headers()
            self.close_connection = True
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (OSError, http.client.HTTPException):
            if not started:
                try:
                    self._refuse(502, "upstream unreachable")
                except OSError:
                    pass
            self.close_connection = True
        finally:
            upstream.close()

    do_GET = do_POST = _forward

    def do_PUT(self):  # noqa: N802
        self._refuse(405, "method not allowed")

    do_DELETE = do_PATCH = do_PUT


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, timeout_s: float):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.routes: dict[str, Route] = {}
        self.timeout_s = timeout_s


class CredentialProxy:
    """Start with :meth:`start`, add routes with :meth:`route`, stop with :meth:`stop`."""

    def __init__(self, timeout_s: float = 900.0):
        self._server = _Server(timeout_s)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def start(self) -> "CredentialProxy":
        if self._thread is None:
            self._thread = threading.Thread(target=self._server.serve_forever, name="agent-trials-proxy", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._server.server_close()

    def route(self, upstream: str, inject: dict[str, str], append: dict[str, str] | None = None) -> tuple[str, str]:
        """A new route to ``upstream``: returns (base URL for the CLI, dummy token for the CLI)."""
        route = Route(upstream, {k.lower(): v for k, v in inject.items()},
                      {k.lower(): v for k, v in (append or {}).items()})
        with self._lock:
            self._server.routes[route.route_id] = route
        return f"http://127.0.0.1:{self.port}/r/{route.route_id}", route.dummy

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


class PlaceholderProxy:
    """For --dry-run and tests: hands out routes without listening anywhere, and records them."""

    def __init__(self):
        self.routes: list[tuple[str, dict[str, str], dict[str, str]]] = []

    def route(self, upstream: str, inject: dict[str, str], append: dict[str, str] | None = None) -> tuple[str, str]:
        self.routes.append((upstream, dict(inject), dict(append or {})))
        n = len(self.routes)
        return f"http://127.0.0.1:<proxy-port>/r/<route-{n}>", f"agent-trials-dummy-{n}"
