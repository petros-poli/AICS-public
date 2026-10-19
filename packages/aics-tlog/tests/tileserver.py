"""A tiny threaded HTTP server for tile tests (127.0.0.1, random port)."""

from __future__ import annotations

import gzip
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class TileServer:
    """Serves ``files`` (path -> bytes).  ``default`` / ``modes[path]`` pick a
    behaviour: None (serve), "500", "redirect", "corrupt", "gzip", "huge",
    "bomb"."""

    def __init__(self, files: dict[str, bytes] | None = None, default: str | None = None) -> None:
        self.files = dict(files or {})
        self.default = default
        self.modes: dict[str, str] = {}
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"

    def paths_requested(self) -> list[str]:
        return [p for p, _ in self.requests]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler(server):  # noqa: N805 - closure over the TileServer
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_GET(self):  # noqa: N802
                path = self.path.lstrip("/")
                server.requests.append((path, dict(self.headers)))
                mode = server.modes.get(path, server.default)
                if mode == "500":
                    self.send_error(500)
                    return
                if mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", server.url + path)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                data = server.files.get(path)
                if data is None:
                    self.send_error(404)
                    return
                headers = {"Content-Type": "application/octet-stream"}
                if mode == "corrupt":
                    data = bytes([data[0] ^ 1]) + data[1:]
                elif mode == "huge":
                    data = data + b"\x00" * (32 << 20)
                elif mode == "gzip":
                    data = gzip.compress(data)
                    headers["Content-Encoding"] = "gzip"
                elif mode == "bomb":
                    data = gzip.compress(b"\x00" * (64 << 20))
                    headers["Content-Encoding"] = "gzip"
                self.send_response(200)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        return Handler


def dead_url() -> str:
    """A URL on a port nothing listens on (connection refused)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/"
