"""End to end over real HTTP (stdlib server on 127.0.0.1) with HttpFetcher."""

from __future__ import annotations

import http.server
import threading

import pytest

from aics_cli.commands import Env
from aics_cli.errors import FetchError
from aics_cli.net import HttpFetcher, check_url

from conftest import FakeDNS, Log, make_policy


class _Handler(http.server.BaseHTTPRequestHandler):
    files: dict[str, bytes] = {}

    def do_GET(self):  # noqa: N802
        body = self.files.get(self.path)
        if self.path == "/redirect-to-http":
            self.send_response(302)
            self.send_header("Location", "http://example.com/checkpoint")
            self.end_headers()
            return
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.fixture
def server():
    files: dict[str, bytes] = {}
    handler = type("H", (_Handler,), {"files": files})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", files
    srv.shutdown()
    srv.server_close()


def test_verify_checkpoint_and_consistency_over_http(server, tmp_path):
    base, files = server
    log = Log(300)
    home = tmp_path / "home"
    pol = make_policy(home, log)
    pol.checkpoint_url = f"{base}/checkpoint"
    pol.tiles_url = f"{base}/"
    from aics_cli.policy import save

    save(pol, home, force=True)

    def publish(size):
        files.clear()
        files["/checkpoint"] = log.note(size).encode()
        for path, data in log.tiles(size).items():
            files["/" + path] = data

    from aics_cli.cli import run
    import io
    import json

    env = Env(fetcher=HttpFetcher(timeout=5), resolve_txt=FakeDNS(), home=home)
    publish(9)
    buf = io.StringIO()
    assert run(["verify", "checkpoint", "--json"], env=env, out=buf) == 0, buf.getvalue()
    publish(300)
    buf = io.StringIO()
    code = run(["verify", "consistency", "--json"], env=env, out=buf)
    out = json.loads(buf.getvalue())
    assert code == 0, out
    assert out["checked"][0]["status"] == "consistent"


def test_url_policy():
    assert check_url("https://api.example/checkpoint")
    assert check_url("http://127.0.0.1:8080/x")
    assert check_url("http://localhost/x")
    for bad in ("http://example.com/x", "ftp://example.com/x", "file:///etc/passwd", "https:///nohost"):
        with pytest.raises(FetchError):
            check_url(bad)


def test_redirects_are_not_followed(server):
    base, files = server
    resp = HttpFetcher(timeout=5).get(f"{base}/redirect-to-http")
    assert resp.status == 302


def test_size_cap(server):
    base, files = server
    files["/big"] = b"x" * 5000
    with pytest.raises(FetchError, match="exceeds"):
        HttpFetcher(timeout=5).get(f"{base}/big", max_bytes=1000)
    assert HttpFetcher(timeout=5).get(f"{base}/missing").status == 404


def test_unreachable_host_raises_fetch_error():
    with pytest.raises(FetchError):
        HttpFetcher(timeout=2).get("http://127.0.0.1:9/nothing")
