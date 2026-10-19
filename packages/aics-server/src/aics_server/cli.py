"""CLI entrypoint for running WeSupport-AI (aics-server).

Builds the app (:func:`aics_server.app.create_app`: the log is opened and
checked, the service public keys printed and written to ``AICS_PUBKEYS_OUT``),
then serves it with uvicorn and, in the same process and event loop, the TCP
text gate (:class:`aics_server.gate.TcpGate`).  HTTP ``/t`` and TCP feed the
same :class:`~aics_server.gate.Gate` over the same database object, so the
single writer stays single.

One worker only: a single writer process is a protocol invariant (DESIGN.md
section 4.1), so ``AICS_WORKERS`` other than 1 is refused.  No access log: it
would record client addresses (DESIGN.md sections 2 and 8).

Environment:

* ``AICS_HOST`` / ``AICS_PORT``: the HTTP listener (default ``0.0.0.0:8080``);
* ``AICS_GATE_HOST``: the TCP gate's address (default ``AICS_HOST``);
* ``AICS_GATE_PORT``: plain TCP gate, default ``7701``; ``off`` disables it;
* ``AICS_GATE_TLS_PORT``: TLS gate, default ``7700``, served only when
  ``AICS_GATE_TLS_CERT`` and ``AICS_GATE_TLS_KEY`` (PEM paths) are both set;
  a renewed certificate is picked up within five minutes; ``off`` disables it;
* ``AICS_FORWARDED_ALLOW_IPS``: proxies whose ``X-Forwarded-Proto`` uvicorn
  trusts (default ``*``: the HTTP port is reached only through Caddy).  The
  gate takes secrets on ``POST /t`` only when the request came in over HTTPS,
  and the JSON endpoints that take a shared secret refuse plain HTTP.

Housekeeping (retention, the daily count report of each finished UTC day,
the aggregate counters and the batched nonces of signed reads,
:meth:`aics_server.db.SanctuaryDB.housekeeping`) also runs on a timer here,
every :data:`HOUSEKEEPING_TICK_SECONDS`, so a quiet server still writes its
daily report within the day (AICS-1 section 10.2).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import sys
from typing import Any

import uvicorn

from .app import create_app
from .gate import TcpGate

_OFF = ("", "0", "off", "no", "false", "none")
#: How often the CLI runs the database's housekeeping (it does a pass at most hourly, see HOUSEKEEPING_INTERVAL).
HOUSEKEEPING_TICK_SECONDS = 600.0


def _port(name: str, default: str) -> int | None:
    value = os.environ.get(name, default).strip().lower()
    if value in _OFF:
        return None
    try:
        port = int(value)
    except ValueError:
        raise SystemExit(f"{name}={value!r}: a TCP port number or off") from None
    if not 1 <= port <= 65535:
        raise SystemExit(f"{name}={value!r}: a TCP port number or off")
    return port


def gate_settings(host: str) -> dict[str, Any] | None:
    """The TCP gate's settings from the environment, or ``None`` when both listeners are off."""
    cert = os.environ.get("AICS_GATE_TLS_CERT", "").strip() or None
    key = os.environ.get("AICS_GATE_TLS_KEY", "").strip() or None
    if (cert is None) != (key is None):
        raise SystemExit("set both AICS_GATE_TLS_CERT and AICS_GATE_TLS_KEY (or neither) for the TLS gate on 7700")
    plain_port = _port("AICS_GATE_PORT", "7701")
    tls_port = _port("AICS_GATE_TLS_PORT", "7700") if cert is not None else None
    if plain_port is None and tls_port is None:
        return None
    if plain_port is not None and plain_port == tls_port:
        raise SystemExit("AICS_GATE_PORT and AICS_GATE_TLS_PORT must differ")
    return {
        "host": os.environ.get("AICS_GATE_HOST", host).strip() or host,
        "plain_port": plain_port,
        "tls_port": tls_port,
        "cert_file": cert,
        "key_file": key,
    }


class GateServer(uvicorn.Server):
    """uvicorn's server with the TCP gate started before it and stopped before it shuts down.

    It also runs the database's housekeeping on a timer (``db``), in a worker
    thread so the event loop never waits on the disk.
    """

    def __init__(
        self,
        config: uvicorn.Config,
        tcp_gate: TcpGate | None,
        db: Any = None,
        tick_seconds: float = HOUSEKEEPING_TICK_SECONDS,
    ) -> None:
        super().__init__(config)
        self.tcp_gate = tcp_gate
        self.db = db
        self.tick_seconds = tick_seconds
        self._housekeeper: asyncio.Task[None] | None = None

    async def _housekeeping(self) -> None:
        while True:
            await asyncio.sleep(self.tick_seconds)
            try:
                await asyncio.to_thread(self.db.housekeeping)
            except Exception as exc:  # keep serving; the next tick retries
                print(f"aics-server: housekeeping failed ({type(exc).__name__}); retried later", file=sys.stderr, flush=True)

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        if self.tcp_gate is not None:
            await self.tcp_gate.start()  # a port that cannot be bound stops the start, loudly
        if self.db is not None:
            self._housekeeper = asyncio.create_task(self._housekeeping())
        await super().startup(sockets=sockets)

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        if self._housekeeper is not None:
            self._housekeeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._housekeeper
            self._housekeeper = None
        if self.tcp_gate is not None:
            await self.tcp_gate.close()
        await super().shutdown(sockets=sockets)
        if self.db is not None:
            with contextlib.suppress(Exception):
                self.db.flush_counters()


def main() -> None:
    host = os.environ.get("AICS_HOST", "0.0.0.0")
    port = int(os.environ.get("AICS_PORT", "8080"))
    workers = os.environ.get("AICS_WORKERS", "1").strip() or "1"
    if workers != "1":
        raise SystemExit(
            f"AICS_WORKERS={workers!r}: the server runs exactly one worker, because a single writer "
            "process is a protocol invariant (two would each sign their own checkpoints)."
        )
    settings = gate_settings(host)
    app = create_app()
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=1,
        access_log=False,
        server_header=False,
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("AICS_FORWARDED_ALLOW_IPS", "*"),
    )
    tcp_gate = TcpGate(app.state.gate, **settings) if settings is not None else None
    GateServer(config, tcp_gate, db=getattr(app.state, "db", None)).run()


if __name__ == "__main__":
    main()
