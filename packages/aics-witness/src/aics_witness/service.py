"""The witness: c2sp.org/tlog-witness (v1.1.0) over HTTP, standard library only.

``POST <prefix>/add-checkpoint`` follows the specification's checks in
order:

* malformed body or checkpoint ............................ 400 Bad Request
* checkpoint origin not configured ........................ 404 Not Found
* extension lines in a checkpoint of a log configured
  without them (AICS-1 §6.2 checkpoints have none) ........ 400 Bad Request
* no signature from a trusted log key, a trusted key's
  signature fails to verify, or two lines from the same
  trusted key (signature lines from unknown keys, repeated
  or not, are ignored) .................................... 403 Forbidden
* old size larger than the checkpoint size ................ 400 Bad Request
* old size differs from the size of the latest checkpoint
  this witness cosigned for the origin (0 if none, or the
  configured initial pin) ................................. 409 Conflict,
  body ``<latest size>\\n``, ``Content-Type: text/x.tlog.size``; a
  log-signed checkpoint of the latest size with another root is kept as
  evidence even here (direct proof of equivocation)
* size 0 without the empty-tree root, a proof sent with old
  size 0, an equal size with a different root, or a
  consistency proof that does not verify .................. 422 Unprocessable
  Entity (the request is kept as evidence, never cosigned)
* the clock reads earlier than this witness's latest cosignature for the
  log, or the database cannot be written .................. 503 Service
  Unavailable (``Retry-After`` when the clock is at most 5 s behind)
* otherwise the new checkpoint is persisted (atomically with the old-size
  check) and the answer is ``200`` with one cosignature/v1 line
  ``— <witness name> base64(key ID || timestamp || Ed25519 signature)``,
  timestamped with the current time.  A replay of the stored checkpoint
  within the same second gets the stored cosignature back, without a
  write.

``GET <prefix>/<sha256(origin) hex>/checkpoint`` serves the latest cosigned
checkpoint with the verified log signature(s) and the witness cosignature
(the specification's monitoring endpoint), read through a read-only
database connection so only committed state is ever served.  ``GET
/healthz`` answers ``ok``, or 503 once the database failed.

Slow clients cannot hold connections: a request (request line, headers and
body together) must arrive within ``request_timeout`` seconds of its first
byte, and an idle keep-alive connection is closed after ``idle_timeout``
seconds, or at once when every connection slot is taken.

No client address or user agent is logged (docs/DESIGN.md §2, §8).
"""

from __future__ import annotations

import io
import logging
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import (
    EMPTY_HASH,
    Checkpoint,
    Note,
    SignatureLine,
    VKey,
    cosignature_vkey,
    format_vkey,
    parse_checkpoint,
    parse_note,
    sign_cosignature,
    verify_consistency,
    verify_cosignature,
    verify_note,
)

from ._version import __version__
from .config import TYPE_COSIGNATURE, TYPE_ED25519, LogConfig, normalize_prefix
from .protocol import (
    MAX_TREE_SIZE,
    SIZE_CONTENT_TYPE,
    AddCheckpointRequest,
    ProtocolError,
    format_signature_line,
    format_size_body,
    parse_add_checkpoint_request,
    validate_name,
)
from .store import LogState, StoreError, WitnessStore

__all__ = [
    "CLOCK_RETRY_SECONDS",
    "DEFAULT_IDLE_TIMEOUT",
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_REQUEST_TIMEOUT",
    "Witness",
    "WitnessError",
    "WitnessHTTPServer",
    "make_server",
]

log = logging.getLogger("aics_witness")

DEFAULT_MAX_BODY_BYTES = 256 * 1024
DEFAULT_MAX_CONNECTIONS = 128
DEFAULT_REQUEST_TIMEOUT = 10.0  # request line + headers + body, from the first byte
DEFAULT_IDLE_TIMEOUT = 5.0  # keep-alive wait for the next request
DEFAULT_WRITE_TIMEOUT = 10.0
# A clock up to this many seconds behind the latest cosignature of a log
# gets "503, Retry-After"; further behind, the witness refuses until an
# operator acts (the clock is wrong, or was wrong when it last cosigned).
CLOCK_RETRY_SECONDS = 5
TEXT_PLAIN = "text/plain; charset=utf-8"
_MAX_CHUNK_LINE = 4096
_MAX_TRAILER_LINES = 32


class WitnessError(Exception):
    """A refused add-checkpoint request, carrying its HTTP status."""

    def __init__(
        self,
        status: int,
        message: str,
        *,
        body: bytes | None = None,
        content_type: str = TEXT_PLAIN,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.body = body if body is not None else (message + "\n").encode("utf-8")
        self.content_type = content_type
        self.headers = dict(headers or {})


class _Inconsistent(Exception):
    def __init__(self, reason: str, state: LogState | None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.state = state


class Witness:
    """Protocol logic, independent of HTTP: verify, check, persist, cosign."""

    def __init__(
        self,
        name: str,
        private_key: Ed25519PrivateKey,
        store: WitnessStore,
        logs: Iterable[LogConfig] = (),
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        validate_name(name, "witness name")
        self.name = name
        self._key = private_key
        self._public_key = private_key.public_key().public_bytes_raw()
        self.vkey: VKey = cosignature_vkey(name, private_key.public_key())
        self.store = store
        self._clock = clock
        self._logs: dict[str, LogConfig] = {}
        self.set_logs(logs)
        self._warn_future_timestamps()

    @property
    def vkey_text(self) -> str:
        """The witness verifier key: ``<name>+<key ID>+base64(0x04 || key)``."""
        return format_vkey(self.vkey)

    @property
    def logs(self) -> Mapping[str, LogConfig]:
        return dict(self._logs)

    def set_logs(self, logs: Iterable[LogConfig]) -> None:
        """Replace the configured logs (used on SIGHUP).  State for a log
        removed from the configuration stays in the store, so adding it back
        later cannot roll it back.  Raises ValueError (keeping the previous
        list) for a log configured twice or one that lists this witness's own
        public key as a log key: the witness would then take its own earlier
        cosignatures as log signatures."""
        new: dict[str, LogConfig] = {}
        for entry in logs:
            if entry.origin in new:
                raise ValueError(f"log origin {entry.origin!r} configured twice")
            for key in entry.vkeys:
                if key.public_key == self._public_key:
                    raise ValueError(
                        f"log {entry.origin!r} lists this witness's own public key "
                        f"({key.name}) as a log key"
                    )
            new[entry.origin] = entry
        self._logs = new  # a single reference swap; readers see old or new

    def _warn_future_timestamps(self) -> None:
        now = int(self._clock())
        for state in self.store.all_logs():
            if state.timestamp > now + CLOCK_RETRY_SECONDS:
                log.warning(
                    "the latest cosignature for %s is dated %d s after the current time: "
                    "the clock is behind, or was ahead when it cosigned. The witness "
                    "refuses to cosign that log until the clock passes %d; after fixing "
                    "the clock, 'aics-witness clear-timestamp --origin ...' lifts this",
                    state.origin, state.timestamp - now, state.timestamp,
                )

    # -- add-checkpoint ---------------------------------------------------

    def add_checkpoint(self, body: bytes) -> bytes:
        """Handle an add-checkpoint request body.  Returns the 200 response
        body (cosignature lines) or raises WitnessError (StoreError when
        the database cannot be used)."""
        try:
            req = parse_add_checkpoint_request(body)
        except ProtocolError as e:
            raise WitnessError(400, f"bad request: {e}") from None
        try:
            note = parse_note(req.checkpoint)
            cp = parse_checkpoint(note.text)
        except ValueError as e:
            raise WitnessError(400, f"bad request: malformed checkpoint: {e}") from None

        log_config = self._logs.get(cp.origin)
        if log_config is None:
            raise WitnessError(404, "unknown log origin")
        if cp.extension_lines and not log_config.extension_lines:
            raise WitnessError(
                400, "bad request: checkpoints of this log carry no extension lines"
            )
        trusted = _verify_log_signatures(note, cp, log_config.vkeys)

        if cp.size > MAX_TREE_SIZE:
            raise WitnessError(400, "bad request: tree size too large")
        if req.old_size > cp.size:
            raise WitnessError(400, "bad request: old size is larger than the checkpoint size")

        equivocation: LogState | None = None
        coalesced = False
        try:
            with self.store.transaction() as tx:
                state = tx.get(cp.origin)
                known = state if state is not None else _initial_state(log_config)
                known_size = 0 if known is None else known.size
                if req.old_size != known_size:
                    if known is not None and cp.size == known.size and cp.root != known.root:
                        # Two log-signed checkpoints of one size with different
                        # roots: proof of equivocation, whatever old size came with it.
                        equivocation = known
                    raise WitnessError(
                        409,
                        f"old size {req.old_size} does not match the latest cosigned size {known_size}",
                        body=format_size_body(known_size),
                        content_type=SIZE_CONTENT_TYPE,
                    )
                _check_consistency(req, cp, known)
                now = int(self._clock())
                last = 0 if state is None else state.timestamp
                if now < last:
                    raise self._clock_behind(cp.origin, last - now)
                cosignature = self._stored_cosignature(state, note, now)
                if cosignature is not None:
                    coalesced = True
                else:
                    _, cosignature = sign_cosignature(
                        self._key,
                        self.name,
                        now,
                        cp.origin,
                        cp.size,
                        cp.root,
                        cp.extension_lines,
                    )
                    stored = Note(text=note.text, signatures=trusted + (cosignature,))
                    tx.put(
                        origin=cp.origin,
                        size=cp.size,
                        root=cp.root,
                        note=stored.serialise(),
                        timestamp=now,
                        updated_at=now,
                    )
        except _Inconsistent as e:
            self._keep_evidence(cp.origin, e, req, body)
            raise WitnessError(422, e.reason) from None
        except WitnessError:
            if equivocation is not None:
                self._keep_evidence(
                    cp.origin,
                    _Inconsistent("same size, different root (old size mismatch)", equivocation),
                    req,
                    body,
                )
            raise

        if coalesced:
            log.debug("re-sent the cosignature of %s at size %d (time %d)", cp.origin, cp.size, now)
        else:
            log.info("cosigned %s: size %d -> %d (time %d)", cp.origin, known_size, cp.size, now)
        return format_signature_line(cosignature).encode("utf-8")

    def _clock_behind(self, origin: str, behind: int) -> WitnessError:
        """Never sign a time the clock does not show: a small backward step
        is retried, a large one waits for the operator."""
        if behind <= CLOCK_RETRY_SECONDS:
            return WitnessError(
                503,
                f"the witness clock is {behind} s behind its latest cosignature for this log; retry",
                headers={"Retry-After": str(behind)},
            )
        log.error(
            "clock behind last cosignature by %d s for %s; refusing to cosign it until the "
            "clock is fixed, or 'aics-witness clear-timestamp' if it ran ahead earlier",
            behind, origin,
        )
        return WitnessError(503, "the witness clock is behind its latest cosignature for this log")

    def _stored_cosignature(
        self, state: LogState | None, note: Note, now: int
    ) -> SignatureLine | None:
        """The stored cosignature if this very checkpoint text was cosigned
        in this same second by the current key (replays then cost no write)."""
        if state is None or state.timestamp != now:
            return None
        try:
            stored = parse_note(state.note)
        except ValueError:
            return None
        if stored.text != note.text:
            return None
        for sig in stored.signatures:
            if (
                sig.name == self.name
                and sig.key_id == self.vkey.key_id
                and len(sig.signature) == 72
                and int.from_bytes(sig.signature[:8], "big") == now
            ):
                return sig
        return None

    def _keep_evidence(
        self, origin: str, err: _Inconsistent, req: AddCheckpointRequest, body: bytes
    ) -> None:
        state = err.state
        log.warning(
            "refused checkpoint signed by log %s: %s (old size %d, latest cosigned %d)",
            origin, err.reason, req.old_size, 0 if state is None else state.size,
        )
        try:
            kept = self.store.record_evidence(
                origin=origin,
                reason=err.reason,
                old_size=req.old_size,
                known_size=0 if state is None else state.size,
                known_root=None if state is None else state.root,
                request=body,
                received_at=int(self._clock()),
            )
        except Exception:  # evidence is best effort; the refusal stands regardless
            log.exception("could not record evidence for %s", origin)
            return
        if not kept:
            log.warning("evidence limit reached for %s; request not kept", origin)

    # -- monitoring -------------------------------------------------------

    def latest_checkpoint(self, origin_hash_hex: str) -> bytes | None:
        """The latest committed, cosigned checkpoint note for a log, by
        origin hash."""
        state = self.store.get_by_origin_hash(origin_hash_hex)
        return None if state is None else state.note.encode("utf-8")


def _initial_state(log_config: LogConfig) -> LogState | None:
    """The configured starting point of a log the witness never cosigned."""
    if log_config.initial is None:
        return None
    size, root = log_config.initial
    return LogState(origin=log_config.origin, size=size, root=root, note="", timestamp=0, updated_at=0)


def _verify_log_signatures(
    note: Note, cp: Checkpoint, vkeys: tuple[VKey, ...]
) -> tuple[SignatureLine, ...]:
    """Signed-note rules: ignore unknown keys (repeated lines too); a known
    key whose signature fails, or that signed twice, rejects the note; at
    least one known key must verify."""
    trusted: list[SignatureLine] = []
    seen: set[tuple[str, bytes]] = set()
    for sig in note.signatures:
        for key in vkeys:
            if sig.name != key.name or sig.key_id != key.key_id:
                continue
            if (key.name, key.key_id) in seen:
                # c2sp.org/tlog-checkpoint: MUST NOT have two lines with the
                # same key name and key ID; for a trusted key that is a
                # malformed note.
                raise WitnessError(403, f"two signature lines from trusted key {key.name}")
            seen.add((key.name, key.key_id))
            if key.key_type == TYPE_ED25519:
                ok = verify_note(Note(text=note.text, signatures=(sig,)), [key])
            elif key.key_type == TYPE_COSIGNATURE:
                ok = verify_cosignature(
                    sig.signature,
                    key.name,
                    key.public_key,
                    cp.origin,
                    cp.size,
                    cp.root,
                    cp.extension_lines,
                )
            else:  # excluded by LogConfig; kept as a fail-closed default
                ok = False
            if not ok:
                raise WitnessError(403, f"signature from trusted key {key.name} does not verify")
            trusted.append(sig)
    if not trusted:
        raise WitnessError(403, "no signature from a trusted key for this log")
    return tuple(trusted)


def _check_consistency(
    req: AddCheckpointRequest, cp: Checkpoint, state: LogState | None
) -> None:
    """Called with req.old_size equal to the latest cosigned size."""
    if cp.size == 0 and cp.root != EMPTY_HASH:
        raise _Inconsistent("a checkpoint of size 0 must carry the empty-tree root hash", state)
    if req.old_size == 0:
        if req.proof:
            raise _Inconsistent("the consistency proof must be empty when the old size is 0", state)
        return
    assert state is not None  # old_size == state.size > 0
    if req.old_size == cp.size:
        if cp.root != state.root:
            raise _Inconsistent(
                "same tree size as the latest cosigned checkpoint but a different root hash",
                state,
            )
        if req.proof:
            raise _Inconsistent("the consistency proof must be empty for equal sizes", state)
        return
    if not verify_consistency(req.old_size, cp.size, state.root, cp.root, list(req.proof)):
        raise _Inconsistent(
            f"consistency proof from size {req.old_size} to {cp.size} does not verify", state
        )


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class _DeadlineReader(io.RawIOBase):
    """The request socket, read under the handler's current deadline: every
    recv gets only the time left (keep-alive idle time before a request,
    then one deadline for the whole request), so trickling bytes cannot
    extend a request."""

    def __init__(self, sock: socket.socket, handler: _Handler) -> None:
        self._sock = sock
        self._handler = handler

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def,override]
        self._sock.settimeout(self._handler._recv_timeout())
        n = self._sock.recv_into(buffer)
        if n:
            self._handler._request_started()
        return n


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, as the specification recommends
    server_version = f"aics-witness/{__version__}"
    sys_version = ""
    timeout = None  # socket timeouts are set per read and per response
    server: WitnessHTTPServer

    def version_string(self) -> str:
        return self.server_version

    # No client addresses or user agents in any log line.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        log.debug("http: " + format, *args)

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        log.debug("http: %s %s -> %s", self.command, self._path(), code)

    def _path(self) -> str:
        return urlsplit(self.path).path

    # -- connection lifecycle and deadlines ---------------------------------

    def setup(self) -> None:
        self._phase = "idle"
        self._deadline = time.monotonic() + self.server.idle_timeout
        super().setup()
        self.rfile.close()  # replaced by a reader that enforces the deadlines
        self.rfile = io.BufferedReader(_DeadlineReader(self.connection, self))
        self.server._track(self)

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self.server._untrack(self)

    def is_idle(self) -> bool:
        """Waiting for the next request on a connection, nothing received."""
        return self._phase == "idle"

    def _recv_timeout(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            what = "keep-alive idle time" if self._phase == "idle" else "request deadline"
            raise TimeoutError(f"{what} exceeded")
        return max(0.1, remaining)

    def _request_started(self) -> None:
        if self._phase == "idle":
            self._phase = "request"
            self._deadline = time.monotonic() + self.server.request_timeout

    def handle_one_request(self) -> None:
        # As in http.server, with a keep-alive idle deadline before the
        # request line and one deadline for the whole request after it.
        self._phase = "idle"
        self._deadline = time.monotonic() + self.server.idle_timeout
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if self.raw_requestline:
                self._request_started()  # it may have come from the buffer
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return  # an error response has been sent
            method = getattr(self, "do_" + self.command, None)
            if method is None:
                self.send_error(501, f"Unsupported method ({self.command!r})")
                return
            method()
            self.wfile.flush()
        except TimeoutError as e:
            log.debug("http: connection closed: %s", e)
            self.close_connection = True

    def send_response(self, code: int, message: str | None = None) -> None:
        self._phase = "response"
        self.connection.settimeout(self.server.write_timeout)
        super().send_response(code, message)

    # -- methods ------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        path = self._path()
        if path == self.server.add_checkpoint_path:
            self._add_checkpoint()
        elif path == "/healthz" or self.server.match_monitor_path(path):
            self._reply(405, b"method not allowed\n", headers={"Allow": "GET"}, close=True)
        else:
            self._reply(404, b"not found\n", close=True)

    def do_GET(self) -> None:  # noqa: N802
        # A GET body is never read; drop the connection after answering so
        # unread bytes cannot be taken for the next request.
        close = self.headers.get("Transfer-Encoding") is not None or (
            self.headers.get("Content-Length", "0").strip() not in ("", "0")
        )
        path = self._path()
        if path == "/healthz":
            if self.server.witness.store.healthy():
                self._reply(200, b"ok\n", close=close)
            else:
                self._reply(503, b"witness database failed\n", close=close)
            return
        if path == self.server.add_checkpoint_path:
            self._reply(405, b"method not allowed\n", headers={"Allow": "POST"}, close=close)
            return
        origin_hash = self.server.match_monitor_path(path)
        if origin_hash is None:
            self._reply(404, b"not found\n", close=close)
            return
        try:
            note = self.server.witness.latest_checkpoint(origin_hash)
        except StoreError as e:
            log.error("monitoring read failed: %s", e)
            self._reply(503, b"witness storage unavailable\n", close=close)
            return
        if note is None:
            self._reply(404, b"no checkpoint cosigned for this log\n", close=close)
        else:
            self._reply(200, note, close=close)

    def _add_checkpoint(self) -> None:
        body = self._read_body()
        if body is None:
            return
        try:
            response = self.server.witness.add_checkpoint(body)
        except WitnessError as e:
            if e.status >= 500:
                log.warning("add-checkpoint unavailable (%d): %s", e.status, e.message)
            else:
                log.info("add-checkpoint refused (%d): %s", e.status, e.message)
            self._reply(e.status, e.body, content_type=e.content_type, headers=e.headers)
            return
        except StoreError as e:
            log.error("add-checkpoint: witness database unavailable: %s", e)
            self._reply(503, b"witness storage unavailable\n")
            return
        except Exception:
            log.exception("add-checkpoint failed")
            self._reply(500, b"internal error\n")
            return
        self._reply(200, response)

    # -- request bodies -----------------------------------------------------

    def _read_body(self) -> bytes | None:
        """The request body (Content-Length or chunked, at most
        max_body_bytes), or None once an error reply was sent or the
        connection is to be dropped."""
        codings = self.headers.get_all("Transfer-Encoding") or []
        lengths = self.headers.get_all("Content-Length") or []
        if codings:
            if lengths:
                self._reply(400, b"both Content-Length and Transfer-Encoding\n", close=True)
                return None
            tokens = [t.strip().lower() for v in codings for t in v.split(",") if t.strip()]
            if tokens != ["chunked"]:
                self._reply(501, b"only the chunked transfer coding is supported\n", close=True)
                return None
            return self._read_chunked()
        if not lengths:
            self._reply(411, b"Content-Length required\n", close=True)
            return None
        if len(lengths) != 1:
            self._reply(400, b"bad Content-Length\n", close=True)
            return None
        length_text = lengths[0].strip()
        if not length_text.isascii() or not length_text.isdigit():
            self._reply(400, b"bad Content-Length\n", close=True)
            return None
        if len(length_text) > 12:
            self._reply(413, b"request body too large\n", close=True)
            return None
        length = int(length_text)
        if length > self.server.max_body_bytes:
            self._reply(413, b"request body too large\n", close=True)
            return None
        body = self.rfile.read(length)
        if len(body) != length:
            self.close_connection = True
            return None
        return body

    def _read_chunked(self) -> bytes | None:
        """A chunked body (RFC 9112 §7.1), bounded by max_body_bytes; chunk
        extensions and trailer fields are read and ignored."""
        parts: list[bytes] = []
        total = 0
        while True:
            line = self.rfile.readline(_MAX_CHUNK_LINE + 1)
            if not line.endswith(b"\n"):
                if len(line) > _MAX_CHUNK_LINE:
                    self._reply(400, b"malformed chunked body\n", close=True)
                else:
                    self.close_connection = True  # the client went away
                return None
            size_text = line.split(b";", 1)[0].strip()
            if (
                not size_text
                or len(size_text) > 16
                or any(c not in b"0123456789abcdefABCDEF" for c in size_text)
            ):
                self._reply(400, b"malformed chunked body\n", close=True)
                return None
            size = int(size_text, 16)
            if size == 0:
                break
            if total + size > self.server.max_body_bytes:
                self._reply(413, b"request body too large\n", close=True)
                return None
            data = self.rfile.read(size)
            if len(data) != size:
                self.close_connection = True
                return None
            parts.append(data)
            total += size
            if self.rfile.readline(3) not in (b"\r\n", b"\n"):
                self._reply(400, b"malformed chunked body\n", close=True)
                return None
        for _ in range(_MAX_TRAILER_LINES):
            line = self.rfile.readline(_MAX_CHUNK_LINE + 1)
            if line in (b"\r\n", b"\n"):
                return b"".join(parts)
            if not line.endswith(b"\n"):
                if len(line) > _MAX_CHUNK_LINE:
                    self._reply(400, b"malformed chunked body\n", close=True)
                else:
                    self.close_connection = True
                return None
        self._reply(400, b"too many trailer fields\n", close=True)
        return None

    def _reply(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str = TEXT_PLAIN,
        headers: Mapping[str, str] | None = None,
        close: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)


class WitnessHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server bound to a Witness.  Each connection gets a
    thread, at most ``max_connections`` at a time.  When every slot is
    taken, idle keep-alive connections are closed to make room; otherwise
    new connections wait in the listen queue until a slot frees up (each
    busy one is bounded by the request deadline)."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(
        self,
        address: tuple[str, int],
        witness: Witness,
        *,
        prefix: str = "",
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        write_timeout: float = DEFAULT_WRITE_TIMEOUT,
    ) -> None:
        if max_connections < 1:
            raise ValueError("max_connections must be at least 1")
        if min(request_timeout, idle_timeout, write_timeout) <= 0:
            raise ValueError("timeouts must be positive")
        self.witness = witness
        self.prefix = normalize_prefix(prefix)
        self.add_checkpoint_path = self.prefix + "/add-checkpoint"
        self._monitor_re = re.compile(re.escape(self.prefix) + r"/([0-9a-f]{64})/checkpoint")
        self.max_body_bytes = max_body_bytes
        self.request_timeout = request_timeout
        self.idle_timeout = idle_timeout
        self.write_timeout = write_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._handlers: set[_Handler] = set()
        self._handlers_lock = threading.Lock()
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{port}{self.prefix}"

    def handle_error(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        # socketserver's default prints the client address; log without it.
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            log.debug("http: connection error: %s", sys.exc_info()[1])
            return
        log.exception("unhandled error while serving a request")

    def match_monitor_path(self, path: str) -> str | None:
        m = self._monitor_re.fullmatch(path)
        return None if m is None else m.group(1)

    # -- connection slots ---------------------------------------------------

    def _track(self, handler: _Handler) -> None:
        with self._handlers_lock:
            self._handlers.add(handler)

    def _untrack(self, handler: _Handler) -> None:
        with self._handlers_lock:
            self._handlers.discard(handler)

    def _close_idle_connections(self) -> int:
        with self._handlers_lock:
            idle = [h for h in self._handlers if h.is_idle()]
        for handler in idle:
            try:
                handler.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if idle:
            log.debug("http: closed %d idle connection(s) to free a slot", len(idle))
        return len(idle)

    def _acquire_slot(self) -> bool:
        if self._slots.acquire(blocking=False):
            return True
        if self._close_idle_connections():
            return self._slots.acquire(timeout=1.0)
        return self._slots.acquire(timeout=0.25)

    def _handle_request_noblock(self) -> None:
        # socketserver's version, with a connection slot taken before
        # accept(): without one the connection stays in the listen queue.
        if not self._acquire_slot():
            return
        try:
            request, client_address = self.get_request()
        except OSError:
            self._slots.release()
            return
        try:
            self.process_request(request, client_address)  # the thread releases the slot
        except Exception:
            self._slots.release()
            self.handle_error(request, client_address)
            self.shutdown_request(request)
        except BaseException:
            self._slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(
    witness: Witness,
    host: str = "127.0.0.1",
    port: int = 0,
    **kwargs: object,
) -> WitnessHTTPServer:
    """Bind a WitnessHTTPServer (port 0 picks a free port; see ``.url``)."""
    return WitnessHTTPServer((host, port), witness, **kwargs)  # type: ignore[arg-type]
