"""Client side of c2sp.org/tlog-witness: what a log calls to get cosigned.

::

    from aics_witness.feeder import WitnessClient, merge_cosignatures

    client = WitnessClient("https://witness.example.org", witness_vkey,
                           state_path="witness1.state.json")
    line = client.submit(signed_note, tree.consistency_proof)  # proof(old, new)
    note = merge_cosignatures(signed_note, line)

Old-size handling follows the specification.  The client starts from the
size it last saw this witness cosign for the origin (remembered across
restarts with ``state_path``), else from 0; a ``409 Conflict`` names the
size the witness holds (``text/x.tlog.size``), and the client retries from
that size with a consistency proof built by the proof source.  If the
witness already holds this very checkpoint size (for instance after an
earlier response was lost), the retry needs no proof.  A remembered size
larger than the checkpoint is ignored (the client starts from 0), so one
bad answer cannot block later submissions.

Two answers stop the client: a witness that holds a larger tree than the
checkpoint (WitnessAhead: the checkpoint is stale, or with a single writer
the log rolled back or its key signed elsewhere), and a witness that holds
a smaller tree than one this client saw it cosign (WitnessRolledBack: the
witness lost or rolled back its state).  The second is recorded in the
state file and every later submission for that origin raises it, so the
witness stops counting toward the log's quorum, until an operator calls
``acknowledge_rollback``.

Transport errors and 429/5xx answers are retried with capped exponential
backoff (``Retry-After`` honoured); a keep-alive connection the witness
closed while idle is replaced at once.  Re-sending an add-checkpoint is
safe: a request the witness already applied comes back as a 409 and is
handled as above.  400, 403, 404 and 422 are final (WitnessRejected); 422
means the witness considers the checkpoint inconsistent with what it saw
before.  A 409 that names the very size that was sent, for a checkpoint of
that size, is how tlog-witness v1.0.0 witnesses report a different root at
an equal size (v1.1.0 uses 422); it is final as well.

The returned cosignature line(s) are verified against the checkpoint and
the witness vkey (signed-note rule: lines from other keys are ignored), and
must be fresh: dated at most ``max_age_seconds`` (60) ago and at most
``max_future_seconds`` (30, as in AICS-1 §6.3) ahead of the local clock.
A vkey is required; ``allow_unverified=True`` exists for diagnostics only,
because one unverifiable line from a trusted witness name and key ID makes
clients reject the whole published checkpoint.  The HTTP connection is
kept alive between requests of one client.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import random
import ssl
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aics_tlog import Note, SignatureLine, VKey, format_vkey, parse_checkpoint, parse_note, parse_vkey, verify_cosignature

from ._version import __version__
from .protocol import (
    MAX_PROOF_LINES,
    SIZE_CONTENT_TYPE,
    ProtocolError,
    ed25519_public_key_problem,
    format_add_checkpoint_request,
    format_signature_line,
    parse_signature_lines,
    parse_size_body,
)

__all__ = [
    "BadWitnessResponse",
    "FeederError",
    "ProofFunction",
    "ProofSource",
    "WitnessAhead",
    "WitnessClient",
    "WitnessConflict",
    "WitnessRejected",
    "WitnessRolledBack",
    "WitnessUnavailable",
    "merge_cosignatures",
    "submit_checkpoint",
]

log = logging.getLogger("aics_witness.feeder")

ProofFunction = Callable[[int, int], Sequence[bytes]]
"""``proof(old_size, new_size)`` -> RFC 6962 consistency proof hashes,
e.g. ``aics_tlog.MerkleTree.consistency_proof``."""

ProofSource = ProofFunction | tuple[int, Sequence[bytes]]
"""A proof function, or a fixed ``(old_size, proof)`` pair."""

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RESPONSE_BYTES = 1 << 20
COSIGNATURE_TYPE = 0x04
DEFAULT_MAX_FUTURE_SECONDS = 30  # AICS-1 §6.3: timestamp <= now + 30
DEFAULT_MAX_AGE_SECONDS = 60
STATE_VERSION = 1


class FeederError(Exception):
    """Base class for witness submission failures."""


class WitnessRejected(FeederError):
    """The witness refused the checkpoint (400, 403, 404, 422, ...)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"witness answered {status}: {message}")
        self.status = status
        self.message = message


class WitnessConflict(FeederError):
    """The witness holds a tree size this submission cannot continue from:
    larger than the checkpoint, or one the fixed proof does not start at."""

    def __init__(self, known_size: int, message: str) -> None:
        super().__init__(message)
        self.known_size = known_size


class WitnessAhead(WitnessConflict):
    """The witness names a tree size larger than the checkpoint.  Either the
    checkpoint is stale, or -- with a single writer -- the log rolled back
    or its key signed checkpoints elsewhere (log key compromise)."""


class WitnessRolledBack(FeederError):
    """The witness answered from a smaller tree than one this client saw it
    cosign for the origin: it lost or rolled back its state, and could now
    be led to cosign a fork.  Raised for every submission for the origin
    until ``WitnessClient.acknowledge_rollback(origin)``."""

    def __init__(self, origin: str, previous: int, named: int, message: str | None = None) -> None:
        super().__init__(
            message
            or f"witness rolled back for {origin}: it answered from size {named}, "
            f"but cosigned size {previous} before"
        )
        self.origin = origin
        self.previous = previous
        self.named = named


class WitnessUnavailable(FeederError):
    """No usable answer after the configured attempts."""


class BadWitnessResponse(FeederError):
    """The answer does not follow the protocol, or its cosignature does not
    verify under the expected witness key, or is not fresh."""


def _text(data: bytes, limit: int = 300) -> str:
    return data[:limit].decode("utf-8", "replace").strip()


def _write_json_atomically(path: Path, doc: dict[str, Any]) -> None:
    data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    if os.name == "posix":
        try:
            dfd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)


class WitnessClient:
    """Submits checkpoints to one witness and remembers, per log origin, the
    latest tree size that witness cosigned.  Holds one keep-alive connection;
    use one client per thread.

    ``state_path`` (a JSON file, one per witness) keeps the largest size the
    witness was seen to cosign per origin, and any detected rollback, across
    restarts; a log server should always pass it.
    """

    def __init__(
        self,
        witness_url: str,
        witness_vkey: VKey | str | None = None,
        *,
        allow_unverified: bool = False,
        timeout: float = 10.0,
        max_attempts: int = 4,
        backoff: float = 0.5,
        max_backoff: float = 8.0,
        max_conflicts: int = 3,
        max_future_seconds: int | None = DEFAULT_MAX_FUTURE_SECONDS,
        max_age_seconds: int | None = DEFAULT_MAX_AGE_SECONDS,
        state_path: str | os.PathLike[str] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        parts = urlsplit(witness_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"witness URL must be http(s)://host[:port][/prefix], got {witness_url!r}")
        if parts.query or parts.fragment:
            raise ValueError("witness URL must not have a query or fragment")
        path = parts.path.rstrip("/")
        if not path.endswith("/add-checkpoint"):
            path += "/add-checkpoint"
        self.url = f"{parts.scheme}://{parts.netloc}{path}"
        self._scheme = parts.scheme
        self._host = parts.hostname
        self._port = parts.port
        self._path = path
        if isinstance(witness_vkey, str):
            witness_vkey = parse_vkey(witness_vkey.strip())
        if witness_vkey is None:
            if not allow_unverified:
                raise ValueError(
                    "a witness vkey is required to verify cosignatures "
                    "(allow_unverified=True is for diagnostics only)"
                )
        else:
            if witness_vkey.key_type != COSIGNATURE_TYPE or len(witness_vkey.public_key) != 32:
                raise ValueError("witness vkey must be an Ed25519 cosignature key (type 0x04)")
            problem = ed25519_public_key_problem(witness_vkey.public_key)
            if problem is not None:
                raise ValueError(f"witness vkey: the public key {problem}")
        self.witness_vkey = witness_vkey
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        for name, value in (("max_future_seconds", max_future_seconds), ("max_age_seconds", max_age_seconds)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{name} must be a non-negative integer or None")
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.backoff = backoff
        self.max_backoff = max_backoff
        self.max_conflicts = max_conflicts
        self.max_future_seconds = max_future_seconds
        self.max_age_seconds = max_age_seconds
        self._ssl_context = ssl_context
        self._sleep = sleep
        self._clock = clock
        self._conn: http.client.HTTPConnection | None = None
        self.known_sizes: dict[str, int] = {}
        self.state_path = None if state_path is None else Path(state_path)
        self._logs_state: dict[str, dict[str, Any]] = {}
        self._load_state()

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> WitnessClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- persisted per-origin state ------------------------------------------

    def _vkey_text(self) -> str | None:
        return None if self.witness_vkey is None else format_vkey(self.witness_vkey)

    def _load_state(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            doc = json.loads(self.state_path.read_text("utf-8"))
        except (OSError, ValueError) as e:
            raise ValueError(f"cannot read witness client state {self.state_path}: {e}") from None
        if not isinstance(doc, dict) or doc.get("version") != STATE_VERSION or not isinstance(doc.get("logs"), dict):
            raise ValueError(f"{self.state_path} is not a witness client state file (version {STATE_VERSION})")
        if doc.get("witness_vkey") != self._vkey_text():
            raise ValueError(
                f"{self.state_path} belongs to witness key {doc.get('witness_vkey')}, "
                f"not {self._vkey_text()}"
            )
        for origin, entry in doc["logs"].items():
            if not isinstance(entry, dict):
                raise ValueError(f"{self.state_path}: bad entry for {origin!r}")
            cosigned = entry.get("max_cosigned")
            if cosigned is not None and (isinstance(cosigned, bool) or not isinstance(cosigned, int) or cosigned < 0):
                raise ValueError(f"{self.state_path}: bad max_cosigned for {origin!r}")
            record = entry.get("rolled_back")
            if record is not None and not (
                isinstance(record, dict)
                and all(isinstance(record.get(k), int) for k in ("previous", "named"))
            ):
                raise ValueError(f"{self.state_path}: bad rolled_back record for {origin!r}")
            self._logs_state[origin] = dict(entry)

    def _save_state(self) -> None:
        if self.state_path is None:
            return
        _write_json_atomically(
            self.state_path,
            {"version": STATE_VERSION, "witness_vkey": self._vkey_text(), "witness_url": self.url,
             "logs": self._logs_state},
        )

    def max_cosigned(self, origin: str) -> int | None:
        """The largest size this witness was seen to cosign for ``origin``."""
        value = self._logs_state.get(origin, {}).get("max_cosigned")
        return value if isinstance(value, int) else None

    def rollback(self, origin: str) -> dict[str, int] | None:
        """The recorded, unacknowledged rollback of this witness for
        ``origin`` (``{"previous", "named", "detected_at"}``), if any."""
        record = self._logs_state.get(origin, {}).get("rolled_back")
        return dict(record) if isinstance(record, dict) else None

    def acknowledge_rollback(self, origin: str) -> None:
        """An operator accepts that this witness lost its state for
        ``origin``: forget the recorded rollback and the sizes seen before,
        so the client starts again from whatever the witness holds."""
        self._logs_state.pop(origin, None)
        self.known_sizes.pop(origin, None)
        self._save_state()

    def _save_state_logged(self) -> None:
        try:
            self._save_state()
        except OSError as e:  # the in-memory state still holds until restart
            log.error("cannot write witness client state %s: %s", self.state_path, e)

    def _record_cosigned(self, origin: str, size: int) -> None:
        entry = self._logs_state.setdefault(origin, {})
        previous = entry.get("max_cosigned")
        if not isinstance(previous, int) or size > previous:
            entry["max_cosigned"] = size
            self._save_state_logged()

    def _rolled_back(self, origin: str, previous: int, named: int) -> WitnessRolledBack:
        log.critical(
            "witness %s answered for %s from tree size %d, but this client saw it cosign "
            "size %d: the witness lost or rolled back its state. Its cosignatures for this "
            "log are refused until an operator acknowledges (acknowledge_rollback)",
            self.url, origin, named, previous,
        )
        self._logs_state.setdefault(origin, {})["rolled_back"] = {
            "previous": previous, "named": named, "detected_at": int(self._clock()),
        }
        self._save_state_logged()
        return WitnessRolledBack(origin, previous, named)

    def _check_named_size(self, origin: str, named: int) -> None:
        previous = self.max_cosigned(origin)
        if previous is not None and named < previous:
            raise self._rolled_back(origin, previous, named)

    # -- submission -------------------------------------------------------

    def submit(
        self,
        signed_note: bytes | str,
        consistency_proof: ProofSource,
        *,
        old_size: int | None = None,
    ) -> str:
        """Submit a signed checkpoint; return the cosignature line(s).

        ``consistency_proof`` is ``proof(old_size, new_size)`` (preferred:
        it lets the client recover from any 409) or a fixed
        ``(old_size, proof)`` pair.  ``old_size`` overrides the starting
        size; by default the client starts from the size it last saw this
        witness hold for the origin (when not larger than the checkpoint),
        else from the fixed pair, else 0.
        """
        note_bytes = signed_note.encode("utf-8") if isinstance(signed_note, str) else bytes(signed_note)
        note = parse_note(note_bytes)
        cp = parse_checkpoint(note.text)
        if not note_bytes.endswith(b"\n"):
            raise ValueError("signed note must end with a newline")

        record = self.rollback(cp.origin)
        if record is not None:
            raise WitnessRolledBack(
                cp.origin, record["previous"], record["named"],
                f"witness rolled back for {cp.origin} (from size {record['previous']} to "
                f"{record['named']}); not acknowledged",
            )

        proof_fn: ProofFunction | None = None
        fixed: tuple[int, list[bytes]] | None = None
        if callable(consistency_proof):
            proof_fn = consistency_proof
        else:
            fixed_old, fixed_proof = consistency_proof
            fixed = (int(fixed_old), [bytes(h) for h in fixed_proof])

        if old_size is not None:
            old = old_size
        elif fixed is not None:
            old = fixed[0]
        else:
            old = self._starting_size(cp.origin, cp.size)
        if old < 0:
            raise ValueError("old size must be non-negative")
        if old > cp.size:
            raise ValueError(f"old size {old} is larger than the checkpoint size {cp.size}")

        conflicts = 0
        while True:
            proof = self._proof_for(old, cp.size, fixed, proof_fn)
            body = format_add_checkpoint_request(old, proof, note_bytes)
            status, content_type, data = self._post(body)
            if status == 200:
                lines = self._accept(data, cp)
                # A 200 means the witness held exactly ``old``.
                self._check_named_size(cp.origin, old)
                self.known_sizes[cp.origin] = cp.size
                self._record_cosigned(cp.origin, cp.size)
                return lines
            if status == 409:
                known = self._parse_conflict(content_type, data)
                if known == old:
                    if old == cp.size:
                        # tlog-witness v1.0.0 answers "same size, different
                        # root" with 409 (v1.1.0 uses 422): a possible split view.
                        raise WitnessRejected(
                            409,
                            f"witness holds tree size {old} for {cp.origin} with a different root hash",
                        )
                    raise BadWitnessResponse(f"409 Conflict naming the old size {old} that was sent")
                self._check_named_size(cp.origin, known)
                if known > cp.size:
                    # Not remembered: an unauthenticated 409 must not block
                    # later submissions.
                    log.error(
                        "witness %s holds size %d for %s, larger than this checkpoint (%d): "
                        "the checkpoint is stale, or the log rolled back or its key signed "
                        "elsewhere", self.url, known, cp.origin, cp.size,
                    )
                    raise WitnessAhead(
                        known,
                        f"witness already cosigned size {known} for {cp.origin}, "
                        f"larger than this checkpoint ({cp.size})",
                    )
                self.known_sizes[cp.origin] = known
                conflicts += 1
                if conflicts > self.max_conflicts:
                    raise WitnessConflict(known, f"gave up after {conflicts} conflicts")
                old = known
                continue
            raise WitnessRejected(status, _text(data))

    def _starting_size(self, origin: str, size: int) -> int:
        hint = self.known_sizes.get(origin)
        if hint is None:
            hint = self.max_cosigned(origin)
        if hint is None:
            return 0
        if hint > size:
            log.debug("ignoring the remembered size %d for %s (checkpoint size %d)", hint, origin, size)
            return 0
        return hint

    def _proof_for(
        self,
        old: int,
        new: int,
        fixed: tuple[int, list[bytes]] | None,
        proof_fn: ProofFunction | None,
    ) -> list[bytes]:
        if old == 0 or old == new:
            return []  # nothing to prove from the empty tree or to the same size
        if fixed is not None and old == fixed[0]:
            proof = fixed[1]
        elif proof_fn is not None:
            proof = [bytes(h) for h in proof_fn(old, new)]
        else:
            raise WitnessConflict(
                old,
                f"the witness expects old size {old}; pass a proof function "
                "(old, new) -> proof to continue from it",
            )
        if len(proof) > MAX_PROOF_LINES:
            raise ValueError(f"consistency proof longer than {MAX_PROOF_LINES} hashes")
        return proof

    def _accept(self, data: bytes, cp) -> str:  # type: ignore[no-untyped-def]
        try:
            lines = parse_signature_lines(data.decode("utf-8"))
        except (UnicodeDecodeError, ProtocolError) as e:
            raise BadWitnessResponse(f"malformed cosignature response: {e}") from None
        key = self.witness_vkey
        if key is None:  # allow_unverified: diagnostics only
            return "".join(format_signature_line(s) for s in lines)
        mine = [s for s in lines if s.name == key.name and s.key_id == key.key_id]
        if not mine:
            raise BadWitnessResponse(f"response holds no signature from witness key {key.name}")
        now = int(self._clock())
        for sig in mine:
            if not verify_cosignature(
                sig.signature,
                key.name,
                key.public_key,
                cp.origin,
                cp.size,
                cp.root,
                cp.extension_lines,
            ):
                raise BadWitnessResponse(
                    f"cosignature from {key.name} does not verify for this checkpoint"
                )
            timestamp = int.from_bytes(sig.signature[:8], "big")
            if self.max_future_seconds is not None and timestamp > now + self.max_future_seconds:
                raise BadWitnessResponse(
                    f"cosignature from {key.name} is dated {timestamp - now} s in the future"
                )
            if self.max_age_seconds is not None and timestamp < now - self.max_age_seconds:
                raise BadWitnessResponse(
                    f"cosignature from {key.name} is {now - timestamp} s old (stale or replayed)"
                )
        return "".join(format_signature_line(s) for s in mine)

    @staticmethod
    def _parse_conflict(content_type: str, data: bytes) -> int:
        media = content_type.split(";", 1)[0].strip().lower()
        if media != SIZE_CONTENT_TYPE:
            raise BadWitnessResponse(f"409 Conflict with Content-Type {content_type!r}, not {SIZE_CONTENT_TYPE}")
        try:
            return parse_size_body(data)
        except ProtocolError as e:
            raise BadWitnessResponse(f"409 Conflict body: {e}") from None

    # -- HTTP -------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        if self._conn is None:
            if self._scheme == "https":
                context = self._ssl_context or ssl.create_default_context()
                self._conn = http.client.HTTPSConnection(
                    self._host, self._port, timeout=self.timeout, context=context
                )
            else:
                self._conn = http.client.HTTPConnection(self._host, self._port, timeout=self.timeout)
        return self._conn

    def _request_once(self, body: bytes) -> tuple[int, str, bytes, float | None]:
        conn = self._connection()
        conn.request(
            "POST",
            self._path,
            body=body,
            headers={
                "Content-Type": "text/plain; charset=utf-8",
                "User-Agent": f"aics-witness-feeder/{__version__}",
            },
        )
        resp = conn.getresponse()
        data = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            self.close()
            raise BadWitnessResponse("witness response too large")
        if resp.will_close:
            self.close()
        retry_after: float | None = None
        header = resp.getheader("Retry-After")
        if header and header.strip().isdigit():
            retry_after = float(header.strip())
        return resp.status, resp.getheader("Content-Type", "") or "", data, retry_after

    def _request(self, body: bytes) -> tuple[int, str, bytes, float | None]:
        reused = self._conn is not None and self._conn.sock is not None
        try:
            return self._request_once(body)
        except ConnectionError:
            if not reused:
                raise
            # The witness closed the idle keep-alive connection (it does so
            # after a few seconds); send again at once on a new one.
            self.close()
            return self._request_once(body)

    def _post(self, body: bytes) -> tuple[int, str, bytes]:
        delay = self.backoff
        last_error = "no attempt made"
        for attempt in range(1, self.max_attempts + 1):
            wait = delay * random.uniform(0.5, 1.0)
            try:
                status, content_type, data, retry_after = self._request(body)
            except (OSError, http.client.HTTPException) as e:
                self.close()
                last_error = f"{type(e).__name__}: {e}"
            else:
                if status not in RETRYABLE_STATUS:
                    return status, content_type, data
                last_error = f"HTTP {status}: {_text(data, 120)}"
                if retry_after is not None:
                    wait = retry_after
            if attempt == self.max_attempts:
                break
            self._sleep(min(wait, self.max_backoff))
            delay = min(delay * 2, self.max_backoff)
        raise WitnessUnavailable(f"{self.url}: no answer after {self.max_attempts} attempts ({last_error})")


def submit_checkpoint(
    witness_url: str,
    signed_note_bytes: bytes | str,
    consistency_proof: ProofSource,
    *,
    witness_vkey: VKey | str | None = None,
    old_size: int | None = None,
    **client_options: object,
) -> str:
    """One-shot submission: returns the witness's cosignature line(s).

    See WitnessClient for the options and the retry / old-size behaviour.
    A long-running log should keep a WitnessClient per witness instead, so
    it remembers each witness's size and reuses the connection.
    """
    with WitnessClient(witness_url, witness_vkey, **client_options) as client:  # type: ignore[arg-type]
        return client.submit(signed_note_bytes, consistency_proof, old_size=old_size)


def merge_cosignatures(signed_note: bytes | str, cosignature_lines: str) -> bytes:
    """Add cosignature lines to a signed checkpoint, replacing any earlier
    line from the same key (same name and key ID), so the result never
    holds two lines with the same key name and ID."""
    note = parse_note(signed_note)
    try:
        new: list[SignatureLine] = parse_signature_lines(cosignature_lines)
    except ProtocolError as e:
        raise ValueError(f"malformed cosignature lines: {e}") from None
    replaced = {(s.name, s.key_id) for s in new}
    kept = [s for s in note.signatures if (s.name, s.key_id) not in replaced]
    return Note(text=note.text, signatures=tuple(kept + new)).to_bytes()
