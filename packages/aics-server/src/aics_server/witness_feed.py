"""Feeding the published checkpoint to witnesses, and serving their cosignatures.

AICS-1 sections 6.2 and 6.3, DESIGN.md G5, DECISIONS.md #30 (the founder-run
witness host), packages/aics-witness (the witness and its feeder client).

Configuration (environment, read by :class:`aics_server.db.SanctuaryDB`):

* ``AICS_WITNESSES``: empty (the default) means no witness, and nothing below
  runs.  Otherwise either comma-separated ``name=url=vkey`` entries, or the
  path of a JSON file ``{"witnesses": [{"name", "url", "vkey"}, ...]}``.
  ``name`` is a local label (``[A-Za-z0-9._-]``, at most 64 characters) for
  the status and the state file; ``url`` is the witness's
  ``http(s)://host[:port][/prefix]`` (``/add-checkpoint`` is appended);
  ``vkey`` is the witness's cosignature verifier key (type ``0x04``) as
  ``aics-witness init`` prints it.  None of this is secret.  The card module
  (:func:`aics_server.card.witnesses_from_env`) reads the same setting for the
  witness policy the card states.
* ``AICS_WITNESS_STATE_DIR``: default ``<db dir>/witness-state``.  One JSON
  file per witness: the largest size it was seen to cosign and any detected
  rollback (:class:`aics_witness.feeder.WitnessClient` state).
* ``AICS_WITNESS_REFRESH_SECONDS`` (default 60, from 5 to 100: at most a
  third of the card's ``max_checkpoint_age`` of 300 s): how often the current
  checkpoint is submitted again while the tree does not grow.
* ``AICS_WITNESS_TIMEOUT_SECONDS`` (default 5, from 0.1 to 120): the bound on
  one submission to one witness (one request; a failed one is retried with
  the backoff below), and on how long a request for a checkpoint that waits
  for its cosignature waits, at most 5 s whatever this says
  (:data:`aics_server.db.MAX_COSIGNATURE_WAIT_SECONDS`).
* ``AICS_WITNESS_GRACE_SECONDS`` (default 120, from 0 to 300 minus
  ``AICS_WITNESS_REFRESH_SECONDS`` minus 30: 210 s with the default
  refresh): how long every witness may fail before newer checkpoints are
  served without a cosignature (step 5).  The cosigned note held meanwhile
  is at most about a refresh interval older than the outage, so it is still
  inside the card's ``max_checkpoint_age`` of 300 s when the grace ends; a
  longer grace would hold a note every quorum-1 verifier rejects as stale
  and keep newer entries from being served for nothing
  (:func:`max_grace_seconds`).  With a witness configured, a value above
  that stops the start.

The import of :mod:`aics_witness` happens only when a witness is configured;
a server whose image lacks the package refuses to start with that setting
rather than run without the witness it was told to feed.

The flow, after every new checkpoint:

1. :class:`aics_server.tlog_store.TlogStore` writes the tiles, then signs
   the note, under the database lock, exactly as before.  A write never
   waits for a witness: the 60-second maximum merge delay and the
   single-writer invariant are unchanged.
2. The store hands ``(size, note)`` to :meth:`WitnessFeeder.offer` at once,
   which records it and wakes one thread per witness: the checkpoint is
   submitted at publication, bounded by ``AICS_WITNESS_TIMEOUT_SECONDS`` per
   witness, unless that witness is waiting out a backoff (step 5).
3. Each thread submits the latest note with ``WitnessClient.submit``; the
   consistency proof from whatever size the witness holds is computed from
   the in-memory tree under the database lock.  The client verifies the
   returned line under the witness vkey and checks it is fresh.
4. :meth:`TlogStore.add_cosignature` verifies it again (that witness key,
   a valid ``cosignature/v1`` over exactly that checkpoint, dated neither
   ahead nor stale), merges it (``merge_cosignatures`` semantics: one line
   per witness key, a newer line replaces an older one), verifies the merged
   note as a whole and replaces ``<tiles>/checkpoint`` atomically: it is the
   served note from then on.  A line that fails any check is dropped: no
   note whose cosignature does not verify is ever served.  Until a witness
   cosigns a new publication, the note served at ``/checkpoint``,
   ``/tiles/checkpoint`` and ``<tiles>/checkpoint``, stated by the read
   projections and used for every inclusion proof is the newest cosigned
   one (:attr:`TlogStore.served`), so a verifier holding a card of quorum 1
   never gets a newer note it must reject.  A line for a checkpoint older
   than the served one is dropped (``"superseded"``); one for a publication
   newer than the served one but older than the latest moves the served note
   forward all the same.
5. A witness that times out, refuses, answers 5xx or returns a bad line is
   retried with capped exponential backoff and jitter (1 s doubling to
   :data:`MAX_BACKOFF_SECONDS`, 30 s: half the 60 s maximum merge delay, so a
   witness that comes back cosigns the current checkpoint well within it,
   AICS-1 section 10.1), always with the latest checkpoint.  A new checkpoint
   published during the wait is fed when the wait ends.  Meanwhile the log
   keeps accepting writes and publishing; the served note stays the newest
   cosigned one.  Only when every witness has been failing for longer than
   ``AICS_WITNESS_GRACE_SECONDS`` (or no checkpoint served here carries a
   cosignature yet, so there is nothing to hold on to) are newer checkpoints
   served without one, and ``/healthz`` says so (``serving_uncosigned``,
   ``uncosigned_reason``).  The first cosignature after that is served
   again.
6. While the tree does not grow, the current checkpoint is submitted again
   every ``AICS_WITNESS_REFRESH_SECONDS``, so its cosignature stays inside
   the card's ``max_checkpoint_age`` (300 s) and AICS-1 section 6.3's
   freshness window.

At start-up the feeder submits the published checkpoint before the server
answers requests, waiting up to that request wait (plus a second) for every
witness's first answer.

Uptime probe.  ``ops/uptime-check.sh`` reads the checkpoint's age from the
cosignature timestamps in the note (76-byte ``key ID || timestamp ||
signature`` blobs).  A log-only note carries none, so until a witness cosigns
the probe exits 4 ("cannot determine checkpoint age").  Once a witness
cosigns, that exit-4 case ends: the note carries a timestamp, refreshed
every ``AICS_WITNESS_REFRESH_SECONDS``, well under the probe's limit (240 s
from the vantage, ops/vantage, under the card's ``max_checkpoint_age`` of
300 s; 600 s by default).  With the witness's vkey pinned
(``AICS_WITNESS_VKEY_FILE``) only that witness's verified line dates it.
If the witness stops answering, the old line stays on the served note (it is
still a valid cosignature of that checkpoint, and a newer publication waits
for its own) and ages until the probe exits 3; once every witness has failed
for longer than ``AICS_WITNESS_GRACE_SECONDS`` and the tree has grown, the
newer note served has no line and the probe exits 4 again.  Either way
``/healthz`` ``witnesses`` says which witness fails and why
(``serving_uncosigned`` once the newer note is served).

Trust.  A founder-run witness is in the operator's trust domain even on
another provider: its cosignature makes a split view detectable, not
prevented, and G5 stays ``promised``.  The card a server builds states the
witnesses of the same setting (:mod:`aics_server.card`), but the logged card
agents hold changes only through a logged successor card (AICS-1 section
13).  Clients of a card that does not list the witness ignore its line
(signed-note: unknown keys are ignored).

Status (``/healthz`` ``witnesses``, one object per configured witness):
``name`` (the local label of ``AICS_WITNESSES``), ``cosigner`` (the name on
its ``cosignature/v1`` lines, which its vkey and the card carry), ``vkey``,
``state`` (``pending``, ``ok``, ``failing``, ``rolled_back``, ``ahead``),
``last_success_at``, ``last_cosigned_size``, ``last_error``,
``last_error_at``, ``failing_since`` (Unix seconds), ``consecutive_failures``,
``next_attempt_in_seconds``, and for the note served now ``cosigned_current``,
``cosignature_timestamp`` and ``cosignature_age_seconds``.  The witness URL is
not shown (error texts name it ``<witness>``).
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aics_tlog import VKey, format_vkey, parse_vkey
from aics_tlog.note import ed25519_public_key_problem

__all__ = [
    "COSIGNATURE_MAX_AGE_SECONDS",
    "GRACE_SECONDS",
    "MAX_BACKOFF_SECONDS",
    "WitnessConfigError",
    "WitnessEndpoint",
    "WitnessFeeder",
    "WitnessSettings",
    "max_grace_seconds",
    "parse_witnesses",
]

#: A cosignature older than this when it arrives is not served (the card's max_checkpoint_age).
COSIGNATURE_MAX_AGE_SECONDS = 300
#: A cosignature dated further ahead than this is not served (AICS-1 section 6.3: timestamp <= now + 30).
COSIGNATURE_MAX_FUTURE_SECONDS = 30
#: Cosignature vkey type (c2sp.org/tlog-cosignature, Ed25519).
_COSIGNATURE_TYPE = 0x04
_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_ENTRY_KEYS = {"name", "url", "vkey"}
#: Bounds of AICS_WITNESS_REFRESH_SECONDS: a third of the card's max_checkpoint_age at most.
REFRESH_BOUNDS = (5.0, COSIGNATURE_MAX_AGE_SECONDS / 3)
#: The longest wait before a failing witness is tried again: half the maximum merge delay (MMD_SECONDS, 60 s).
#: Once a card requires a witness quorum, a cosignature is part of publication (AICS-1 section 10.1), so a
#: witness that recovers must be tried again well within the MMD, not after minutes of backoff.
MAX_BACKOFF_SECONDS = 30.0
#: How long every witness may fail before newer checkpoints are served uncosigned (AICS_WITNESS_GRACE_SECONDS).
#: Under the card's max_checkpoint_age (300 s), so the cosigned note held meanwhile is still fresh for verifiers.
GRACE_SECONDS = 120.0
#: Bounds of AICS_WITNESS_GRACE_SECONDS (from the environment also at most :func:`max_grace_seconds`).
GRACE_BOUNDS = (0.0, 3600.0)
#: What :func:`max_grace_seconds` keeps free under the card's max_checkpoint_age, for a submission's timeout and a
#: verifier's clock.
GRACE_MARGIN_SECONDS = 30.0
#: The bound on one submission to one witness (AICS_WITNESS_TIMEOUT_SECONDS).
TIMEOUT_SECONDS = 5.0


class WitnessConfigError(ValueError):
    """``AICS_WITNESSES`` (or a related setting) is malformed; the server does not start."""


def _say(message: str) -> None:
    print(f"aics-server: {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class WitnessEndpoint:
    """One witness the checkpoint is fed to: a local label, its add-checkpoint base URL and its cosignature vkey."""

    name: str
    url: str
    vkey: VKey

    @property
    def vkey_text(self) -> str:
        return format_vkey(self.vkey)

    @property
    def state_file_name(self) -> str:
        """The client state file: per label and key (a new key under an old label starts a new state)."""
        return f"{self.name}-{self.vkey.key_id.hex()}.json"


def _endpoint(name: Any, url: Any, vkey: Any, where: str) -> WitnessEndpoint:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise WitnessConfigError(f"{where}: the witness name is 1 to 64 characters of A-Z a-z 0-9 . _ -")
    if not isinstance(url, str):
        raise WitnessConfigError(f"{where}: witness {name!r} has no URL")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment:
        raise WitnessConfigError(f"{where}: witness {name!r}: the URL is http(s)://host[:port][/prefix]")
    if not isinstance(vkey, str):
        raise WitnessConfigError(f"{where}: witness {name!r} has no vkey")
    try:
        key = parse_vkey(vkey.strip())
    except ValueError as exc:
        raise WitnessConfigError(f"{where}: witness {name!r}: the vkey is not a C2SP verifier key ({exc})") from None
    if key.key_type != _COSIGNATURE_TYPE or len(key.public_key) != 32:
        raise WitnessConfigError(f"{where}: witness {name!r}: the vkey is not an Ed25519 cosignature key (type 0x04)")
    problem = ed25519_public_key_problem(key.public_key)
    if problem is not None:
        raise WitnessConfigError(f"{where}: witness {name!r}: the public key {problem}")
    return WitnessEndpoint(name=name, url=url.strip(), vkey=key)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise WitnessConfigError(f"AICS_WITNESSES: duplicate member {key!r}")
        out[key] = value
    return out


def parse_witnesses(value: str) -> tuple[WitnessEndpoint, ...]:
    """Parse ``AICS_WITNESSES``: ``name=url=vkey[,name=url=vkey...]`` or a JSON file path; empty gives none."""
    value = (value or "").strip()
    if not value:
        return ()
    endpoints: list[WitnessEndpoint] = []
    if "=" not in value:
        where = value
        try:
            doc = json.loads(Path(value).read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)
        except OSError as exc:
            raise WitnessConfigError(f"AICS_WITNESSES: cannot read {value} ({exc.strerror or exc})") from None
        except WitnessConfigError:
            raise
        except ValueError as exc:
            raise WitnessConfigError(f"AICS_WITNESSES: {value} is not JSON ({exc})") from None
        if isinstance(doc, dict) and set(doc) == {"witnesses"}:
            doc = doc["witnesses"]
        if not isinstance(doc, list):
            raise WitnessConfigError(f'{where}: expected {{"witnesses": [{{"name", "url", "vkey"}}, ...]}}')
        for item in doc:
            if not isinstance(item, dict) or set(item) != _ENTRY_KEYS:
                raise WitnessConfigError(f"{where}: each witness is exactly {{name, url, vkey}}")
            endpoints.append(_endpoint(item["name"], item["url"], item["vkey"], where))
    else:
        for raw in value.split(","):
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split("=", 2)
            if len(parts) != 3:
                raise WitnessConfigError("AICS_WITNESSES: each entry is name=url=vkey")
            endpoints.append(_endpoint(parts[0].strip(), parts[1], parts[2], "AICS_WITNESSES"))
    names = [e.name for e in endpoints]
    keys = [e.vkey.public_key for e in endpoints]
    if len(set(names)) != len(names):
        raise WitnessConfigError("AICS_WITNESSES: witness names must be unique")
    if len(set(keys)) != len(keys) or len({e.vkey.name for e in endpoints}) != len(endpoints):
        raise WitnessConfigError("AICS_WITNESSES: witness keys and cosigner names must be unique")
    return tuple(endpoints)


def max_grace_seconds(refresh_seconds: float) -> float:
    """The longest ``AICS_WITNESS_GRACE_SECONDS`` with that ``AICS_WITNESS_REFRESH_SECONDS``.

    The newest cosignature on the note held while every witness fails was
    made at the last answer, at most about ``refresh_seconds`` before the
    first failed attempt (an idle log is submitted again every refresh; a
    growing one at every publication), so when the grace ends it is younger
    than the card's ``max_checkpoint_age`` (:data:`COSIGNATURE_MAX_AGE_SECONDS`)
    by :data:`GRACE_MARGIN_SECONDS` at least.
    """
    return COSIGNATURE_MAX_AGE_SECONDS - refresh_seconds - GRACE_MARGIN_SECONDS


def _seconds(environ: Mapping[str, str], name: str, default: float, low: float, high: float) -> float:
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise WitnessConfigError(f"{name} must be a number of seconds") from None
    if not low <= value <= high:
        raise WitnessConfigError(f"{name} must be between {low:g} and {high:g} seconds")
    return value


@dataclass(frozen=True)
class WitnessSettings:
    """The witnesses to feed and how (see the module docstring for the variables)."""

    witnesses: tuple[WitnessEndpoint, ...]
    state_dir: Path | None = None
    refresh_seconds: float = 60.0
    timeout_seconds: float = TIMEOUT_SECONDS
    min_backoff_seconds: float = 1.0
    max_backoff_seconds: float = MAX_BACKOFF_SECONDS
    grace_seconds: float = GRACE_SECONDS

    def __post_init__(self) -> None:
        if not 0 < self.min_backoff_seconds <= self.max_backoff_seconds <= MAX_BACKOFF_SECONDS:
            raise WitnessConfigError(
                f"witness backoff must satisfy 0 < min <= max <= {MAX_BACKOFF_SECONDS:g} s (half the maximum merge delay)"
            )
        if not GRACE_BOUNDS[0] <= self.grace_seconds <= GRACE_BOUNDS[1]:
            raise WitnessConfigError(f"the witness grace must be between {GRACE_BOUNDS[0]:g} and {GRACE_BOUNDS[1]:g} s")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, *, default_state_dir: Path) -> WitnessSettings:
        environ = os.environ if environ is None else environ
        witnesses = parse_witnesses(environ.get("AICS_WITNESSES", ""))
        state_dir = (environ.get("AICS_WITNESS_STATE_DIR") or "").strip()
        # Well inside the freshness window clients apply to cosignatures (the card's max_checkpoint_age).
        refresh = _seconds(environ, "AICS_WITNESS_REFRESH_SECONDS", 60.0, *REFRESH_BOUNDS)
        grace = _seconds(environ, "AICS_WITNESS_GRACE_SECONDS", GRACE_SECONDS, *GRACE_BOUNDS)
        if witnesses and grace > max_grace_seconds(refresh):
            raise WitnessConfigError(
                f"AICS_WITNESS_GRACE_SECONDS must be at most {max_grace_seconds(refresh):g} s with "
                f"AICS_WITNESS_REFRESH_SECONDS {refresh:g}: the cosigned note held while every witness fails would "
                f"be older than the card's max_checkpoint_age ({COSIGNATURE_MAX_AGE_SECONDS} s) before the grace "
                "ends, and rejected by every verifier of a quorum-1 card"
            )
        return cls(
            witnesses=witnesses,
            state_dir=Path(state_dir) if state_dir else default_state_dir,
            refresh_seconds=refresh,
            timeout_seconds=_seconds(environ, "AICS_WITNESS_TIMEOUT_SECONDS", TIMEOUT_SECONDS, 0.1, 120.0),
            grace_seconds=grace,
        )


class _Worker:
    """One witness: its client, its thread and what the status reports about it."""

    def __init__(self, endpoint: WitnessEndpoint, client: Any) -> None:
        self.endpoint = endpoint
        self.client = client
        self.thread: threading.Thread | None = None
        self.state = "pending"
        self.done_size: int | None = None  # the size of the last cosignature served
        self.done_at: float | None = None  # monotonic
        self.retry_at: float | None = None  # monotonic; backoff after a failure
        self.backoff = 0.0
        self.failures = 0
        self.last_success_at: int | None = None
        self.last_cosigned_size: int | None = None
        self.last_error: str | None = None
        self.last_error_at: int | None = None
        # Since when its attempts have failed without an answer in between (monotonic, and Unix seconds for status).
        self.failing_since: float | None = None
        self.failing_since_at: int | None = None

    def reached(self) -> None:
        """The witness answered with a cosignature (served, or for a checkpoint already overtaken)."""
        self.state = "ok"
        self.retry_at = None
        self.backoff = 0.0
        self.failures = 0
        self.failing_since = None
        self.failing_since_at = None


#: ``proof(old_size, new_size)``: the RFC 6962 consistency proof (the caller takes the database lock).
ProofFunction = Callable[[int, int], Sequence[bytes]]
#: ``deliver(endpoint, size, lines)``: merge the lines into the served note; ``(served, reason)``.
DeliverFunction = Callable[[WitnessEndpoint, int, str], "tuple[bool, str | None]"]


class WitnessFeeder:
    """Submits the latest published checkpoint to every configured witness, one thread each.

    :meth:`offer`, :meth:`outage`, :meth:`next_attempt_in` and
    :meth:`status` are the calls made under the database lock; they never
    block on the network.  The threads call ``proof``, ``deliver`` and
    ``on_change``, which take the database lock themselves, and never hold the
    feeder's own lock while they do (so the lock order is always database,
    then feeder).  ``on_change()`` is called after each attempt that changed
    what a witness is known to do (an answer, a failure).
    """

    def __init__(
        self,
        settings: WitnessSettings,
        *,
        proof: ProofFunction,
        deliver: DeliverFunction,
        client_factory: Callable[[WitnessEndpoint], Any] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], float] = time.time,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        if not settings.witnesses:
            raise ValueError("a witness feeder needs at least one witness")
        self.settings = settings
        self._proof = proof
        self._deliver = deliver
        self._on_change = on_change
        self._monotonic = monotonic
        self._clock = clock
        self._cond = threading.Condition()
        self._target: tuple[int, bytes] | None = None
        self._stopping = False
        self._started = False
        factory = client_factory or self._default_client
        self._workers = [_Worker(endpoint, factory(endpoint)) for endpoint in settings.witnesses]

    def _default_client(self, endpoint: WitnessEndpoint) -> Any:
        try:
            from aics_witness.feeder import WitnessClient
        except ImportError:
            raise WitnessConfigError(
                "AICS_WITNESSES names a witness, but the aics-witness package (packages/aics-witness) is not "
                "installed in this environment: install it next to aics-server, or leave AICS_WITNESSES empty"
            ) from None
        state_path = None
        if self.settings.state_dir is not None:
            state_path = self.settings.state_dir / endpoint.state_file_name
        try:
            # One request per submission, bounded by the timeout: a failed one is retried with this feeder's
            # backoff (which /healthz reports), not inside the client.
            return WitnessClient(
                endpoint.url,
                endpoint.vkey,
                timeout=self.settings.timeout_seconds,
                max_attempts=1,
                state_path=state_path,
            )
        except ValueError as exc:
            raise WitnessConfigError(f"witness {endpoint.name!r}: {exc}") from None

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        with self._cond:
            if self._started:
                return
            self._started = True
            for worker in self._workers:
                worker.thread = threading.Thread(
                    target=self._run, args=(worker,), name=f"aics-witness-feed-{worker.endpoint.name}", daemon=True
                )
                worker.thread.start()

    @property
    def running(self) -> bool:
        """Whether the threads were started and not told to stop."""
        return self._started and not self._stopping

    def wait_first_attempts(self, timeout: float) -> bool:
        """Block until every witness has answered or failed once (the start-up submission); False after ``timeout``."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while self.running and any(w.state == "pending" for w in self._workers):
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(left)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        with self._cond:
            self._stopping = True
            self._cond.notify_all()
        for worker in self._workers:
            if worker.thread is not None:
                worker.thread.join(timeout)
            try:
                worker.client.close()
            except Exception:  # pragma: no cover - closing a socket
                pass

    # -- the log side ---------------------------------------------------------

    def offer(self, size: int, note: bytes) -> None:
        """The checkpoint now published (log-signed); returns at once, and every idle witness thread submits it."""
        with self._cond:
            current = self._target
            if current is not None and current[0] >= size:
                return  # only ever move forward
            self._target = (size, bytes(note))
            self._cond.notify_all()

    # -- the threads ----------------------------------------------------------

    def _wait_for(self, worker: _Worker, size: int, now: float) -> float:
        """Seconds until ``worker`` should submit the checkpoint of ``size`` (0: now)."""
        if worker.retry_at is not None and now < worker.retry_at:
            return worker.retry_at - now
        if worker.done_size != size or worker.done_at is None:
            return 0.0
        return max(0.0, worker.done_at + self.settings.refresh_seconds - now)

    def _run(self, worker: _Worker) -> None:
        while True:
            with self._cond:
                while True:
                    if self._stopping:
                        return
                    target = self._target
                    if target is None:
                        self._cond.wait()
                        continue
                    wait = self._wait_for(worker, target[0], self._monotonic())
                    if wait <= 0:
                        break
                    self._cond.wait(wait)
            size, note = target
            try:
                lines = worker.client.submit(note, self._proof)
            except Exception as exc:  # FeederError, a transport error, a proof the tree cannot give
                self._failed(worker, exc)
                self._changed()
                continue
            try:
                served, reason = self._deliver(worker.endpoint, size, lines)
            except Exception as exc:  # pragma: no cover - deliver catches its own errors
                served, reason = False, f"{type(exc).__name__}: {exc}"
            if served:
                self._succeeded(worker, size)
            elif reason == "superseded":
                with self._cond:  # it answered, but a newer checkpoint is served already: feed the latest at once
                    worker.reached()
                    moved = self._target is not None and self._target[0] != size
                    worker.retry_at = None if moved else self._monotonic() + self.settings.min_backoff_seconds
                    self._cond.notify_all()
            else:
                self._failed(worker, None, f"cosignature not served: {reason}")
            self._changed()

    def _changed(self) -> None:
        hook = self._on_change
        if hook is not None:
            try:
                hook()
            except Exception as exc:  # pragma: no cover - the database's hook catches its own errors
                _say(f"witness state hand-off failed: {type(exc).__name__}: {exc}")

    def _scrub(self, worker: _Worker, text: str) -> str:
        url = getattr(worker.client, "url", None)
        for secretish in filter(None, (url, worker.endpoint.url, urlsplit(worker.endpoint.url).hostname)):
            text = text.replace(secretish, "<witness>")
        return text[:300]

    def _failed(self, worker: _Worker, exc: BaseException | None, message: str | None = None) -> None:
        kind = type(exc).__name__ if exc is not None else None
        text = self._scrub(worker, message if message is not None else f"{kind}: {exc}")
        with self._cond:
            worker.failures += 1
            worker.last_error = text
            worker.last_error_at = int(self._clock())
            if worker.failing_since is None:
                worker.failing_since = self._monotonic()
                worker.failing_since_at = worker.last_error_at
            if kind == "WitnessRolledBack":
                worker.state = "rolled_back"
            elif kind == "WitnessAhead":
                worker.state = "ahead"
            else:
                worker.state = "failing"
            low, high = self.settings.min_backoff_seconds, self.settings.max_backoff_seconds
            worker.backoff = min(high, max(low, worker.backoff * 2 if worker.backoff else low))
            delay = worker.backoff * random.uniform(0.5, 1.0)
            worker.retry_at = self._monotonic() + delay
            state = worker.state
            self._cond.notify_all()  # wait_first_attempts
        if state == "ahead":
            _say(
                f"WITNESS {worker.endpoint.name} HOLDS A LARGER TREE THAN THIS LOG: the log rolled back or its key "
                f"signed elsewhere; investigate now ({text})"
            )
        elif state == "rolled_back":
            _say(f"witness {worker.endpoint.name} lost or rolled back its state; its cosignatures are refused ({text})")
        else:
            _say(f"witness {worker.endpoint.name}: {text}; retrying in about {int(delay) or 1} s")

    def _succeeded(self, worker: _Worker, size: int) -> None:
        with self._cond:
            worker.reached()
            worker.done_size = size
            worker.done_at = self._monotonic()
            worker.last_success_at = int(self._clock())
            worker.last_cosigned_size = size
            self._cond.notify_all()  # wait_first_attempts

    # -- what the served checkpoint depends on ------------------------------------

    def outage(self) -> float | None:
        """For how many seconds every witness has been failing (each since its last answer), or ``None``.

        ``None`` while any witness has not failed its last attempt (it is
        answering, or still has its first answer to give), and while the
        threads are not running: then a cosignature may still come.
        """
        with self._cond:
            if not self.running:
                return None
            starts = [w.failing_since for w in self._workers]
            if any(s is None for s in starts):
                return None
            return max(0.0, self._monotonic() - max(starts))  # type: ignore[type-var]

    def next_attempt_in(self) -> float:
        """Seconds until the next witness is tried again (0 when one is not waiting out a backoff)."""
        with self._cond:
            now = self._monotonic()
            return min(max(0.0, w.retry_at - now) if w.retry_at is not None else 0.0 for w in self._workers)

    # -- status ---------------------------------------------------------------

    def status(self, served: Mapping[str, int] | None = None) -> list[dict[str, Any]]:
        """Per witness, in configuration order; ``served`` maps a vkey to its line's timestamp on the served note."""
        served = served or {}
        now = self._monotonic()
        wall = int(self._clock())
        out = []
        with self._cond:
            for worker in self._workers:
                vkey = worker.endpoint.vkey_text
                stamp = served.get(vkey)
                retry = None if worker.retry_at is None else max(0, int(worker.retry_at - now))
                out.append({
                    "name": worker.endpoint.name,
                    "cosigner": worker.endpoint.vkey.name,
                    "vkey": vkey,
                    "state": worker.state,
                    "last_success_at": worker.last_success_at,
                    "last_cosigned_size": worker.last_cosigned_size,
                    "last_error": worker.last_error,
                    "last_error_at": worker.last_error_at,
                    "failing_since": worker.failing_since_at,
                    "consecutive_failures": worker.failures,
                    "next_attempt_in_seconds": retry,
                    "cosigned_current": stamp is not None,
                    "cosignature_timestamp": stamp,
                    "cosignature_age_seconds": None if stamp is None else max(0, wall - stamp),
                })
        return out
