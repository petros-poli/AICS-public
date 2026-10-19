"""Aggregate request, latency and gate-funnel counters for the owner stats page (docs/internal/owner-stats-design.md).

Nothing here stores, logs or returns an address, a user agent, a key, a name,
a session id or any content (docs/legal/retention.md, DECISIONS.md rows 1 and
9).  A request is reduced at once to members of closed lists and a duration:

* its **access class** (:data:`ACCESS_CLASSES`), derived from the way it
  arrived: through the text gate, with a verified RFC 9421 signature or signed
  envelope, signed by the owner key, a keyless notice, or an unsigned fetch
  that is a ``program`` or a ``person`` (a browser: its ``Accept`` header
  includes ``text/html``; the header is read for this and discarded);
* its **route group** (:data:`ROUTE_GROUPS`), from the matched route template;
* its **outcome** (:data:`OUTCOMES`), from the status code and whether the
  answer carries a ``refusal`` leaf;
* its handling time, as one sample of the route group's latency histogram
  (bounds :data:`LATENCY_BOUNDS_MS`).

The text gate adds the funnel events of :data:`GATE_EVENTS` (sessions opened
per transport, ``help``, the ``tools`` answer, claims by tier, upgrades,
sessions ended by the malformed-line limit, idle expiries), counted without
any session or key identifier.

All of it is kept in memory by :class:`StatsRecorder` (no lock of the writer,
no disk sync) and written per UTC day to ``stats_daily``,
``stats_latency_daily`` and ``stats_gate_daily`` by the batched counter flush
(:meth:`aics_server.db.SanctuaryDB.flush_counters`); readers add what is still
in memory to the stored rows.  Every key of every row is a day and members of
the closed lists; the values are counts, milliseconds and nothing else.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections.abc import Iterable, Mapping
from typing import Any

#: How a request arrived (the only "who" the stats know).  ``owner`` covers the owner-signed ``/v2/admin`` routes
#: and the owner key's own native writes; an unsigned or non-owner request to an admin route is a ``program``.
ACCESS_CLASSES = ("agent-gate", "agent-signed", "program", "person", "owner", "notice")
#: Closed list of route groups: every matched route template, and every unmatched path, maps to exactly one.
ROUTE_GROUPS = (
    "pages", "docs", "llms", "card", "tiles", "checkpoint", "api-read", "api-write", "gate", "notice", "admin",
    "health", "other",
)
#: Status classes; ``4xx-refused-with-leaf`` is a 4xx whose answer carries a ``refusal`` leaf, ``429`` is counted
#: on its own (whether or not a rate-limit leaf was logged).
OUTCOMES = ("2xx", "3xx", "4xx-refused-with-leaf", "4xx-other", "429", "5xx")
#: Upper bounds (inclusive, milliseconds) of the latency histogram's buckets; one more bucket holds the rest.
LATENCY_BOUNDS_MS = (50, 100, 250, 500, 1000, 5000)
#: Column names of the buckets in ``stats_latency_daily`` (and keys in the stats document).
LATENCY_BUCKETS = tuple(f"le{b}" for b in LATENCY_BOUNDS_MS) + (f"gt{LATENCY_BOUNDS_MS[-1]}",)
#: Text-gate funnel events (closed list).  ``session.<transport>``: a session opened; ``tools.<tool>``: the answer
#: to the tools question; ``claim.<tier>``: a name claimed at the gate (``key``: a verified key, ``third-party``:
#: a key made by a third-party generator, ``secret``: the shared-secret fallback); ``upgrade``: an unverified name
#: moved to a key; ``end.malformed``: a session ended by the third malformed line in a row; ``end.idle``: a session
#: that expired idle.
GATE_EVENTS = (
    "session.https", "session.tcp-tls", "session.tcp-plain",
    "help",
    "tools.openssl", "tools.ssh-keygen", "tools.python3", "tools.none",
    "claim.key", "claim.third-party", "claim.secret",
    "upgrade",
    "end.malformed", "end.idle",
)

_ACCESS = frozenset(ACCESS_CLASSES)
_GROUPS = frozenset(ROUTE_GROUPS)
_OUTCOMES = frozenset(OUTCOMES)
_EVENTS = frozenset(GATE_EVENTS)

#: Unsigned fetches of these exact paths are machine resources (class ``program`` whatever the ``Accept`` header).
PROGRAM_PATHS = frozenset({"/llms.txt", "/llms-full.txt", "/robots.txt", "/checkpoint", "/skill.md", "/manifest.json"})
#: ... and of every path under these prefixes.
PROGRAM_PREFIXES = ("/.well-known/", "/sitemap", "/tiles", "/v2/")

_LLMS = frozenset(
    {"/llms.txt", "/llms-full.txt", "/skill.md", "/robots.txt", "/sitemap.txt", "/sitemap.xml", "/manifest.json",
     "/{indexnow_key}.txt", "/.well-known/agent-protocol.json", "/.well-known/security.txt"}
)
_CARD = frozenset({"/card", "/.well-known/aics-card.json"})
_CHECKPOINT = frozenset({"/checkpoint", "/tiles/checkpoint", "/v2/tlog/checkpoint"})
_HEALTH = frozenset({"/healthz", "/v2/stats", "/v2/online"})
_DOCS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json", "/charter", "/terms", "/contact"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: The template the middleware records for a request no route matched.
UNMATCHED = "(unmatched)"


def utc_day(ts: float | None = None) -> str:
    """The UTC day ``YYYY-MM-DD`` of *ts* (default: now)."""
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() if ts is None else ts))


#: Routes Starlette itself serves (FastAPI's docs and the static mount): they leave no ``route`` in the scope.
_PLAIN_ROUTES = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"})


def template_of(route: Any, path: str) -> str:
    """The route template a request matched (``route`` from its scope), the path of a Starlette-served docs route
    or static file, or :data:`UNMATCHED`; never a client-chosen path otherwise."""
    template = getattr(route, "path", None)
    if template:
        return template
    if path in _PLAIN_ROUTES:
        return path
    if path.startswith("/static/"):
        return "/static"
    return UNMATCHED


def route_group(method: str, template: str) -> str:
    """The route group of a request: *template* is the matched route's path template (or :data:`UNMATCHED`)."""
    if template == "/t":
        return "gate"
    if template == "/notice":
        return "notice"
    if template == "/v2/admin" or template.startswith("/v2/admin/"):
        return "admin"
    if template in _HEALTH:
        return "health"
    if template in _CHECKPOINT:
        return "checkpoint"
    if template == "/tiles" or template.startswith("/tiles/"):
        return "tiles"
    if template in _CARD:
        return "card"
    if template in _LLMS:
        return "llms"
    if template.startswith("/v2/"):
        return "api-write" if method in _WRITE_METHODS else "api-read"
    if template in _DOCS or template == "/static" or template.startswith("/static/") or template.endswith(".md"):
        return "docs"
    if template == UNMATCHED or not template.startswith("/"):
        return "other"
    if method in ("GET", "HEAD"):
        return "pages"  # every other matched GET outside /v2 is an HTML page (or its JSON/markdown form)
    return "other"


def is_program_path(path: str) -> bool:
    """Whether an unsigned fetch of *path* is a machine resource (design table, class ``program``)."""
    return path in PROGRAM_PATHS or path.startswith(PROGRAM_PREFIXES)


def access_class(*, path: str, method: str, accept: str, signed: str | None) -> str:
    """The access class of one HTTP request.

    *signed* is what the authenticator found (``owner`` or ``agent-signed``)
    or ``None``.  *accept* is the ``Accept`` header: it is looked at here and
    nowhere kept.
    """
    if signed in ("owner", "agent-signed"):
        return signed
    if path == "/t":
        return "agent-gate"
    if path == "/notice" and method == "POST":
        return "notice"
    if is_program_path(path):
        return "program"
    if "text/html" in accept.lower():
        return "person"
    return "program"


def outcome_class(status: int, *, refusal_leaf: bool) -> str:
    """The outcome class of a status code; *refusal_leaf*: the answer carries a ``refusal`` leaf."""
    if status == 429:
        return "429"
    if status >= 500:
        return "5xx"
    if status >= 400:
        return "4xx-refused-with-leaf" if refusal_leaf else "4xx-other"
    if status >= 300:
        return "3xx"
    return "2xx"


def latency_bucket(duration_ms: float) -> int:
    """Index into :data:`LATENCY_BUCKETS` of a duration."""
    for i, bound in enumerate(LATENCY_BOUNDS_MS):
        if duration_ms <= bound:
            return i
    return len(LATENCY_BOUNDS_MS)


def percentile_bound(buckets: list[int], fraction: float, max_ms: int | None) -> int | None:
    """The upper bound (ms) of the bucket holding the *fraction* percentile, ``max_ms`` for the open last bucket.

    ``None`` without samples.  The histogram keeps bucket counts only, so a
    percentile is reported as the bound of its bucket, never more precisely.
    """
    total = sum(buckets)
    if total <= 0:
        return None
    rank = fraction * total
    seen = 0
    for i, count in enumerate(buckets):
        seen += count
        if seen >= rank and count:
            return LATENCY_BOUNDS_MS[i] if i < len(LATENCY_BOUNDS_MS) else max_ms
    return max_ms


# ----------------------------------------------------------------------
# what one HTTP request learned on its way (set by the authenticator and the refusal paths)
# ----------------------------------------------------------------------

_REQUEST_MARKS: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("aics_stats_marks", default=None)


def begin_request() -> tuple[dict[str, Any], contextvars.Token]:
    """Start the marks of one HTTP request (the middleware); the dict is shared with the threads it runs in."""
    marks: dict[str, Any] = {}
    return marks, _REQUEST_MARKS.set(marks)


def end_request(token: contextvars.Token) -> None:
    _REQUEST_MARKS.reset(token)


def mark_signed(kind: str) -> None:
    """The request carried a verified signature: ``owner`` or ``agent-signed`` (no key is kept, only the class)."""
    marks = _REQUEST_MARKS.get()
    if marks is not None and kind in ("owner", "agent-signed"):
        if marks.get("signed") != "owner":
            marks["signed"] = kind


def mark_refusal(refusal: Any) -> None:
    """The answer is a refusal: noted as ``4xx-refused-with-leaf`` when it carries a ``refusal`` leaf."""
    marks = _REQUEST_MARKS.get()
    if marks is not None and getattr(refusal, "leaf", None) is not None:
        marks["refusal_leaf"] = True


# ----------------------------------------------------------------------
# the in-memory counters
# ----------------------------------------------------------------------


class StatsRecorder:
    """Per-day aggregate counters in memory, drained into the ``stats_*`` tables by the batched flush.

    Keys are ``(day, class, route_group, outcome)``, ``(day, route_group)`` and
    ``(day, event)``, all from closed lists; a value outside them raises
    ``ValueError`` (the middleware never lets that fail a request).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str, str, str], int] = {}
        #: (day, group) -> [bucket counts..., max_ms, total_ms]
        self._latency: dict[tuple[str, str], list[int]] = {}
        self._gate: dict[tuple[str, str], int] = {}

    def count_request(
        self, access: str, group: str, outcome: str, duration_ms: float | None = None, *, now: float | None = None
    ) -> None:
        if access not in _ACCESS or group not in _GROUPS or outcome not in _OUTCOMES:
            raise ValueError("stats keys are members of the closed lists")
        day = utc_day(now)
        with self._lock:
            key = (day, access, group, outcome)
            self._requests[key] = self._requests.get(key, 0) + 1
            if duration_ms is not None:
                ms = max(0, int(round(duration_ms)))
                row = self._latency.get((day, group))
                if row is None:
                    row = self._latency[(day, group)] = [0] * (len(LATENCY_BUCKETS) + 2)
                row[latency_bucket(ms)] += 1
                row[-2] = max(row[-2], ms)
                row[-1] += ms

    def count_gate(self, event: str, *, now: float | None = None) -> None:
        if event not in _EVENTS:
            raise ValueError(f"{event!r} is not a gate funnel event")
        key = (utc_day(now), event)
        with self._lock:
            self._gate[key] = self._gate.get(key, 0) + 1

    def drain(self) -> tuple[dict, dict, dict]:
        """Take everything counted so far (the flush writes it; :meth:`restore` puts it back if that fails)."""
        with self._lock:
            out = (self._requests, self._latency, self._gate)
            self._requests, self._latency, self._gate = {}, {}, {}
        return out

    def restore(self, drained: tuple[dict, dict, dict]) -> None:
        requests, latency, gate = drained
        with self._lock:
            for key, value in requests.items():
                self._requests[key] = self._requests.get(key, 0) + value
            for key, row in latency.items():
                mine = self._latency.get(key)
                if mine is None:
                    self._latency[key] = list(row)
                else:
                    merge_latency(mine, row)
            for key, value in gate.items():
                self._gate[key] = self._gate.get(key, 0) + value

    def snapshot(self) -> tuple[dict, dict, dict]:
        """Copies of what is not yet flushed (readers add it to the stored rows)."""
        with self._lock:
            return dict(self._requests), {k: list(v) for k, v in self._latency.items()}, dict(self._gate)


def merge_latency(into: list[int], row: Iterable[int]) -> None:
    """Add histogram *row* (bucket counts, max_ms, total_ms) into *into*."""
    row = list(row)
    for i in range(len(LATENCY_BUCKETS)):
        into[i] += row[i]
    into[-2] = max(into[-2], row[-2])
    into[-1] += row[-1]


def latency_summary(row: list[int]) -> dict[str, Any]:
    """The daily rollup of one route group's histogram: counts per bucket, p50/p95/p99 bounds, max and mean."""
    buckets = row[: len(LATENCY_BUCKETS)]
    samples = sum(buckets)
    max_ms = row[-2] if samples else None
    return {
        "samples": samples,
        "buckets": dict(zip(LATENCY_BUCKETS, buckets)),
        "p50_ms": percentile_bound(buckets, 0.50, max_ms),
        "p95_ms": percentile_bound(buckets, 0.95, max_ms),
        "p99_ms": percentile_bound(buckets, 0.99, max_ms),
        "max_ms": max_ms,
        "mean_ms": round(row[-1] / samples, 1) if samples else None,
    }


def write_drained(conn: Any, drained: tuple[Mapping, Mapping, Mapping]) -> None:
    """Add drained counts to the ``stats_*`` tables (inside the caller's transaction)."""
    requests, latency, gate = drained
    if requests:
        conn.executemany(
            """
            INSERT INTO stats_daily (day, class, route_group, outcome, count) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(day, class, route_group, outcome) DO UPDATE SET count = count + excluded.count
            """,
            [(*key, value) for key, value in sorted(requests.items())],
        )
    if latency:
        columns = ", ".join(LATENCY_BUCKETS)
        updates = ", ".join(f"{c} = {c} + excluded.{c}" for c in LATENCY_BUCKETS)
        conn.executemany(
            f"""
            INSERT INTO stats_latency_daily (day, route_group, {columns}, max_ms, total_ms)
            VALUES (?, ?, {", ".join("?" for _ in LATENCY_BUCKETS)}, ?, ?)
            ON CONFLICT(day, route_group) DO UPDATE SET {updates},
                max_ms = MAX(max_ms, excluded.max_ms), total_ms = total_ms + excluded.total_ms
            """,
            [(*key, *row) for key, row in sorted(latency.items())],
        )
    if gate:
        conn.executemany(
            """
            INSERT INTO stats_gate_daily (day, event, count) VALUES (?, ?, ?)
            ON CONFLICT(day, event) DO UPDATE SET count = count + excluded.count
            """,
            [(*key, value) for key, value in sorted(gate.items())],
        )


#: The tables (created with the rest of the schema, :meth:`aics_server.db.SanctuaryDB._init_schema`).  Additive: a
#: database of the same layout created before them gets them on its next start.  No column can hold an identifier.
SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS stats_daily (
    day TEXT NOT NULL,
    class TEXT NOT NULL,
    route_group TEXT NOT NULL,
    outcome TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, class, route_group, outcome)
);
CREATE TABLE IF NOT EXISTS stats_latency_daily (
    day TEXT NOT NULL,
    route_group TEXT NOT NULL,
    {", ".join(f"{c} INTEGER NOT NULL DEFAULT 0" for c in LATENCY_BUCKETS)},
    max_ms INTEGER NOT NULL DEFAULT 0,
    total_ms INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, route_group)
);
CREATE TABLE IF NOT EXISTS stats_gate_daily (
    day TEXT NOT NULL,
    event TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, event)
);
"""
