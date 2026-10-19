"""The document of ``GET /v2/admin/stats`` (owner login): requests, latency, the gate funnel, log activity,
health and witness status (docs/internal/owner-stats-design.md).

Aggregate figures only: counts per UTC day by closed-list classes
(:mod:`aics_server.stats`), counts derived from the public log, sizes,
durations and the state of the host.  No address, user agent, key, name,
session id or content is read into it, and no series is kept per key or per
name.  Everything that scans a table is read on a read-only SQLite connection
of its own (WAL lets it read while the writer writes), outside the writer
lock; the few health figures shared with ``/healthz`` are its constant-time
reads.  :class:`OwnerStats` caches the document for :data:`CACHE_SECONDS`.

The leaf table only grows (a leaf is never edited or removed), so the
all-time figures read from it are kept by :class:`LogTotals` up to a
``leaf_index`` high-water mark and each build adds only the newer leaves;
window figures are read through the ``(event_type, created_at)`` index.  The
tiles directory's size is walked in a background thread and the last value
read is served.
"""

from __future__ import annotations

import calendar
import json
import os
import platform
import sqlite3
import threading
import time
from importlib import metadata
from pathlib import Path
from typing import Any

import psutil

from . import stats as st
from .db import SCHEMA_VERSION, SanctuaryDB
from .telemetry import host_metrics

#: The document is computed at most this often (an owner dashboard refreshes every 30 s).
CACHE_SECONDS = 10.0
#: ``days`` defaults and bounds of the endpoint.
DEFAULT_DAYS = 30
MAX_DAYS = 366
#: The tiles directory is walked for its size at most this often (in a background thread).
TILES_BYTES_CACHE_SECONDS = 300.0
#: Before the first walk finished, a build waits this long for it (a small directory is read at once).
TILES_FIRST_WAIT_SECONDS = 0.5

#: Name tiers as the page names them: a key the agent holds, a key a third-party generator made, the shared secret.
TIER_NAMES = {"verified": "key", "third-party-generated": "third-party", "unverified": "secret"}
#: Purposes of ``sup.spend`` (AICS-1 section 20.3) and sources of ``sup.credit``.
SPEND_PURPOSES = ("owner_action", "hosting", "storage")


def _day_range(days: int, now: float) -> list[str]:
    today = int(now) // 86400
    return [st.utc_day((today - i) * 86400) for i in range(days - 1, -1, -1)]


def _zero(keys: tuple[str, ...] | list[str]) -> dict[str, int]:
    return dict.fromkeys(keys, 0)


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def dir_bytes(path: str | Path) -> int:
    """Bytes of the regular files under *path* (the tiles directory's size)."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.stat(os.path.join(root, name)).st_size
            except OSError:
                continue
    return total


class LogTotals:
    """All-time aggregates of the append-only leaf table, kept up to a ``leaf_index`` high-water mark.

    :meth:`refresh` adds the leaves committed since the last call, so the
    cost of a build follows the leaves written since the previous one, not
    the size of the log.  Only closed-list codes, counts and SUP amounts are
    kept; a per-day count of names claimed by tier is kept for the window.
    If the table is ever shorter than the mark (another database), the
    totals start again from leaf 0.
    """

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.next_index = 0
        self.by_type: dict[str, int] = {}
        #: Leaves per UTC day and type (a few dozen types a day): the window's daily figures without a scan.
        self.daily_types: dict[str, dict[str, int]] = {}
        self.rotate_upgrades = 0
        self.notice_outcomes: dict[str, int] = {}
        self.credits = {s: [0, 0] for s in ("contribution", "task")}
        self.spends = {p: [0, 0] for p in SPEND_PURPOSES}
        self.claims_daily: dict[str, dict[str, int]] = {}

    def refresh(self, conn: sqlite3.Connection) -> None:
        """Add the leaves after the mark; *conn* is inside a read transaction (one snapshot for the whole build)."""
        top = conn.execute("SELECT MAX(leaf_index) FROM tlog_leaves").fetchone()[0]
        top = -1 if top is None else int(top)
        if top < self.next_index - 1:
            self.reset()
        lo, hi = self.next_index, top
        if lo <= hi:
            try:
                self._add(conn, lo, hi)
            except BaseException:
                self.reset()  # a partial add would count some leaves twice next time: start again from leaf 0
                raise
        self.next_index = hi + 1

    def _add(self, conn: sqlite3.Connection, lo: int, hi: int) -> None:
        span = (lo, hi)
        # A span shorter than what is already counted is read by leaf_index (``+event_type`` keeps SQLite off the
        # type index, whose entries of one type grow with the log); a first or a long read goes by type.
        et = "+event_type" if hi - lo < lo else "event_type"
        for day, typ, count in conn.execute(
            "SELECT substr(created_at, 1, 10), event_type, COUNT(*) FROM tlog_leaves WHERE leaf_index BETWEEN ? AND ? "
            "GROUP BY 1, 2",
            span,
        ):
            self.by_type[typ] = self.by_type.get(typ, 0) + int(count)
            per_day = self.daily_types.setdefault(day, {})
            per_day[typ] = per_day.get(typ, 0) + int(count)
        self.rotate_upgrades += int(
            conn.execute(
                f"SELECT COUNT(*) FROM tlog_leaves WHERE {et} = 'key.rotate' AND leaf_index BETWEEN ? AND ? "
                "AND json_extract(leaf_json, '$.payload.mode') = 'upgrade'",
                span,
            ).fetchone()[0]
        )
        for outcome, count in conn.execute(
            f"""
            SELECT json_extract(leaf_json, '$.payload.outcome_code'), COUNT(*) FROM tlog_leaves
            WHERE {et} = 'report' AND leaf_index BETWEEN ? AND ?
              AND json_extract(leaf_json, '$.payload.kind') = 'notice' GROUP BY 1
            """,
            span,
        ):
            if isinstance(outcome, str):
                self.notice_outcomes[outcome] = self.notice_outcomes.get(outcome, 0) + int(count)
        for typ, field, out in (("sup.credit", "source", self.credits), ("sup.spend", "purpose", self.spends)):
            for key, count, amount in conn.execute(
                f"SELECT json_extract(leaf_json, '$.payload.{field}'), COUNT(*), "
                "COALESCE(SUM(json_extract(leaf_json, '$.payload.amount')), 0) FROM tlog_leaves "
                f"WHERE {et} = ? AND leaf_index BETWEEN ? AND ? GROUP BY 1",
                (typ, lo, hi),
            ):
                if key in out:
                    out[key][0] += int(count)
                    out[key][1] += int(amount or 0)
        for tier, day, count in conn.execute(
            """
            SELECT e.tier_after, substr(l.created_at, 1, 10), COUNT(*) FROM key_events e
            CROSS JOIN tlog_leaves l ON l.leaf_index = e.leaf_index
            WHERE e.event_type = 'name.claim' AND e.leaf_index BETWEEN ? AND ? GROUP BY 1, 2
            """,
            span,
        ):
            label = TIER_NAMES.get(tier)
            if label is not None:
                per_day = self.claims_daily.setdefault(day, {})
                per_day[label] = per_day.get(label, 0) + int(count)

    def rotate_modes(self) -> dict[str, int]:
        rotations = self.by_type.get("key.rotate", 0)
        return {"rotate": rotations - self.rotate_upgrades, "upgrade": self.rotate_upgrades}

    @staticmethod
    def _amounts(out: dict[str, list[int]]) -> dict[str, dict[str, int]]:
        return {k: {"count": v[0], "sup": v[1]} for k, v in out.items()}

    def credit_totals(self) -> dict[str, dict[str, int]]:
        return self._amounts(self.credits)

    def spend_totals(self) -> dict[str, dict[str, int]]:
        return self._amounts(self.spends)


class OwnerStats:
    """Builds and caches the owner stats document for one app (its database, gate and card)."""

    def __init__(self, db: SanctuaryDB, *, gate: Any = None, card: Any = None, site: Any = None, api_version: str | None = None) -> None:
        self.db = db
        self.gate = gate
        self.card = card
        self.site = site
        self.api_version = api_version
        self._lock = threading.Lock()
        self._cache: dict[int, tuple[float, dict[str, Any]]] = {}
        self._totals = LogTotals()
        self._tiles_lock = threading.Lock()
        self._tiles_bytes: tuple[float, int | None] | None = None
        self._tiles_walk: threading.Thread | None = None
        self._cert: tuple[tuple[str, int, int], dict[str, Any]] | None = None

    # -- the endpoint's entry ----------------------------------------------------------

    def document(self, days: int = DEFAULT_DAYS) -> dict[str, Any]:
        """The stats document for the last *days* UTC days (today included), from a cache at most 10 s old."""
        if not 1 <= days <= MAX_DAYS:
            raise ValueError(f"days is 1 to {MAX_DAYS}")
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(days)
            if cached is not None and now - cached[0] < CACHE_SECONDS:
                return cached[1]
            doc = self._build(days)
            self._cache = {k: v for k, v in self._cache.items() if now - v[0] < CACHE_SECONDS}
            self._cache[days] = (now, doc)
            return doc

    def _build(self, days: int) -> dict[str, Any]:
        now = time.time()
        window = _day_range(days, now)
        conn = sqlite3.connect(f"file:{self.db.db_path.resolve()}?mode=ro", uri=True, timeout=5, isolation_level=None)
        try:
            # The stats_* rollups first, each read in its own statement right after the in-memory snapshot (as
            # before the flush drains it); then one read snapshot in which the log's all-time totals, its window
            # figures and its projections agree.
            requests_doc, latency_doc, gate_rows = self._rollups(conn, window)
            conn.execute("BEGIN")
            self._totals.refresh(conn)
            return {
                "generated_at": _iso(now),
                "days": days,
                "window": {"from": window[0], "to": window[-1]},
                "lists": {
                    "access_classes": list(st.ACCESS_CLASSES),
                    "route_groups": list(st.ROUTE_GROUPS),
                    "outcomes": list(st.OUTCOMES),
                    "latency_bounds_ms": list(st.LATENCY_BOUNDS_MS),
                    "latency_buckets": list(st.LATENCY_BUCKETS),
                    "gate_events": list(st.GATE_EVENTS),
                },
                "requests": requests_doc,
                "latency": latency_doc,
                "gate": self._gate_doc(gate_rows, window),
                "activity": self._activity(conn, window, now),
                "health": self._health(conn, now),
                "witness": self._witness(),
                "pages_host": getattr(self.site, "pages_host", None),
            }
        finally:
            conn.close()

    # -- the stats_* rollups plus what is still in memory -------------------------------------

    def _rollups(self, conn: sqlite3.Connection, window: list[str]) -> tuple[dict, dict, dict]:
        first = window[0]
        in_window = set(window)
        mem_requests, mem_latency, mem_gate = self.db.stats.snapshot()

        requests: dict[tuple[str, str, str, str], int] = {}
        for day, cls, group, outcome, count in conn.execute(
            "SELECT day, class, route_group, outcome, count FROM stats_daily WHERE day >= ?", (first,)
        ):
            requests[(day, cls, group, outcome)] = requests.get((day, cls, group, outcome), 0) + int(count)
        for key, value in mem_requests.items():
            if key[0] in in_window:
                requests[key] = requests.get(key, 0) + value

        latency: dict[tuple[str, str], list[int]] = {}
        columns = ", ".join(st.LATENCY_BUCKETS)
        for row in conn.execute(
            f"SELECT day, route_group, {columns}, max_ms, total_ms FROM stats_latency_daily WHERE day >= ?", (first,)
        ):
            latency[(row[0], row[1])] = [int(v) for v in row[2:]]
        for key, row in mem_latency.items():
            if key[0] not in in_window:
                continue
            if key in latency:
                st.merge_latency(latency[key], row)
            else:
                latency[key] = list(row)

        gate: dict[tuple[str, str], int] = {}
        for day, event, count in conn.execute("SELECT day, event, count FROM stats_gate_daily WHERE day >= ?", (first,)):
            gate[(day, event)] = gate.get((day, event), 0) + int(count)
        for key, value in mem_gate.items():
            if key[0] in in_window:
                gate[key] = gate.get(key, 0) + value

        # requests: per day by class, group and outcome; window totals; group x outcome and class x outcome
        daily = []
        for day in window:
            daily.append(
                {
                    "day": day,
                    "total": 0,
                    "by_class": _zero(st.ACCESS_CLASSES),
                    "by_group": _zero(st.ROUTE_GROUPS),
                    "by_outcome": _zero(st.OUTCOMES),
                }
            )
        index = {d["day"]: d for d in daily}
        group_outcome = {g: _zero(st.OUTCOMES) for g in st.ROUTE_GROUPS}
        class_outcome = {c: _zero(st.OUTCOMES) for c in st.ACCESS_CLASSES}
        class_group = {c: _zero(st.ROUTE_GROUPS) for c in st.ACCESS_CLASSES}
        totals = {"total": 0, "by_class": _zero(st.ACCESS_CLASSES), "by_group": _zero(st.ROUTE_GROUPS), "by_outcome": _zero(st.OUTCOMES)}
        rows = []
        for (day, cls, group, outcome), count in sorted(requests.items()):
            if day not in index or cls not in class_outcome or group not in group_outcome or outcome not in totals["by_outcome"]:
                continue  # never trust a stored key outside the closed lists
            d = index[day]
            d["total"] += count
            d["by_class"][cls] += count
            d["by_group"][group] += count
            d["by_outcome"][outcome] += count
            group_outcome[group][outcome] += count
            class_outcome[cls][outcome] += count
            class_group[cls][group] += count
            totals["total"] += count
            totals["by_class"][cls] += count
            totals["by_group"][group] += count
            totals["by_outcome"][outcome] += count
            rows.append({"day": day, "class": cls, "route_group": group, "outcome": outcome, "count": count})
        requests_doc = {
            "daily": daily,
            "totals": totals,
            "by_group_outcome": group_outcome,
            "by_class_outcome": class_outcome,
            "by_class_group": class_group,
            "rows": rows,
        }

        # latency: per day and group, and the window's histogram per group
        empty = [0] * (len(st.LATENCY_BUCKETS) + 2)
        latency_daily = []
        whole = {g: list(empty) for g in st.ROUTE_GROUPS}
        for day in window:
            groups = {}
            for group in st.ROUTE_GROUPS:
                row = latency.get((day, group))
                if row is None:
                    continue
                groups[group] = st.latency_summary(row)
                st.merge_latency(whole[group], row)
            latency_daily.append({"day": day, "groups": groups})
        latency_doc = {
            "bounds_ms": list(st.LATENCY_BOUNDS_MS),
            "daily": latency_daily,
            "window": {g: st.latency_summary(row) for g, row in whole.items() if sum(row[: len(st.LATENCY_BUCKETS)])},
        }
        return requests_doc, latency_doc, gate

    def _gate_doc(self, gate: dict[tuple[str, str], int], window: list[str]) -> dict[str, Any]:
        def shape(counts: dict[str, int]) -> dict[str, Any]:
            sessions = {t: counts.get(f"session.{t}", 0) for t in ("https", "tcp-tls", "tcp-plain")}
            return {
                "sessions_opened": {**sessions, "total": sum(sessions.values())},
                "help": counts.get("help", 0),
                "tools": {t: counts.get(f"tools.{t}", 0) for t in ("openssl", "ssh-keygen", "python3", "none")},
                "claims": {t: counts.get(f"claim.{t}", 0) for t in ("key", "third-party", "secret")},
                "upgrades": counts.get("upgrade", 0),
                "ended_malformed": counts.get("end.malformed", 0),
                "idle_expired": counts.get("end.idle", 0),
            }

        daily, total = [], dict.fromkeys(st.GATE_EVENTS, 0)
        for day in window:
            counts = {e: gate.get((day, e), 0) for e in st.GATE_EVENTS}
            for e, v in counts.items():
                total[e] += v
            daily.append({"day": day, **shape(counts)})
        doc: dict[str, Any] = {"daily": daily, "totals": shape(total), "sessions_open": None, "max_sessions": None}
        if self.gate is not None:
            try:
                doc["sessions_open"] = self.gate.sweep()
                doc["max_sessions"] = self.gate.limits.max_sessions
            except Exception:  # pragma: no cover
                pass
        return doc

    # -- activity, from the log and its projections -------------------------------------------

    def _activity(self, conn: sqlite3.Connection, window: list[str], now: float) -> dict[str, Any]:
        first_iso = f"{window[0]}T00:00:00Z"
        one = lambda sql, *args: conn.execute(sql, args).fetchone()[0]  # noqa: E731

        # leaves per type per day (window) and all time
        totals = self._totals
        by_day = {day: dict(totals.daily_types.get(day, {})) for day in window}
        window_types: dict[str, int] = {}
        for counts in by_day.values():
            for typ, count in counts.items():
                window_types[typ] = window_types.get(typ, 0) + count
        all_time = dict(totals.by_type)
        rotate_modes = totals.rotate_modes()
        window_upgrades = one(
            "SELECT COUNT(*) FROM tlog_leaves WHERE event_type = 'key.rotate' AND created_at >= ? "
            "AND json_extract(leaf_json, '$.payload.mode') = 'upgrade'",
            first_iso,
        )
        leaves = {
            "daily": [{"day": day, "total": sum(c.values()), "by_type": dict(sorted(c.items()))} for day, c in by_day.items()],
            "window": dict(sorted(window_types.items())),
            "all_time": dict(sorted(all_time.items())),
            "tree_size": sum(all_time.values()),
        }

        # refusals per code per day: the daily report leaves; days without one yet (today) counted live
        live: dict[str, dict[str, int]] = {day: {} for day in window}
        for day, code, count in conn.execute(
            """
            SELECT substr(created_at, 1, 10), json_extract(leaf_json, '$.payload.reason_code'), COUNT(*)
            FROM tlog_leaves WHERE event_type = 'refusal' AND created_at >= ? GROUP BY 1, 2
            """,
            (first_iso,),
        ):
            if day in live and isinstance(code, str):
                live[day][code] = int(count)
        reports: dict[str, tuple[int, dict[str, int]]] = {}
        first_number = calendar.timegm(time.strptime(window[0], "%Y-%m-%d")) // 86400  # daily_reports.day: UTC day number
        for day_number, leaf_index, leaf_json in conn.execute(
            """
            SELECT d.day, d.leaf_index, l.leaf_json FROM daily_reports d JOIN tlog_leaves l ON l.leaf_index = d.leaf_index
            WHERE d.day >= ?
            """,
            (first_number,),
        ):
            try:
                counts = json.loads(leaf_json)["payload"]["counts"]
                reports[st.utc_day(int(day_number) * 86400)] = (
                    int(leaf_index),
                    {c["reason_code"]: int(c["count"]) for c in counts if c.get("count")},
                )
            except (ValueError, KeyError, TypeError):
                continue
        refusal_daily, refusal_totals = [], {}
        for day in window:
            if day in reports:
                index, counts = reports[day]
                entry = {"day": day, "source": "report", "report_index": index}
            else:
                counts = live[day]
                entry = {"day": day, "source": "live", "report_index": None}
            counts = dict(sorted(counts.items()))
            for code, count in counts.items():
                refusal_totals[code] = refusal_totals.get(code, 0) + count
            refusal_daily.append({**entry, "total": sum(counts.values()), "by_code": counts})
        refusals = {"daily": refusal_daily, "window": dict(sorted(refusal_totals.items()))}

        # names: claimed by tier (all time and per day in the window), current names by tier, revoked
        claimed = _zero(tuple(TIER_NAMES.values()))
        claimed_daily = {day: _zero(tuple(TIER_NAMES.values())) for day in window}
        for day, counts in totals.claims_daily.items():
            for label, count in counts.items():
                claimed[label] += count
                if day in claimed_daily:
                    claimed_daily[day][label] += count
        current = {**_zero(tuple(TIER_NAMES.values())), "revoked": 0}
        for tier, revoked, count in conn.execute(
            """
            SELECT e.tier_after, e.revoked, COUNT(*) FROM key_events e
            WHERE e.leaf_index = (SELECT MAX(leaf_index) FROM key_events WHERE name_norm = e.name_norm)
            GROUP BY 1, 2
            """
        ):
            if revoked:
                current["revoked"] += int(count)
            elif tier in TIER_NAMES:
                current[TIER_NAMES[tier]] += int(count)
        names = {
            "total": one("SELECT COUNT(*) FROM names"),
            "claimed_by_tier": claimed,
            "claimed_daily": [{"day": day, **c} for day, c in claimed_daily.items()],
            "current_by_tier": current,
        }

        keys_doc = {
            "window": {
                "rotations": window_types.get("key.rotate", 0) - window_upgrades,
                "upgrades": window_upgrades,
                "x25519_rotations": window_types.get("x25519.rotate", 0),
                "revocations": window_types.get("key.revoke", 0),
            },
            "all_time": {
                "rotations": rotate_modes["rotate"],
                "upgrades": rotate_modes["upgrade"],
                "x25519_rotations": all_time.get("x25519.rotate", 0),
                "revocations": all_time.get("key.revoke", 0),
            },
        }

        swarms = {
            "enabled": bool(getattr(self.db, "swarms", None) is not None and getattr(self.db.swarms, "requested", False)),
            "window": {t: window_types.get(t, 0) for t in ("swarm.form", "swarm.join", "swarm.leave", "swarm.broadcast", "agent.introduce")},
            "all_time": {t: all_time.get(t, 0) for t in ("swarm.form", "swarm.join", "swarm.leave", "swarm.broadcast", "agent.introduce")},
            "active_swarms": None,
            "members_in_swarms": None,
        }
        swarms.update(self._swarm_state())

        messages = {
            "dm_leaves": {"window": window_types.get("dm", 0), "all_time": all_time.get("dm", 0)},
            "grant_leaves": {"window": window_types.get("grant", 0), "all_time": all_time.get("grant", 0)},
            "bodies_stored": one("SELECT COUNT(*) FROM messages WHERE ciphertext IS NOT NULL"),
            "bodies_expired": one("SELECT COUNT(*) FROM messages WHERE expired_policy_index IS NOT NULL"),
        }
        capsules = {
            "capsule_leaves": {"window": window_types.get("capsule", 0), "all_time": all_time.get("capsule", 0)},
            "slots": one("SELECT COUNT(*) FROM capsules"),
            "bodies_stored": one("SELECT COUNT(*) FROM capsule_leaves WHERE ciphertext IS NOT NULL"),
        }

        hidden: dict[str, int] = {}
        for reason, count in conn.execute("SELECT reason_code, COUNT(*) FROM tombstones GROUP BY 1"):
            hidden[reason] = int(count)
        hidden_doc = {
            "total": sum(hidden.values()),
            "by_reason": dict(sorted(hidden.items())),
            "erased": one("SELECT COUNT(*) FROM tombstones WHERE erased_at IS NOT NULL"),
            "window": window_types.get("tombstone", 0),
        }

        closed_by_outcome = dict(totals.notice_outcomes)
        open_row = conn.execute(
            """
            SELECT COUNT(*), COALESCE(SUM(
                length(CAST(location AS BLOB)) + length(CAST(explanation AS BLOB))
                + COALESCE(length(CAST(notifier_name AS BLOB)), 0) + COALESCE(length(CAST(notifier_email AS BLOB)), 0)
                + COALESCE(length(CAST(cites_report_id AS BLOB)), 0)), 0)
            FROM notices WHERE closed_at IS NULL
            """
        ).fetchone()
        first_ts = int(now) // 86400 * 86400 - (len(window) - 1) * 86400
        notices = {
            "open": int(open_row[0]),
            "open_bytes": int(open_row[1]),
            "max_open": self.db.limits.get("open_notices"),
            "max_open_bytes": self.db.limits.get("open_notice_bytes"),
            "closed": sum(closed_by_outcome.values()),
            "closed_by_outcome": dict(sorted(closed_by_outcome.items())),
            "received_in_window": one("SELECT COUNT(*) FROM notices WHERE received_at >= ?", first_ts),
        }

        latest_freeze = conn.execute("SELECT freeze_index, state, reason_code FROM freezes ORDER BY freeze_index DESC LIMIT 1").fetchone()
        freeze = {
            "state": "frozen" if getattr(self.db, "_frozen_index", None) is not None else "open",
            "freeze_index": latest_freeze[0] if latest_freeze else None,
            "reason_code": latest_freeze[2] if latest_freeze else None,
            "freeze_leaves": all_time.get("freeze", 0),
            "suspension_leaves": all_time.get("suspension", 0),
        }

        return {
            "leaves": leaves,
            "refusals": refusals,
            "names": names,
            "keys": keys_doc,
            "swarms": swarms,
            "messages": messages,
            "capsules": capsules,
            "hidden_bodies": hidden_doc,
            "notices": notices,
            "freeze": freeze,
            "sup": self._sup(conn, first_iso, all_time),
        }

    def _swarm_state(self) -> dict[str, Any]:
        """Swarms with members and the members in one, from the swarm replay as of its last update (no lock)."""
        store = getattr(self.db, "swarms", None)
        state = getattr(store, "_state", None) if store is not None else None
        if state is None:
            return {}
        for _ in range(3):  # the writer may extend the replay while it is read; a retry sees a settled copy
            try:
                members = [m for m in list(state.members.values()) if m.get("swarm_id")]
                live = {m["swarm_id"] for m in members}
                swarms = [s for s in list(state.swarms.values()) if not s.get("retired")]
                return {"active_swarms": len([s for s in swarms if s["swarm_id"] in live]), "members_in_swarms": len(members)}
            except RuntimeError:
                continue
        return {}

    def _sup(self, conn: sqlite3.Connection, first_iso: str, all_time: dict[str, int]) -> dict[str, Any]:
        """Contributions, awards and spends (AICS-1+SUP-1), aggregate counts and SUP amounts only."""

        def window(typ: str, field: str, keys: tuple[str, ...]) -> dict[str, dict[str, int]]:
            # the window's leaves of one type, through the (event_type, created_at) index
            out = {k: {"count": 0, "sup": 0} for k in keys}
            for key, count, amount in conn.execute(
                f"SELECT json_extract(leaf_json, '$.payload.{field}'), COUNT(*), "
                "COALESCE(SUM(json_extract(leaf_json, '$.payload.amount')), 0) FROM tlog_leaves "
                "WHERE event_type = ? AND created_at >= ? GROUP BY 1",
                (typ, first_iso),
            ):
                if key in out:
                    out[key] = {"count": int(count), "sup": int(amount or 0)}
            return out

        try:
            contributions_open = bool(self.db.contribution_networks())
        except Exception:  # pragma: no cover
            contributions_open = False
        active = contributions_open or any(all_time.get(t, 0) for t in ("sup.task", "sup.credit", "sup.spend"))
        return {
            "profile": "AICS-1+SUP-1",
            "active": active,
            "contributions_open": contributions_open,
            "credits": {
                "window": window("sup.credit", "source", ("contribution", "task")),
                "all_time": self._totals.credit_totals(),
            },
            "spends": {"window": window("sup.spend", "purpose", SPEND_PURPOSES), "all_time": self._totals.spend_totals()},
            "tasks_published": all_time.get("sup.task", 0),
            "tasks_open": conn.execute(
                "SELECT COUNT(*) FROM sup_tasks t WHERE t.closes > ? AND "
                "(SELECT COUNT(*) FROM sup_awards a WHERE a.task_index = t.task_index) < t.max_awards",
                (int(time.time()),),
            ).fetchone()[0],
            "balance_outstanding": conn.execute("SELECT COALESCE(SUM(delta), 0) FROM sup_ledger").fetchone()[0],
        }

    # -- health -------------------------------------------------------------------------------

    def _health(self, conn: sqlite3.Connection, now: float) -> dict[str, Any]:
        healthz = self.db.health()  # /healthz's constant-time reads
        tiles = self.db._log.status()
        log = self.db._log
        host = host_metrics(self.db)
        try:
            host["disk_free_bytes"] = psutil.disk_usage(str(self.db.db_path.parent)).free
        except (psutil.Error, OSError):
            host["disk_free_bytes"] = None
        checkpoint_at = log.checkpoint_written_at
        tiles_at = log.tiles_written_at
        limits = self.db.limits
        budgets: dict[str, Any] = {
            "ciphertext": {
                "used_bytes": getattr(self.db, "_ciphertext_total", None),
                "budget_bytes": limits.get("ciphertext_budget_bytes"),
            },
            "disk": {"used_percent": host.get("disk_used_percent"), "free_bytes": host.get("disk_free_bytes")},
        }
        if self.gate is not None:
            budgets["gate_staged"] = {"used_bytes": getattr(self.gate, "_staged", None), "limit_bytes": self.gate.limits.staged_bytes}
        return {
            "status": healthz["status"],
            "healthz": healthz,
            "usage": self.db.get_db_counts(),  # the counts of /v2/stats
            "host": host,
            "tiles": tiles,
            "tiles_bytes": self._tiles_size(),
            "checkpoint_age_seconds": int(now - checkpoint_at) if checkpoint_at is not None else None,
            "seconds_since_tile_write": int(now - tiles_at) if tiles_at is not None else None,
            "tls_certificate": self._certificate(now),
            "uptime_seconds": max(0, int(now - self.db.started_at)),
            "started_at": _iso(self.db.started_at),
            "schema_version": SCHEMA_VERSION,
            "versions": self._versions(),
            "budgets": budgets,
        }

    def _tiles_size(self) -> int | None:
        """The tiles directory's size from the last background walk; a stale value starts a new walk.

        The walk never runs in the owner request: before the first one
        finished, a build waits at most :data:`TILES_FIRST_WAIT_SECONDS`
        for it and otherwise answers ``None``.
        """
        now = time.monotonic()
        with self._tiles_lock:
            cached = self._tiles_bytes
            if (cached is None or now - cached[0] >= TILES_BYTES_CACHE_SECONDS) and self._tiles_walk is None:
                self._tiles_walk = threading.Thread(target=self._walk_tiles, name="aics-owner-stats-tiles", daemon=True)
                self._tiles_walk.start()
            walk = self._tiles_walk
        if cached is None and walk is not None:
            walk.join(TILES_FIRST_WAIT_SECONDS)
            cached = self._tiles_bytes
        return cached[1] if cached is not None else None

    def _walk_tiles(self) -> None:
        total: int | None = None
        try:
            total = dir_bytes(self.db.tiles_dir)
        except Exception:  # pragma: no cover
            total = None
        finally:
            with self._tiles_lock:
                self._tiles_bytes = (time.monotonic(), total)
                self._tiles_walk = None

    def _certificate(self, now: float) -> dict[str, Any]:
        """The TLS gate certificate's expiry (``AICS_GATE_TLS_CERT``), or ``configured: false``."""
        path = os.environ.get("AICS_GATE_TLS_CERT", "").strip()
        if not path:
            return {"configured": False, "not_after": None, "seconds_left": None, "error": None}
        try:
            info = os.stat(path)
            stamp = (path, info.st_mtime_ns, info.st_size)
            if self._cert is None or self._cert[0] != stamp:
                from cryptography import x509

                certs = x509.load_pem_x509_certificates(Path(path).read_bytes())
                not_after = certs[0].not_valid_after_utc.timestamp()
                self._cert = (stamp, {"not_after_ts": not_after})
            not_after = self._cert[1]["not_after_ts"]
            return {"configured": True, "not_after": _iso(not_after), "seconds_left": int(not_after - now), "error": None}
        except Exception as exc:
            return {"configured": True, "not_after": None, "seconds_left": None, "error": type(exc).__name__}

    def _versions(self) -> dict[str, Any]:
        out: dict[str, Any] = {"api": self.api_version, "python": platform.python_version()}
        for package in ("aics-server", "aics-identity", "aics-tlog"):
            try:
                out[package] = metadata.version(package)
            except metadata.PackageNotFoundError:
                out[package] = None
        return out

    # -- witness --------------------------------------------------------------------------------

    def _witness(self) -> dict[str, Any]:
        """The served card's witness policy and the cosignatures on the published checkpoint that verify under it."""
        from aics_tlog import parse_note, parse_vkey, verify_checkpoint

        policy = {"quorum": 0, "witnesses": []}
        if self.card is not None:
            try:
                policy = self.card.current().card.get("witness_policy") or policy
            except Exception:  # pragma: no cover
                pass
        witnesses = policy.get("witnesses") or []
        quorum = int(policy.get("quorum") or 0)
        published = self.db._log.published
        doc: dict[str, Any] = {
            "quorum": quorum,
            "witnesses": [{"name": w.get("name"), "independent": w.get("independent")} for w in witnesses if isinstance(w, dict)],
            "checkpoint_size": published.size if published is not None else None,
            "cosignatures": 0,
            "cosigned_by": [],
            "quorum_met": False,
            "state": "no_witness",
            "g5": "promised",
            "error": None,
        }
        if not witnesses:
            return doc
        if published is None:
            doc["state"] = "no_checkpoint"
            return doc
        try:
            keys = [parse_vkey(w["vkey"]) for w in witnesses]
            result = verify_checkpoint(parse_note(published.note), self.db._log.vkey, keys, quorum, expected_origin=self.db.origin)
            doc["cosignatures"] = result.cosignature_count
            doc["cosigned_by"] = list(result.witnesses)
            doc["quorum_met"] = bool(quorum > 0 and result.cosignature_count >= quorum)
            doc["error"] = result.error
        except Exception as exc:
            doc["error"] = type(exc).__name__
        doc["state"] = "quorum_met" if doc["quorum_met"] else "quorum_not_met"
        return doc
