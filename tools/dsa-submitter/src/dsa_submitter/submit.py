"""The three commands: scan (read-only), submit, status.

Exit codes: 0 success or dormant, 1 any leaf failed or a run-level error
(API unreachable, unreadable decisions file, retryable submissions exhausted),
2 a payload-guard violation, which aborts the run before any further POST.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

from . import aics, guard, tdb
from . import decisions as decisions_module
from . import payload as payload_module
from . import state as state_module

DEFAULT_DECISIONS_PATH = "/etc/aics/dsa-decisions.jsonl"
DEFAULT_STATE_PATH = "/var/lib/aics-dsa/state.json"

TOKEN_ENV = "DSA_TRANSPARENCY_TOKEN"
URL_ENV = "DSA_TRANSPARENCY_URL"
ENV_FLAG_ENV = "DSA_TRANSPARENCY_ENV"


class GuardViolation(Exception):
    def __init__(self, problems):
        super().__init__("payload guard: " + "; ".join(problems))
        self.problems = problems


def log(message):
    print(f"[dsa-submitter] {message}", flush=True)


def _now():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _leaf_summary(restriction):
    """The restriction facts kept in the state file (no full hashes)."""
    return {
        "kind": restriction.kind,
        "reason_code": restriction.reason_code,
        "ts": restriction.ts,
        "target_index": restriction.target_index,
        "until": restriction.until,
        "content_date": restriction.content_date,
        "evidence_prefix": restriction.evidence_prefix,
        "receipt_prefix": restriction.receipt_prefix,
        "note": restriction.note,
    }


def _restriction_from_record(index, record):
    return aics.Restriction(leaf_index=index, **{
        key: record.get(key) for key in
        ("kind", "reason_code", "ts", "target_index", "content_date", "until",
         "evidence_prefix", "receipt_prefix", "note")
    })


def collect(api, state):
    """Fresh restrictions since the state's walk mark, merged with what the
    state already knows.  Returns ``(pending, fresh_restrictions, scan)``
    where ``pending`` is a list of :class:`aics.Restriction` for every leaf
    not yet submitted (new leaves are also added to ``state`` as pending).
    """
    scan = api.scan(scanned_from=state["entries_scanned"])
    for restriction in scan.restrictions:
        key = str(restriction.leaf_index)
        if key not in state["leaves"]:
            state["leaves"][key] = {
                "status": "pending",
                "reason": "needs operator input",
                "puid": payload_module.puid_for(restriction.leaf_index),
                **_leaf_summary(restriction),
            }
    pending = []
    for key, record in sorted(state["leaves"].items(), key=lambda item: int(item[0])):
        if record.get("status") == "submitted":
            continue
        pending.append(_restriction_from_record(int(key), record))
    return pending, scan.restrictions, scan


def cmd_scan(base_url, state_path):
    state = state_module.load(state_path)
    api = aics.AicsApi(base_url)
    pending, _, scan = collect(api, state)
    log(f"{base_url}: tree size {scan.tree_size}, walked from {state['entries_scanned']}")
    for restriction in pending:
        record = state["leaves"][str(restriction.leaf_index)]
        suffix = f" [{record.get('reason')}]" if record.get("reason") else ""
        log(f"pending: {aics.describe(restriction)}{suffix}")
    log(f"{len(pending)} pending restriction(s), not yet submitted")
    return 0


def cmd_submit(base_url, state_path, decisions_path, env=None):
    env = env if env is not None else os.environ
    decisions = decisions_module.load(decisions_path)
    if not decisions and not os.path.exists(decisions_path):
        log(f"no decisions file at {decisions_path}; every restriction will need "
            "operator input")
    state = state_module.load(state_path)
    api = aics.AicsApi(base_url)
    pending, _, scan = collect(api, state)

    token = env.get(TOKEN_ENV, "")
    if not token:
        if pending:
            log(f"dormant: no {TOKEN_ENV} in the environment; nothing is submitted")
        else:
            log(f"dormant: no pending restrictions and no {TOKEN_ENV}")
        for restriction in pending:
            decision = decisions.get(restriction.leaf_index)
            if decision is None:
                log(f"leaf {restriction.leaf_index}: needs operator input "
                    f"({aics.describe(restriction)})")
                continue
            try:
                statement = payload_module.build_statement(restriction, decision)
            except payload_module.PayloadError as exc:
                log(f"leaf {restriction.leaf_index}: {exc}")
                continue
            print(json.dumps(statement, indent=2, sort_keys=True, ensure_ascii=False),
                  flush=True)
        log("dormant: wrote nothing, remotely or locally")
        return 0

    url = tdb.resolve_url(env.get(URL_ENV), env.get(ENV_FLAG_ENV))
    client = tdb.TransparencyClient(url, token)
    log(f"submitting to {url} ({len(pending)} pending)")
    outcome_ok = True
    guard_violation = None
    for restriction in pending:
        key = str(restriction.leaf_index)
        record = state["leaves"][key]
        decision = decisions.get(restriction.leaf_index)
        if decision is None:
            record.update({"status": "pending", "reason": "needs operator input"})
            log(f"leaf {restriction.leaf_index}: needs operator input, not submitted")
            continue
        fingerprint = decisions_module.fingerprint(decision)
        if record.get("status") == "failed" and record.get("decisions_fingerprint") == fingerprint:
            earlier = f"HTTP {record['status_code']}" if record.get("status_code") else "local"
            log(f"leaf {restriction.leaf_index}: blocked by an earlier {earlier} error; "
                "the decisions record is unchanged, not retried")
            outcome_ok = False
            continue
        try:
            statement = payload_module.build_statement(restriction, decision)
        except payload_module.PayloadError as exc:
            record.update({"status": "failed", "error": str(exc),
                           "decisions_fingerprint": fingerprint})
            log(f"leaf {restriction.leaf_index}: NOT submitted: {exc}")
            outcome_ok = False
            continue

        problems = guard.check_payload(statement)
        if problems:
            guard_violation = GuardViolation(problems)
            log(f"leaf {restriction.leaf_index}: HARD GUARD VIOLATION, run aborts, "
                "nothing posted for this or any later leaf")
            for problem in problems:
                log(f"  {problem}")
            break

        try:
            result = client.submit(statement)
        except tdb.RetryableError as exc:
            record.update({"status": "pending", "reason": "retryable failure",
                           "last_error": str(exc)})
            log(f"leaf {restriction.leaf_index}: still pending after bounded retries: {exc}")
            outcome_ok = False
            continue
        except tdb.TdbError as exc:
            record.update({"status": "failed", "status_code": exc.status,
                           "error": str(exc), "decisions_fingerprint": fingerprint})
            log(f"leaf {restriction.leaf_index}: NOT submitted (HTTP {exc.status}); "
                "recorded, will retry only if the decisions record changes")
            outcome_ok = False
            continue

        record.update({
            "status": "submitted",
            "uuid": result.get("uuid"),
            "id": result.get("id"),
            "permalink": result.get("permalink"),
            "submitted_at": _now(),
            "duplicate": result.get("duplicate", False),
        })
        record.pop("reason", None)
        record.pop("last_error", None)
        duplicate = " (duplicate puid: already in the database)" if result.get("duplicate") else ""
        log(f"leaf {restriction.leaf_index}: submitted{duplicate}, "
            f"uuid={result.get('uuid')}")

    state["entries_scanned"] = scan.entries_scanned
    state_module.save(state_path, state)
    log(f"state saved to {state_path} (walked to {scan.entries_scanned})")

    if guard_violation is not None:
        raise guard_violation
    return 0 if outcome_ok else 1


def cmd_status(state_path):
    state = state_module.load(state_path)
    leaves = state["leaves"]
    log(f"state file {state_path}: walked to entry {state['entries_scanned']}, "
        f"{len(leaves)} restriction leaf(s) known")
    if not leaves:
        return 0
    for key in sorted(leaves, key=int):
        record = leaves[key]
        head = (f"leaf {key} {record.get('kind')} reason={record.get('reason_code')} "
                f"puid={record.get('puid')}")
        status = record.get("status")
        if status == "submitted":
            log(f"{head}: submitted uuid={record.get('uuid')} id={record.get('id')} "
                f"at={record.get('submitted_at')}"
                + (" [duplicate]" if record.get("duplicate") else ""))
        elif status == "failed":
            log(f"{head}: FAILED (HTTP {record.get('status_code')}) "
                f"error={record.get('error')}")
        else:
            log(f"{head}: pending"
                + (f" ({record.get('reason')})" if record.get("reason") else "")
                + (f" last_error={record.get('last_error')}" if record.get("last_error") else ""))
    return 0
