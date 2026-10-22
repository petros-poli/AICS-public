"""Groups F, G, H, I, J, K, M and the abort half of L: the submit command."""

import json
import os
import re
from pathlib import Path

import pytest
from conftest import (
    LEAF_TOMBSTONE_ILLEGAL,
    RESTRICTION_LEAVES,
    TOKEN,
    TREE_SIZE,
    all_decisions,
    illegal_decision,
)

import dsa_submitter.payload as payload_module
from dsa_submitter import cli, submit
from dsa_submitter import state as state_module

SUBMITTED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _run(fake_aics, state_path, decisions, env):
    return submit.cmd_submit(fake_aics.url, state_path, decisions, env=env)


# --- F: dormant mode -------------------------------------------------------

def test_dormant_mode_prints_and_writes_nothing(fake_aics, fake_tdb, decisions_file,
                                                state_path, capsys):
    decisions = decisions_file(
        {LEAF_TOMBSTONE_ILLEGAL: illegal_decision(LEAF_TOMBSTONE_ILLEGAL)})
    rc = _run(fake_aics, state_path, decisions, env={})
    out = capsys.readouterr().out
    assert rc == 0
    assert "dormant" in out
    # The one leaf with a decision gets its would-be statement printed as JSON.
    assert '"puid": "aics-leaf-2"' in out
    assert '"decision_visibility"' in out
    assert '"DECISION_VISIBILITY_CONTENT_DISABLED"' in out
    # The others are listed as needing operator input.
    assert "needs operator input" in out
    assert fake_tdb.request_count == 0
    assert not os.path.exists(state_path)


# --- G: the real happy path ------------------------------------------------

def test_submit_happy_path(fake_aics, fake_tdb, tdb_env, decisions_file, state_path):
    decisions = decisions_file(all_decisions())
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 0
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)
    assert {statement["puid"] for statement in fake_tdb.statements} == {
        f"aics-leaf-{index}" for index in RESTRICTION_LEAVES}

    state_now = state_module.load(state_path)
    assert state_now["entries_scanned"] == TREE_SIZE
    for index in RESTRICTION_LEAVES:
        record = state_now["leaves"][str(index)]
        assert record["status"] == "submitted", index
        assert record["uuid"] == "uuid-1"
        assert record["id"] == 123
        assert record["permalink"].startswith("https://statement.example/")
        assert SUBMITTED_AT.fullmatch(record["submitted_at"])
    # The token lives only in the Authorization header: never the state file,
    # never a posted body.
    assert TOKEN not in json.dumps(state_now)
    for statement in fake_tdb.statements:
        assert TOKEN not in json.dumps(statement)
    for headers in fake_tdb.headers_seen:
        assert headers["Authorization"] == f"Bearer {TOKEN}"


# --- H: idempotency --------------------------------------------------------

def test_second_run_posts_nothing(fake_aics, fake_tdb, tdb_env, decisions_file,
                                  state_path):
    decisions = decisions_file(all_decisions())
    assert _run(fake_aics, state_path, decisions, env=dict(tdb_env)) == 0
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)
    assert _run(fake_aics, state_path, decisions, env=dict(tdb_env)) == 0
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)


# --- I: crash recovery through the database's own duplicate answer ---------

def test_crash_recovery_via_duplicate_puid(fake_aics, fake_tdb, tdb_env,
                                           decisions_file, state_path):
    decisions = decisions_file(all_decisions())
    assert _run(fake_aics, state_path, decisions, env=dict(tdb_env)) == 0
    os.remove(state_path)  # the state file is lost between runs

    fake_tdb.config["mode"] = "duplicate"
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 0
    assert fake_tdb.request_count == 2 * len(RESTRICTION_LEAVES)
    state_now = state_module.load(state_path)
    for index in RESTRICTION_LEAVES:
        record = state_now["leaves"][str(index)]
        assert record["status"] == "submitted", index
        assert record["uuid"] == "existing-uuid"
        assert record["duplicate"] is True


# --- J: bounded exponential backoff ----------------------------------------

def test_backoff_after_two_500s_then_success(fake_aics, fake_tdb, tdb_env,
                                             decisions_file, state_path,
                                             recording_sleeps, capsys):
    fake_tdb.config.update(mode="flaky_5xx", flaky_remaining=2)
    decisions = decisions_file(
        {LEAF_TOMBSTONE_ILLEGAL: illegal_decision(LEAF_TOMBSTONE_ILLEGAL)})
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 0
    assert recording_sleeps == [1.0, 2.0]
    assert fake_tdb.request_count == 3
    record = state_module.load(state_path)["leaves"][str(LEAF_TOMBSTONE_ILLEGAL)]
    assert record["status"] == "submitted"


def test_all_5xx_leaves_pending_after_exactly_four_attempts(fake_aics, fake_tdb,
                                                            tdb_env, decisions_file,
                                                            state_path,
                                                            recording_sleeps):
    fake_tdb.config.update(mode="flaky_5xx", flaky_remaining=99)
    decisions = decisions_file(all_decisions())
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 1
    assert fake_tdb.request_count == 4 * len(RESTRICTION_LEAVES)
    # Bounded: at most 3 sleeps for 4 attempts, never longer than the 4.0s cap.
    assert recording_sleeps == [1.0, 2.0, 4.0] * len(RESTRICTION_LEAVES)
    state_now = state_module.load(state_path)
    for index in RESTRICTION_LEAVES:
        record = state_now["leaves"][str(index)]
        assert record["status"] == "pending", index
        assert "HTTP 500" in record["last_error"]


# --- K: 4xx is terminal, recorded, and unblocked by a changed record --------

def test_422_posted_once_not_retried_until_decisions_change(fake_aics, fake_tdb,
                                                            tdb_env, decisions_file,
                                                            state_path, capsys):
    fake_tdb.config["mode"] = "reject_422"
    decisions = decisions_file(all_decisions())
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 1
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)  # exactly one POST each
    state_now = state_module.load(state_path)
    for index in RESTRICTION_LEAVES:
        record = state_now["leaves"][str(index)]
        assert record["status"] == "failed", index
        assert record["status_code"] == 422
        assert "HTTP 422" in record["error"]
        assert "rejected by policy" in record["error"]  # the body text is recorded

    # Unchanged decisions record: nothing is posted again.
    capsys.readouterr()
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 1
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)
    assert "decisions record is unchanged" in capsys.readouterr().out

    # A changed application_date un-blocks exactly that leaf.
    changed = all_decisions()
    changed[LEAF_TOMBSTONE_ILLEGAL] = illegal_decision(
        LEAF_TOMBSTONE_ILLEGAL, application_date="2026-10-21")
    decisions_changed = decisions_file(changed)
    rc = _run(fake_aics, state_path, decisions_changed, env=dict(tdb_env))
    assert rc == 1
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES) + 1


def test_429_posted_once_and_never_retried(fake_aics, fake_tdb, tdb_env,
                                           decisions_file, state_path):
    fake_tdb.config["mode"] = "reject_429"
    decisions = decisions_file(all_decisions())
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 1
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)
    state_now = state_module.load(state_path)
    for index in RESTRICTION_LEAVES:
        record = state_now["leaves"][str(index)]
        assert record["status"] == "failed"
        assert record["status_code"] == 429
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 1
    assert fake_tdb.request_count == len(RESTRICTION_LEAVES)


# --- L (abort half): a guard violation stops the run before any POST -------

def _poison_build(monkeypatch):
    real_build = payload_module.build_statement

    def poisoned_build(restriction, decision):
        statement = real_build(restriction, decision)
        if restriction.leaf_index == LEAF_TOMBSTONE_ILLEGAL:
            statement["decision_facts"] += " agent was did:key:z6MkUhOh"
        return statement

    monkeypatch.setattr(payload_module, "build_statement", poisoned_build)


def test_guard_violation_aborts_before_any_post(fake_aics, fake_tdb, tdb_env,
                                                decisions_file, state_path,
                                                monkeypatch, capsys):
    _poison_build(monkeypatch)
    decisions = decisions_file(all_decisions())
    with pytest.raises(submit.GuardViolation):
        _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert fake_tdb.request_count == 0
    assert "HARD GUARD VIOLATION" in capsys.readouterr().out
    # The run stopped before later leaves: every one is still pending.
    state_now = state_module.load(state_path)
    for index in RESTRICTION_LEAVES:
        assert state_now["leaves"][str(index)]["status"] == "pending", index


def test_cli_returns_2_on_guard_violation(fake_aics, fake_tdb, decisions_file,
                                          state_path, monkeypatch):
    _poison_build(monkeypatch)
    monkeypatch.setenv("DSA_TRANSPARENCY_TOKEN", fake_tdb.token)
    monkeypatch.setenv("DSA_TRANSPARENCY_URL", fake_tdb.url + "/api/v1/statement")
    decisions = decisions_file(all_decisions())
    rc = cli.main(["submit", "--base-url", fake_aics.url, "--state", state_path,
                   "--decisions", decisions])
    assert rc == 2
    assert fake_tdb.request_count == 0


# --- M: token secrecy ------------------------------------------------------

def test_token_scrubbed_from_stdout_and_state(fake_aics, fake_tdb, tdb_env,
                                              decisions_file, state_path,
                                              recording_sleeps, capsys):
    fake_tdb.config["mode"] = "echo_token_body"
    decisions = decisions_file(
        {LEAF_TOMBSTONE_ILLEGAL: illegal_decision(LEAF_TOMBSTONE_ILLEGAL)})
    rc = _run(fake_aics, state_path, decisions, env=dict(tdb_env))
    assert rc == 1
    out = capsys.readouterr().out
    assert TOKEN not in out
    assert "***" in out  # where the token was, only stars remain
    state_text = Path(state_path).read_text(encoding="utf-8")
    assert TOKEN not in state_text
    record = state_module.load(state_path)["leaves"][str(LEAF_TOMBSTONE_ILLEGAL)]
    assert record["status"] == "pending"
    assert TOKEN not in record["last_error"]
    assert "***" in record["last_error"]


def test_wrong_token_401_records_no_token(fake_aics, fake_tdb, decisions_file,
                                          state_path, capsys):
    env = {"DSA_TRANSPARENCY_TOKEN": "definitely-the-wrong-token",
           "DSA_TRANSPARENCY_URL": fake_tdb.url + "/api/v1/statement"}
    decisions = decisions_file(
        {LEAF_TOMBSTONE_ILLEGAL: illegal_decision(LEAF_TOMBSTONE_ILLEGAL)})
    rc = _run(fake_aics, state_path, decisions, env=env)
    assert rc == 1
    out = capsys.readouterr().out
    assert "definitely-the-wrong-token" not in out
    assert TOKEN not in out
    state_text = Path(state_path).read_text(encoding="utf-8")
    assert "definitely-the-wrong-token" not in state_text
    record = state_module.load(state_path)["leaves"][str(LEAF_TOMBSTONE_ILLEGAL)]
    assert record["status"] == "failed"
    assert record["status_code"] == 401
    assert "HTTP 401" in record["error"]


# --- J (network half): connection failures stay pending, retried next run ---

def test_network_failure_leaves_leaf_pending(fake_aics, decisions_file, state_path,
                                             recording_sleeps, capsys):
    import socket
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    decisions = decisions_file(
        {LEAF_TOMBSTONE_ILLEGAL: illegal_decision(LEAF_TOMBSTONE_ILLEGAL)})
    env = {"DSA_TRANSPARENCY_TOKEN": TOKEN,
           "DSA_TRANSPARENCY_URL": f"http://127.0.0.1:{port}/api/v1/statement"}
    rc = _run(fake_aics, state_path, decisions, env=env)
    assert rc == 1
    out = capsys.readouterr().out
    assert "still pending after bounded retries" in out
    state_now = state_module.load(state_path)
    record = state_now["leaves"][str(LEAF_TOMBSTONE_ILLEGAL)]
    assert record["status"] == "pending"
    assert record["reason"] == "retryable failure"
    assert TOKEN not in json.dumps(state_now)
    assert TOKEN not in out
    # Bounded: 4 attempts for the one leaf, three recorded backoff sleeps.
    assert recording_sleeps == [1.0, 2.0, 4.0]
