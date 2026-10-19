"""aics status [--mirrors]: origin and mirrors, pairwise consistency."""

from __future__ import annotations

from aics_cli.net import join_url

from conftest import CHECKPOINT_URL, MIRROR, NOW, Log, Witness, make_policy

M1 = MIRROR
M2 = "https://mirror-two.example/"


def serve_mirror(h, log, base, size):
    h.fetcher.set(join_url(base, "checkpoint"), log.note(size))
    h.fetcher.serve_tiles(base, log.tiles(size))


def test_origin_and_lagging_mirrors_are_consistent(h):
    log = Log(300)
    make_policy(h.home, log, mirrors=[M1, M2])
    h.serve(log, 300)
    serve_mirror(h, log, M1, 290)
    serve_mirror(h, log, M2, 12)
    code, out = h.run("status", "--mirrors")
    assert code == 0, out
    assert [s["status"] for s in out["sources"]] == ["ok", "ok", "ok"]
    assert len(out["pairs"]) == 3 and out["not_provable"] == []
    assert out["saved"]["count"] == 3


def test_mirror_serving_a_fork_is_reported_with_evidence(h):
    log = Log(300)
    make_policy(h.home, log, mirrors=[M1])
    h.serve(log, 300)
    serve_mirror(h, log.fork(5), M1, 200)
    code, out = h.run("status", "--mirrors")
    assert code == 2, out
    assert out["not_provable"] == [{"a": "origin", "b": f"mirror {M1}", "status": "split-proven"}]
    item = out["evidence"]["items"][0]
    assert item["type"] == "aics-split-view-evidence/v1"
    assert sorted(n["size"] for n in item["pairs"][0]["notes"]) == [200, 300]


def test_mirror_with_an_invalid_signature_is_not_evidence(h):
    log = Log(20)
    make_policy(h.home, log, mirrors=[M1])
    h.serve(log, 20)
    h.fetcher.set(join_url(M1, "checkpoint"), Log(20).note())  # another key: anyone on the mirror path can do this
    code, out = h.run("status", "--mirrors")
    assert code == 1, out
    assert out["sources"][1]["status"] == "invalid" and "evidence" not in out
    assert "incomplete" in out["error"]


def test_origin_with_an_invalid_signature_is_evidence(h):
    log = Log(20)
    make_policy(h.home, log, mirrors=[M1])
    h.fetcher.set(CHECKPOINT_URL, Log(20).note())  # the log origin itself serves it
    serve_mirror(h, log, M1, 20)
    code, out = h.run("status", "--mirrors")
    assert code == 2
    assert out["sources"][0]["status"] == "invalid"
    assert out["evidence"]["items"][0]["type"] == "aics-checkpoint-failure/v1"


def test_unreachable_mirror_is_incomplete_not_evidence(h):
    log = Log(20)
    make_policy(h.home, log, mirrors=[M1])
    h.serve(log, 20)
    h.fetcher.fail(join_url(M1, "checkpoint"))
    code, out = h.run("status", "--mirrors")
    assert code == 1
    assert out["sources"][1]["status"] == "unreachable" and "incomplete" in out["error"]


def test_status_compares_origin_with_the_saved_head(h):
    log = Log(40)
    make_policy(h.home, log, mirrors=[M1])
    h.serve(log, 10)
    assert h.run("verify", "checkpoint")[0] == 0
    h.serve(log, 40)
    code, out = h.run("status")
    assert code == 0, out
    assert [s["name"] for s in out["sources"]] == ["origin"]
    p = out["pairs"][0]
    assert (p["a"], p["b"], p["a_size"], p["b_size"], p["status"]) == ("saved head", "origin", 10, 40, "consistent")
    assert out["saved"]["head_size"] == 10


def test_status_detects_a_rewrite_since_the_saved_head(h):
    log = Log(40)
    make_policy(h.home, log)
    h.fetcher.set(CHECKPOINT_URL, log.fork(0).note(10))
    assert h.run("verify", "checkpoint")[0] == 0
    h.serve(log, 40)
    code, out = h.run("status")
    assert code == 2
    assert out["not_provable"][0]["status"] == "split-proven"


def test_status_reports_an_older_head_as_historical(h):
    log = Log(40)
    make_policy(h.home, log)
    h.serve(log, 40)
    assert h.run("verify", "checkpoint")[0] == 0
    h.fetcher.set(CHECKPOINT_URL, log.note(30))  # an older head; the tiles still cover the saved one
    code, out = h.run("status")
    assert code == 1, out
    assert out["not_provable"] == [{"a": "saved head", "b": "origin", "status": "historical"}]
    assert "historical" in out["error"] and "evidence" not in out


def test_stale_origin_checkpoint(h):
    log, w = Log(20), Witness("w.test/1")
    make_policy(h.home, log, witnesses=[w], quorum=1, max_age=600)
    h.serve(log, 20, [(w, NOW - 3600)])
    code, out = h.run("status")
    assert code == 1, out
    assert out["sources"][0]["status"] == "stale" and "evidence" not in out


def test_no_mirrors_pinned_warns(h):
    log = Log(5)
    make_policy(h.home, log)
    h.serve(log)
    code, out = h.run("status", "--mirrors")
    assert code == 0 and "no mirrors" in out["warnings"][0]


def test_text_output(h):
    log = Log(300)
    make_policy(h.home, log, mirrors=[M1])
    h.serve(log, 300)
    serve_mirror(h, log, M1, 256)
    code, text = h.run_text("status", "--mirrors")
    assert code == 0
    assert f"pair origin (300) ~ mirror {M1} (256): ok" in text
