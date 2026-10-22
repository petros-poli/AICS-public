"""When a card that is not current is evidence against the operator (exit 2) and when it is not (exit 1).

Exit 2 needs the origin's own act: it serves the card as current at the pinned card URL, or the log has the card
in force.  The review of the readiness/aics-cli lane (2026-10-20) found exit 2 "superseded" for documents the
server keeps by design (``/v2/policies/<index>``, ``/v2/bodies/<hash>``, ``--file``) and for the pinned URL in the
seconds after a switch, when an honest server's clock may not have reached the successor's not_before yet (the
same rule now covers altered, foreign-signed and expired documents); also the saved-card rule overruling the log's
order, a downgrade judged without the notice it needs, a listing without card rows taken for "not logged", a
bootstrap hash that is not the first card leaf, a card leaf whose effective_after the log has not reached, and a
malformed listing that crashed ``policy init``."""

from __future__ import annotations

import hashlib
import json
import types

from aics_identity.canonical import canonicalize

from aics_cli import card as cardmod
from aics_cli import currency
from aics_cli.trust import TrustBundle

from conftest import API_BASE, DAY, DOMAIN, NOW, ORIGIN, POLICIES_URL, TXT_NAME, Site, Witness, did, make_policy
from test_card_currency import card_file, cards_index


def not_before(site: Site, index: int) -> int:
    return next(r["not_before"] for r in site.rows if r["leaf_index"] == index)


def bodies_url(card: dict) -> str:
    return f"{API_BASE}/v2/bodies/{hashlib.sha256(canonicalize(card)).hexdigest()}"


# --- the clock-skew window at the pinned card URL ------------------------------------------------------------------


def test_the_pinned_url_is_evidence_only_30_s_after_the_switch(h):
    site = Site()
    leaf2 = site.successor()
    switch = not_before(site, leaf2)
    site.publish(h)  # the honest server, its clock a few seconds behind this machine's, still serves leaf 1
    site.policy(h)
    for skew in (5, 29):
        h.clock[0] = switch + skew
        code, out = h.run("verify", "card")
        assert code == 1, out
        assert out["currency_state"] == out["reason"] == "superseded" and out["served_as_current"] is True
        assert f"was {skew} s ago by this machine's clock" in out["error"]
        assert "no evidence against the operator" in out["error"] and "nothing was stored" in out["error"]
        assert "evidence" not in out and "stored" not in out
    code, text = h.run_text("verify", "card")
    assert code == 1 and "currency   superseded: policy leaf 1" in text
    assert text.rstrip().splitlines()[-1].startswith("error: superseded:")
    assert not cards_index(h)
    h.clock[0] = switch + 31  # the control: long enough for any honest clock
    code, out = h.run("verify", "card")
    assert code == 2, out
    ev = out["evidence"]
    assert ev["reason"] == "superseded" and ev["replaced_at"] == switch and ev["in_force_leaf"]["leaf_index"] == leaf2
    assert "the origin serves it as current" in out["error"] and not cards_index(h)


def test_the_saved_card_rule_waits_out_the_clock_skew_as_well(h):
    """Without the policy leaves only the saved card speaks; its record says when it took effect."""
    site = Site()
    leaf2 = site.successor()
    switch = not_before(site, leaf2)
    h.clock[0] = switch + 2
    site.publish(h, served=leaf2)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0  # in force: stored, with the not_before of leaf 2
    site.publish(h, listing=False)  # the server, still behind, serves leaf 1; no policy listing
    h.clock[0] = switch + 10
    code, out = h.run("verify", "card")
    assert code == 1 and out["policy_history"]["available"] is False, out
    assert "issued before the card saved earlier" in out["error"] and "was 10 s ago" in out["error"]
    h.clock[0] = switch + 31
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded" and out["evidence"]["saved"]["policy_leaf"] == leaf2


def test_a_repin_is_evidence_only_where_the_site_serves_the_older_card(h, monkeypatch):
    site = Site()
    leaf2 = site.successor()
    switch = not_before(site, leaf2)
    h.clock[0] = switch + 2
    site.publish(h, served=leaf2)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0  # leaf 2 in force: stored
    h.clock[0] = switch + 10
    site.publish(h, listing=False)  # the server, still behind, serves leaf 1; no policy listing
    code, out = site.pin(h, force=True)
    assert code == 1 and "less than 30 s ago by this machine's clock" in out["error"] and "evidence" not in out, out
    h.clock[0] = switch + DAY
    site.publish(h, served=leaf2)
    h.fetcher.set(POLICIES_URL, site.listing(site.rows[:2]))  # a listing that lags: the charter and leaf 1 only
    with monkeypatch.context() as m:
        m.setattr(currency, "MAX_TAIL_SCAN", 0)  # the entries after leaf 1 are not scanned
        code, out = site.pin(h, force=True)  # the card in force as read (leaf 1, from /v2/policies/1) is the older one
    assert code == 1 and "a policy listing that lags" in out["error"] and "evidence" not in out, out
    code, out = site.pin(h, force=True)  # scanned, the entries after leaf 1 hold leaf 2: the lag does not matter
    assert code == 0 and out["card"]["currency"]["in_force"]["leaf_index"] == leaf2, out
    site.publish(h)  # the control: the site serves leaf 1 a day after the switch, no listing to read
    h.fetcher.routes.pop(POLICIES_URL)
    code, out = site.pin(h, force=True)
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


# --- documents the origin does not serve as current ---------------------------------------------------------------


def test_historical_documents_are_superseded_but_no_evidence(h, tmp_path):
    site = Site()
    leaf2 = site.successor()
    h.clock[0] = NOW + 7 * DAY  # a day after leaf 2 took effect
    site.publish(h, served=leaf2)
    site.policy(h)
    old = site.card_of(site.first)
    h.fetcher.set(bodies_url(old), canonicalize(old))
    f = card_file(tmp_path, old, "old.json")
    documents = ([f"{POLICIES_URL}/{site.first}"], [bodies_url(old)], ["--file", str(f)])

    def all_exit_1() -> None:
        for argv in documents:
            code, out = h.run("verify", "card", *argv)
            assert code == 1, (argv, out)
            assert out["currency_state"] == out["reason"] == "superseded" and out["served_as_current"] is False
            assert "not served as the current card" in out["error"]
            assert "no evidence against the operator" in out["error"]
            assert "evidence" not in out and "stored" not in out

    all_exit_1()
    assert not cards_index(h)
    assert h.run("verify", "card")[0] == 0  # the pinned URL serves leaf 2: in force, stored
    all_exit_1()  # the saved card (issued later) agrees with the log, and still no evidence
    assert [r["card_hash"] for r in cards_index(h)] == [cardmod.card_hash(site.card_of(leaf2))]
    site.publish(h, served=leaf2, listing=False)  # without the leaves only the saved card speaks: the same verdict
    code, out = h.run("verify", "card", "--file", str(f))
    assert code == 1 and "issued before the card saved earlier" in out["error"] and "evidence" not in out, out
    site.publish(h)  # the control: the pinned URL serves leaf 1 a day after the switch
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


def test_an_altered_or_expired_document_is_evidence_only_where_the_origin_serves_it(h, tmp_path):
    """Anyone can alter a file, and any agent can post a body: /v2/bodies/<hash> serves it whatever it is."""
    site = Site()
    site.publish(h)
    site.policy(h)
    altered = json.loads(json.dumps(site.card_of(site.first)))
    altered["assurances"][4]["status"] = "proven"  # changed after signing
    h.fetcher.set(bodies_url(altered), canonicalize(altered))
    for argv in ([bodies_url(altered)], ["--file", str(card_file(tmp_path, altered, "altered.json"))]):
        code, out = h.run("verify", "card", *argv)
        assert code == 1 and out["reason"] == "invalid-signature" and "evidence" not in out, out
        assert "no evidence against the operator" in out["error"]
    expires = site.card_of(site.first)["expires"]
    h.clock[0] = expires + 5  # the first card has expired, 5 s ago by this machine's clock
    code, out = h.run("verify", "card", f"{POLICIES_URL}/{site.first}")
    assert code == 1 and out["reason"] == "expired" and "evidence" not in out, out
    code, out = h.run("verify", "card")  # the pinned URL, while an honest server's clock may lag
    assert code == 1 and out["reason"] == "expired" and "that was 5 s ago" in out["error"], out
    h.clock[0] = expires + 30
    code, out = h.run("verify", "card")  # the control: the origin serves the expired card as current
    assert code == 2 and out["evidence"]["reason"] == "expired", out


def test_policy_init_waits_out_the_clock_skew_on_an_expired_card_too(h):
    """Review round 2: ``policy init`` exited 2 at once for a served card that had just expired, while ``verify card``
    waits the 30 s by which an honest server's clock may lag."""
    site = Site()
    site.publish(h)
    expires = site.card_of(site.first)["expires"]
    h.clock[0] = expires + 5
    code, out = site.pin(h)
    assert code == 1 and out["reason"] == "expired" and "5 s ago by this machine's clock" in out["error"], out
    assert "evidence" not in out and not (h.home / "policy.toml").exists()
    h.clock[0] = expires + 30  # the control
    code, out = site.pin(h)
    assert code == 2 and "not currently valid" in out["error"] and out["evidence"]["checked_at"] == expires + 30, out


def test_a_superseded_document_is_never_judged_as_a_downgrade(h, tmp_path):
    """A card that is not current cannot weaken anything: a weaker superseded card read from a file is superseded
    (exit 1), not a witness downgrade (exit 2)."""
    w = Witness("witness.test/w1")
    site = Site()
    leaf2 = site.successor(ts=NOW - 20 * DAY, witnesses=[w], quorum=1)
    site.publish(h, served=leaf2, cosigners=[(w, NOW - 5)])
    site.policy(h)  # quorum 0, as pinned from the bootstrap card
    assert h.run("verify", "card")[0] == 0  # leaf 2 (quorum 1) in force: stored
    f = card_file(tmp_path, site.card_of(site.first), "bootstrap.json")  # quorum 0: weaker than the saved card
    code, out = h.run("verify", "card", "--file", str(f))
    assert code == 1 and out["currency_state"] == "superseded" and "evidence" not in out, out
    assert out["witness_policy_vs_saved_card"] == "weaker"


def test_an_unlogged_weaker_card_is_evidence_only_where_the_origin_serves_it(h, tmp_path):
    w = Witness("witness.test/w1")
    site = Site(witnesses=[w], quorum=1)
    site.publish(h, cosigners=[(w, NOW - 5)])
    assert site.pin(h)[0] == 0  # quorum 1, stored
    weaker = site.make_card(issued_at=NOW - 60, witnesses=[], quorum=0)  # signed, never logged
    code, out = h.run("verify", "card", "--file", str(card_file(tmp_path, weaker)))
    assert code == 1 and out["currency_state"] == "not-logged" and "evidence" not in out, out
    site.publish(h, served=weaker, cosigners=[(w, NOW - 5)])
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "witness-downgrade", out


# --- the log's order, not issued_at -----------------------------------------------------------------------------------


def test_the_log_orders_the_cards_not_their_issued_at(h):
    site = Site()
    leaf2 = site.successor(ts=NOW - 20 * DAY)  # in force from NOW - 13 days
    early = site.card_of(leaf2)["issued_at"] - 3 * DAY
    leaf3 = site.successor(ts=NOW - 10 * DAY, issued_at=early)  # issued before leaf 2's card, logged after it
    h.clock[0] = NOW - 12 * DAY
    site.publish(h, served=leaf2)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0  # leaf 2 in force: stored
    h.clock[0] = NOW
    site.publish(h, served=leaf3)
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["currency_state"] == "in-force" and out["policy_leaf"]["leaf_index"] == leaf3
    assert any(f"policy leaf {leaf3} is logged after leaf {leaf2}" in w and "the log's order decides" in w
               for w in out["warnings"]), out["warnings"]
    code, out = site.pin(h, force=True)
    assert code == 0 and out["card"]["card_hash"] == cardmod.card_hash(site.card_of(leaf3)), out


def test_two_logged_cards_with_one_issued_at_are_not_equivocation(h):
    site = Site()
    leaf2 = site.successor(ts=NOW - 20 * DAY)
    leaf3 = site.successor(ts=NOW - 10 * DAY, issued_at=site.card_of(leaf2)["issued_at"])
    h.clock[0] = NOW - 12 * DAY
    site.publish(h, served=leaf2)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0
    h.clock[0] = NOW
    site.publish(h, served=leaf3)
    code, out = h.run("verify", "card")
    assert code == 0 and out["policy_leaf"]["leaf_index"] == leaf3, out
    unlogged = site.make_card(issued_at=site.card_of(leaf3)["issued_at"], max_age=600)
    site.publish(h, served=unlogged)  # the control: an unlogged card for the same moment
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "equivocation", out


def logged_out_of_issued_order(h, *, same_moment: bool = False) -> tuple[Site, int, int]:
    """Leaves 2 and 3 logged in that order, leaf 3's card issued before leaf 2's (or at the same moment); each
    verified in force in turn, so each is stored with the policy leaf it was in force by."""
    site = Site()
    leaf2 = site.successor(ts=NOW - 20 * DAY)
    issued = site.card_of(leaf2)["issued_at"] - (0 if same_moment else 3 * DAY)
    leaf3 = site.successor(ts=NOW - 10 * DAY, issued_at=issued)
    h.clock[0] = NOW - 12 * DAY
    site.publish(h, served=leaf2)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0
    h.clock[0] = NOW
    site.publish(h, served=leaf3)
    assert h.run("verify", "card")[0] == 0
    assert [r["policy_leaf"] for r in cards_index(h)] == [leaf2, leaf3]
    return site, leaf2, leaf3


def test_the_saved_card_is_the_latest_by_its_recorded_policy_leaf(h):
    """Review round 2 (probe A): the saved card was the one with the latest issued_at, so once the policy leaves could
    not be read the card in force (leaf 3, issued earlier) exited 2 "superseded" by the card it replaced."""
    site, leaf2, leaf3 = logged_out_of_issued_order(h)
    latest = cardmod.CardStore(h.home / "cards").latest(did(site.policy_key))
    assert latest is not None and latest.meta["policy_leaf"] == leaf3
    site.publish(h, served=leaf3, listing=False)  # the listing is down once
    code, out = h.run("verify", "card")
    assert code == 1 and out["currency_state"] == "unproven" and out["error"].startswith("incomplete:"), out
    assert out["diff"] == [] and "evidence" not in out and "stored" not in out
    code, out = site.pin(h, force=True)
    assert code == 1 and "evidence" not in out, out
    site.publish(h, served=leaf2, listing=False)  # the control: the card leaf 3 replaced, at the pinned card URL
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out
    assert out["evidence"]["recorded_order"] == {"card_policy_leaf": leaf2, "saved_policy_leaf": leaf3}
    assert f"logged before the card saved earlier (policy leaf {leaf2}, then leaf {leaf3}" in out["error"]


def test_two_cards_for_one_moment_recorded_in_force_are_ordered_by_their_leaves(h):
    site, leaf2, leaf3 = logged_out_of_issued_order(h, same_moment=True)
    site.publish(h, served=leaf3, listing=False)
    code, out = h.run("verify", "card")
    assert code == 1 and out["error"].startswith("incomplete:") and "evidence" not in out, out
    site.publish(h, served=leaf2, listing=False)  # the card leaf 3 replaced: superseded, not equivocation
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


# --- a downgrade judged without its notice -------------------------------------------------------------------------


def test_a_downgrade_whose_notice_cannot_be_checked_is_incomplete(h):
    w = Witness("witness.test/w1")
    site = Site(witnesses=[w], quorum=1)
    leaf2 = site.successor(ts=NOW - 20 * DAY)  # quorum 1, in force from NOW - 13 days
    leaf3 = site.successor(ts=NOW - 10 * DAY, witnesses=[], quorum=0)  # weaker, with the advertised notice
    h.clock[0] = NOW - 25 * DAY
    site.publish(h, cosigners=[(w, h.clock[0] - 5)])
    assert site.pin(h)[0] == 0  # the bootstrap card stored; leaves 2 and 3 pending
    h.clock[0] = NOW
    site.publish(h, served=leaf3, cosigners=[(w, NOW - 5)])
    del h.fetcher.routes[f"{POLICIES_URL}/{leaf2}"]  # the card in force when leaf 3 was logged cannot be read
    code, out = h.run("verify", "card")
    assert code == 1, out
    assert out["notice"]["status"] == "unchecked" and out["error"].startswith("incomplete: the card weakens")
    assert out["reason"] == "witness-downgrade"
    assert "evidence" not in out and "stored" not in out
    code, out = site.pin(h, force=True)
    assert code == 1 and "incomplete" in out["error"] and "evidence" not in out, out


def pin_flags(*extra: str) -> tuple[str, ...]:
    return ("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--force", *extra)


def test_a_downgrade_judged_while_the_policy_leaves_cannot_be_read_is_incomplete(h):
    """Review round 2 (probe H): a weaker successor logged with the advertised notice and in force, judged while the
    policy listing is down once, exited 2 "witness-downgrade" saying that no logged policy leaf authorises it, and 0
    once the listing was back.  No leaf was read, so the verdict is incomplete (AICS-1 §14)."""
    w = Witness("witness.test/w1")
    site = Site(witnesses=[w], quorum=1)
    site.publish(h, cosigners=[(w, NOW - 5)])
    assert site.pin(h)[0] == 0  # quorum 1, stored
    leaf2 = site.successor(witnesses=[], quorum=0)  # weaker, with the advertised notice
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=leaf2, cosigners=[(w, h.clock[0] - 5)], listing=False)  # the listing is down
    code, out = h.run("verify", "card")
    assert code == 1, out
    assert out["reason"] == "witness-downgrade" and out["error"].startswith("incomplete:")
    assert out["policy_history"]["available"] is False and out["witness_policy_vs_saved_card"] == "weaker"
    assert "evidence" not in out and "stored" not in out and len(cards_index(h)) == 1
    code, out = h.run(*pin_flags("--accept-signed-card"))
    assert code == 1 and out["reason"] == "witness-downgrade" and out["error"].startswith("incomplete:"), out
    assert "--allow-weaker" in out["error"] and "evidence" not in out and len(cards_index(h)) == 1
    site.publish(h, served=leaf2, cosigners=[(w, h.clock[0] - 5)])  # the listing is back
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency_state"] == "in-force" and out["policy_leaf"]["leaf_index"] == leaf2, out


def test_a_retired_witness_leaves_existing_users_incomplete_not_accusing(h):
    """Review round 2 (probe I): after a noticed rotation from w1 to w2, w1 stops cosigning.  A user who pinned w1
    cannot read the policy leaves any more (no checkpoint meets the pinned quorum), so the rotation, a weaker policy
    by the pinned terms, is incomplete for them, never evidence; re-pinning takes --accept-signed-card --allow-weaker
    (docs/internal/followups.md, Readiness 2026-10-20: aics-cli)."""
    w1, w2 = Witness("witness.test/w1"), Witness("witness.test/w2")
    site = Site(witnesses=[w1], quorum=1)
    site.publish(h, cosigners=[(w1, NOW - 5)])
    assert site.pin(h)[0] == 0
    site.successor(witnesses=[w2], quorum=1)
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=site.last_policy_index, cosigners=[(w2, h.clock[0] - 5)])  # w1 retired at the switch
    code, out = h.run("verify", "card")
    assert code == 1 and out["reason"] == "witness-downgrade" and out["error"].startswith("incomplete:"), out
    assert "quorum not met" in out["policy_history"]["reason"] and "evidence" not in out
    assert h.sleeps == [1.0, 2.0, 3.0]  # the wait for a missing witness line, then the history is unavailable
    code, out = h.run(*pin_flags("--accept-signed-card"))
    assert code == 1 and out["error"].startswith("incomplete:") and "evidence" not in out, out
    code, out = h.run(*pin_flags("--accept-signed-card", "--allow-weaker"))
    assert code == 0 and out["policy"]["witness_vkeys"] == [w2.vkey] and out["card"]["status"] == "signature-only", out


# --- what the policy chain read can say ----------------------------------------------------------------------------


def test_a_listing_without_card_rows_leaves_the_bootstrap_card_unproven_not_unlogged(h, monkeypatch):
    site = Site()
    site.publish(h)
    h.fetcher.set(POLICIES_URL, site.listing(site.rows[:1]))  # only the charter row (a listing that lags)
    monkeypatch.setattr(currency, "MAX_TAIL_SCAN", 0)  # the entries after the charter are not scanned
    code, out = site.pin(h)
    assert code == 0 and out["card"]["status"] == "bootstrap", out
    assert any("names no card leaf" in w and "later policy events were not checked" in w for w in out["warnings"])
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency"] == "bootstrap card; later policy events not checked", out
    assert "names no card leaf" in out["policy_history"]["reason"]
    assert "more than the 0 aics scans" in out["policy_history"]["reason"]
    monkeypatch.undo()  # by default the few entries after the charter are scanned, and the card leaf is found
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency_state"] == "in-force" and out["policy_leaf"]["leaf_index"] == site.first, out
    assert any(f"the listing leaves out policy leaf {site.first}" in w for w in out["warnings"])


def test_a_log_without_a_card_leaf_is_not_logged_once_the_chain_reaches_its_last_leaf(h):
    """The genesis window: the charter is logged, the bootstrap card is served but not logged yet, and the chain read
    reaches the last leaf of the tree, so "no card leaf" is proven rather than unread."""
    site = Site()
    site.publish(h, size=1)  # the checkpoint covers the charter only; the listing's card row lies beyond it
    code, out = site.pin(h)
    assert code == 1 and "the log has no card leaf yet" in out["error"] and "nothing was pinned" in out["error"], out
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 1 and out["currency_state"] == "not-logged" and "stored" not in out, out


def test_not_logged_names_the_chain_that_was_read(h):
    site = Site()
    site.publish(h)
    site.policy(h)
    site.publish(h, served=site.make_card(issued_at=NOW - 60))
    code, out = h.run("verify", "card")
    assert code == 1 and out["currency_state"] == "not-logged", out
    assert ("no card leaf on the policy chain read from leaf 1, the last policy leaf in the tree of checkpoint size "
            f"{len(site.log.entries)} (every entry after it scanned), back to the charter") in out["error"]


def test_the_bootstrap_card_must_be_the_first_card_leaf(h):
    site = Site()
    leaf2 = site.successor()
    h.clock[0] = NOW + 7 * DAY
    second = cardmod.card_hash(site.card_of(leaf2))
    site.bundle = TrustBundle(origin=ORIGIN, log_vkey=site.log.vkey, policy_kid=did(site.policy_key),
                              owner_kid=did(site.owner_key), bootstrap_card_hash=second)
    site.publish(h, served=leaf2)
    code, out = site.pin(h)
    assert code == 1 and "the log's first card leaf, policy leaf 1" in out["error"], out
    assert "nothing was pinned" in out["error"] and not (h.home / "policy.toml").exists()
    make_policy(h.home, site.log, policy_kid=did(site.policy_key), owner_kid=did(site.owner_key),
                bootstrap_card_hash=second)
    code, out = h.run("verify", "card")
    assert code == 0 and any("is not the bootstrap card your policy pins" in w for w in out["warnings"]), out


def test_a_card_leaf_waits_for_its_effective_after(h):
    """AICS-1 §6.4: a policy applies only at indices greater than its effective_after."""
    site = Site()
    card = site.make_card(issued_at=NOW - DAY - 2, expires=NOW + 365 * DAY)
    leaf2 = site.log_card(card, ts=NOW - DAY, not_before=NOW - DAY + site.notice, effective_after=10_000)
    h.clock[0] = NOW + 7 * DAY  # past its not_before, but the log has a handful of entries
    site.publish(h, served=leaf2)
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 1 and out["currency_state"] == "pending", out
    assert "once the log is past index 10000" in out["error"]
    site.publish(h)
    code, out = h.run("verify", "card")
    assert code == 0 and out["policy_leaf"]["leaf_index"] == site.first, out
    assert [p["leaf_index"] for p in out["pending"]] == [leaf2]


def test_history_in_force_needs_the_activation_index():
    from aics_cli.currency import History, Leaf

    def leaf(i: int, not_before: int, after: int) -> Leaf:
        return Leaf(index=i, ts=0, kind="card" if i else "charter", document_hash=str(i) * 64, size=None,
                    prev_policy_index=i - 1 if i else None, effective_after=after, not_before=not_before)

    one, two = leaf(1, 10, 1), leaf(2, 20, 100)
    hist = History(checkpoint=types.SimpleNamespace(size=5), check=None, listing="", api_base="", now=30,
                   leaves=[leaf(0, 0, 0), one, two])
    assert hist.in_force() is one and hist.pending() == [two] and hist.replaced_at(one) is None
    assert "once the log is past index 100" in hist.takes_effect(two)
    hist.checkpoint = types.SimpleNamespace(size=101)
    assert hist.in_force() is two and hist.pending() == [] and hist.replaced_at(one) == 20
    assert hist.state(str(1) * 64) == ("superseded", one)


# --- a malformed listing ------------------------------------------------------------------------------------------


def test_a_listing_whose_policies_member_is_not_an_array_is_refused_cleanly(h):
    site = Site()
    leaf2 = site.successor()
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=leaf2)
    h.fetcher.set(POLICIES_URL, json.dumps({"policies": 5}))
    code, out = site.pin(h)
    assert code == 1 and not out.get("internal"), out
    assert "names no leaf whose document is the bootstrap card" in out["error"]
    assert h.dns.records[TXT_NAME]  # the bundle was read; only the listing was wrong
