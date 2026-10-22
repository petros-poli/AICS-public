"""Which card is in force (AICS-1 §6.4, §13.1, §14.5 steps 3-4): aics verify card and aics policy init read the log's
policy leaves.  A card that did not verify as current is never stored; a logged successor that waits for its
not_before is pending, not a reason to call the card in force superseded; a new visitor pins the card in force.

The defects of the 2026-10-20 walk-throughs (docs/internal/readiness-2026-10-20.md, item 6 and the notes):
``aics verify card --file <leaf 2>`` exited 1 but stored the card, after which the card in force exited 2
"superseded" (also through ``policy init --force``), the record named the served card's URL, and from the
successor's not_before ``policy init --from-dns`` refused new visitors; ``aics verify card <a /v2/bodies URL>``
checked the host's well-known card instead."""

from __future__ import annotations

import hashlib
import json
import types

from aics_identity import keys as idkeys
from aics_identity.canonical import canonicalize
from aics_tlog import leaf_hash, verify_inclusion

from aics_cli import card as cardmod
from aics_cli import currency
from aics_cli.encoding import b64d_strict, b64u_d

from conftest import API_BASE, CARD_URL, DAY, DOMAIN, NOW, POLICIES_URL, Site, Witness, did


def cards_index(h) -> list[dict]:
    path = h.home / "cards" / "index.jsonl"
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def card_file(tmp_path, card: dict, name: str = "card.json"):
    f = tmp_path / name
    f.write_bytes(canonicalize(card))
    return f


# --- the pending successor (the reported defect) ---------------------------------------------------------------


def test_a_pending_successor_is_pending_and_never_stored(h, tmp_path):
    site = Site()
    leaf2 = site.successor()  # logged a day ago, takes effect six days from now
    site.publish(h)  # the well-known URL serves the card in force, leaf 1
    code, out = site.pin(h)
    assert code == 0, out
    assert out["card"]["status"] == "in-force" and out["card"]["currency"]["in_force"]["leaf_index"] == site.first
    assert any(f"policy leaf {leaf2} takes effect" in w for w in out["warnings"])
    f = card_file(tmp_path, site.card_of(leaf2), "leaf2.json")
    code, out = h.run("verify", "card", "--file", str(f))
    assert code == 1, out
    assert out["currency_state"] == "pending" and out["error"].startswith("pending: the card is policy leaf")
    assert out["policy_leaf"]["leaf_index"] == leaf2 and out["source"] == f"file:{f}" and out["url"] is None
    assert "stored" not in out and "nothing was stored" in out["error"]
    assert [r["card_hash"] for r in cards_index(h)] == [site.bundle.bootstrap_card_hash]
    code, out = h.run("verify", "card")  # the card in force: still current, the successor shown as pending
    assert code == 0, out
    assert out["currency_state"] == "in-force" and out["policy_leaf"]["leaf_index"] == site.first
    assert [p["leaf_index"] for p in out["pending"]] == [leaf2]
    code, text = h.run_text("verify", "card")
    assert code == 0 and f"pending    policy leaf {leaf2}" in text and "currency   in force: policy leaf 1" in text
    code, out = site.pin(h, force=True)  # the re-pin of the report
    assert code == 0, out
    assert out["policy"]["quorum"] == 0 and out["card"]["card_hash"] == site.bundle.bootstrap_card_hash


def test_a_card_aics_0_1_0_stored_unverified_is_not_history(h):
    """aics-cli 0.1.0 stored a pending successor after its exit-1 verdict, as ``signature-only`` under the served
    card's URL; such a record never makes the card in force superseded, with or without the policy leaves."""
    site = Site()
    leaf2 = site.successor()
    site.publish(h)
    assert site.pin(h)[0] == 0
    cardmod.CardStore(h.home / "cards").save(did(site.policy_key), CARD_URL, site.card_of(leaf2), now=NOW,
                                             status="signature-only")
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["previous"]["status"] == "in-force" and out["previous"]["card_hash"] == site.bundle.bootstrap_card_hash
    site.publish(h, listing=False)
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency"] == "bootstrap card; later policy events not checked", out


def test_the_successor_is_in_force_from_its_not_before_and_the_old_card_superseded(h):
    w = Witness("witness.test/w1")
    site = Site()
    site.publish(h)
    assert site.pin(h)[0] == 0
    leaf2 = site.successor(witnesses=[w], quorum=1)
    h.clock[0] = NOW + 7 * DAY  # past not_before
    site.publish(h, served=leaf2)
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["currency_state"] == "in-force" and out["policy_leaf"]["leaf_index"] == leaf2
    assert out["notice"]["status"] == "ok" and out["notice"]["required_seconds"] == site.notice
    assert out["stored"]["status"] == "in-force" and out["witness_policy_vs_pinned"] == "stronger"
    record = cards_index(h)[-1]
    assert record["source"] == CARD_URL and record["policy_leaf"] == leaf2 and record["status"] == "in-force"
    site.publish(h)  # a stale cache serves the old card again
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


def test_a_fresh_client_sees_the_superseded_card_in_the_policy_leaves(h):
    site = Site()
    leaf2 = site.successor()
    h.clock[0] = NOW + 7 * DAY
    site.publish(h)  # the old card, served after the successor took effect
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 2, out
    ev = out["evidence"]
    assert ev["reason"] == "superseded" and "policy leaf 2 has been in force" in out["error"]
    assert ev["card_leaf"]["leaf_index"] == site.first and ev["in_force_leaf"]["leaf_index"] == leaf2
    # anyone can re-check the in-force leaf against the checkpoint the evidence carries
    note = ev["checkpoint"]
    proof = [b64d_strict(x) for x in ev["in_force_leaf"]["inclusion_proof"]]
    entry = b64u_d(ev["in_force_leaf"]["entry_bytes"])
    assert verify_inclusion(leaf_hash(entry), leaf2, note["size"], proof, b64d_strict(note["root"]))
    assert not cards_index(h)


def test_policy_init_after_not_before_pins_the_successor(h):
    """From the successor's not_before a new visitor's ``policy init --from-dns`` pins it, no workaround needed."""
    w = Witness("witness.test/w1")
    site = Site()
    leaf2 = site.successor(witnesses=[w], quorum=1)
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=leaf2, cosigners=[(w, h.clock[0] - 5)])
    code, out = site.pin(h)
    assert code == 0, out
    pol = out["policy"]
    assert pol["quorum"] == 1 and pol["witness_vkeys"] == [w.vkey]
    leaf2_hash = cardmod.card_hash(site.card_of(leaf2))
    assert pol["sources"]["quorum"] == [f"card:policy-leaf:{leaf2}:{leaf2_hash}"]
    assert out["card"]["status"] == "in-force" and out["card"]["source"] == CARD_URL
    assert out["card"]["currency"]["notice"]["status"] == "ok"
    assert cards_index(h)[-1]["policy_leaf"] == leaf2
    assert h.run("verify", "card")[0] == 0
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and out["freshness"] == "fresh", out


def test_policy_init_pins_the_card_in_force_when_the_site_serves_a_stale_copy(h):
    site = Site()
    leaf2 = site.successor()
    h.clock[0] = NOW + 7 * DAY
    site.publish(h)  # the well-known URL still serves leaf 1
    code, out = site.pin(h)
    assert code == 0, out
    assert out["card"]["card_hash"] == cardmod.card_hash(site.card_of(leaf2))
    assert out["card"]["source"] == f"{POLICIES_URL}/{leaf2}"
    assert any("superseded" in w and "pinned the card in force instead" in w for w in out["warnings"])
    assert cards_index(h)[-1]["source"] == f"{POLICIES_URL}/{leaf2}"


def test_policy_init_never_pins_a_pending_card_served_early(h):
    w = Witness("witness.test/w1")
    site = Site()
    leaf2 = site.successor(witnesses=[w], quorum=1)
    site.publish(h, served=leaf2)  # the successor, served before its not_before
    code, out = site.pin(h)
    assert code == 0, out
    assert out["card"]["card_hash"] == site.bundle.bootstrap_card_hash and out["policy"]["quorum"] == 0
    assert any("pending" in w and "pinned the card in force instead" in w for w in out["warnings"])


def test_a_card_in_force_read_back_from_the_store_is_recorded_as_such(h):
    """Review round 2 (probe K): ``policy init`` that takes the card in force from the cards already stored recorded
    the source "the local card store" with no URL; the record names ``store:<card hash>`` now."""
    site = Site()
    site.publish(h)
    assert site.pin(h)[0] == 0  # the bootstrap card, in force, stored
    leaf2 = site.successor(witnesses=[Witness("witness.test/w1")], quorum=1)
    site.publish(h, served=leaf2)  # the successor, served before its not_before
    code, out = site.pin(h, force=True)
    assert code == 0 and out["card"]["status"] == "in-force", out
    boot = site.bundle.bootstrap_card_hash
    assert out["card"]["source"] == f"store:{boot}"
    record = cards_index(h)[-1]
    assert record["source"] == f"store:{boot}" and record["url"] is None and record["host"] is None
    assert record["card_hash"] == boot and record["policy_leaf"] == site.first


# --- the policy chain ---------------------------------------------------------------------------------------------


def test_in_force_is_the_latest_card_leaf_whose_not_before_has_passed():
    from aics_cli.currency import History, Leaf

    def leaf(i: int, kind: str, digest: str, not_before: int) -> Leaf:
        return Leaf(index=i, ts=not_before, kind=kind, document_hash=digest * 64, size=None,
                    prev_policy_index=i - 1 if i else None, effective_after=i, not_before=not_before)

    a, b, c, a_again = leaf(1, "card", "a", 10), leaf(2, "card", "b", 100), leaf(3, "card", "c", 50), \
        leaf(4, "card", "a", 1000)
    hist = History(checkpoint=types.SimpleNamespace(size=5), check=None, listing="", api_base="", now=60,
                   leaves=[leaf(0, "charter", "0", 0), a, b, c, a_again])
    assert hist.in_force() is c  # leaf 2 waited for 100 and was replaced by leaf 3 before it took effect
    assert hist.pending() == [a_again]
    assert hist.state("c" * 64) == ("in-force", c)
    assert hist.state("b" * 64) == ("superseded", b)
    assert hist.state("a" * 64) == ("pending", a_again)  # a document logged twice: the waiting leaf decides
    assert hist.state("d" * 64) == ("not-logged", None)
    assert hist.in_force_at(20, before=3) is a and hist.in_force_at(5) is None
    hist.now = 5
    assert hist.in_force() is None and [p.index for p in hist.pending()] == [1, 2, 3, 4]


def test_a_policy_leaf_the_listing_leaves_out_is_found_by_the_chain(h):
    site = Site()
    site.filler(5)
    leaf = site.successor()
    site.filler(300)  # a second entry bundle
    site.publish(h)
    h.fetcher.set(POLICIES_URL, site.listing([r for r in site.rows if r["leaf_index"] != site.first]))
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["policy_leaf"]["leaf_index"] == site.first and [p["leaf_index"] for p in out["pending"]] == [leaf]
    assert [x["leaf_index"] for x in out["policy_history"]["leaves"]] == [0, site.first, leaf]


def test_a_policy_leaf_the_listing_leaves_out_after_its_last_row_is_found_by_the_scan(h):
    """Review round 2 (probe F): a listing that leaves out the successor after its last row made the superseded card
    "in force" (exit 0).  AICS-1 §14.5 step 4 scans the policy events through the checkpoint: the entries after the
    listing's last policy leaf are read while they are few."""
    site = Site()
    site.filler(3)
    leaf2 = site.successor()
    site.filler(4)
    h.clock[0] = NOW + 7 * DAY  # a day after leaf 2 took effect
    site.publish(h)  # the old card at the pinned URL
    h.fetcher.set(POLICIES_URL, site.listing([r for r in site.rows if r["leaf_index"] != leaf2]))
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out
    assert out["evidence"]["in_force_leaf"]["leaf_index"] == leaf2
    site.publish(h, served=leaf2)
    h.fetcher.set(POLICIES_URL, site.listing([r for r in site.rows if r["leaf_index"] != leaf2]))
    code, out = h.run("verify", "card")
    assert code == 0 and out["policy_leaf"]["leaf_index"] == leaf2, out
    ph = out["policy_history"]
    assert ph["listing_last_leaf"] == site.first and ph["last_policy_leaf"] == leaf2 and ph["entries_after_scanned"]
    assert any(f"the listing leaves out policy leaf {leaf2}, after its last policy leaf {site.first}" in w
               for w in out["warnings"]), out["warnings"]
    size = len(site.log.entries)
    assert f"every entry after policy leaf {leaf2} through checkpoint size {size}" in " ".join(out["checked"])
    assert not any("leaves out" in x for x in out["unproven"])


def test_the_entries_after_the_listing_stay_unproven_when_too_many_or_unreadable(h, monkeypatch):
    """The scan is bounded (MAX_TAIL_SCAN entries) and never makes the history unavailable: a longer tail, or one
    whose tiles cannot be read, is reported unread, and the listing's last leaf heads the chain as before."""
    from conftest import TILES

    site = Site()
    site.filler(300)  # the entries after leaf 1 reach into a second entry bundle
    site.publish(h)
    site.policy(h)
    monkeypatch.setattr(currency, "MAX_TAIL_SCAN", 100)
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency_state"] == "in-force" and out["policy_history"]["entries_after_scanned"] is False
    assert any("the 300 entries after it are more than the 100 aics scans" in x for x in out["unproven"]), out
    monkeypatch.undo()
    for u in [u for u in h.fetcher.routes if u.startswith(TILES + "tile/entries/001")]:
        del h.fetcher.routes[u]  # the second entry bundle is missing
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency_state"] == "in-force", out
    assert out["policy_history"]["entries_after_scanned"] is False
    assert "could not be read" in out["policy_history"]["entries_after_unscanned"]
    assert any("were not scanned" in w for w in out["warnings"]), out["warnings"]


def test_a_policy_entry_after_the_listing_signed_by_another_key_is_evidence(h):
    site = Site()
    other = idkeys.generate_keypair()
    card = site.make_card(issued_at=NOW - DAY - 2)
    rows = list(site.rows)
    site.policy_leaf(site.card_statement(card, not_before=NOW - DAY), ts=NOW - DAY, document=canonicalize(card),
                     key=other)
    site.publish(h)
    h.fetcher.set(POLICIES_URL, site.listing(rows))  # the listing leaves it out
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "authority", out
    assert out["evidence"]["leaves"][0]["leaf_index"] == len(site.log.entries) - 1


def test_a_misstated_listing_row_is_reported_and_the_signed_values_used(h):
    site = Site()
    leaf2 = site.successor()
    site.publish(h)
    rows = [dict(r) for r in site.rows]
    rows[-1]["not_before"] = NOW - 10  # the listing claims leaf 2 is in force already
    h.fetcher.set(POLICIES_URL, site.listing(rows))
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["currency_state"] == "in-force" and [p["leaf_index"] for p in out["pending"]] == [leaf2]
    assert any(f"misstates leaf {leaf2} (not_before)" in w for w in out["warnings"])


def test_listing_rows_that_name_agent_leaves_are_ignored_and_a_flood_of_them_is_refused(h):
    site = Site()
    site.filler(200)
    site.publish(h)
    site.policy(h)
    agent_row = {"leaf_index": 7, "kind": "card", "document_hash": "ab" * 32, "size": 1, "prev_policy_index": 1,
                 "effective_after": 7, "not_before": NOW - 5}
    h.fetcher.set(POLICIES_URL, site.listing(site.rows[:1] + [agent_row] + site.rows[1:]))
    code, out = h.run("verify", "card")  # leaf 7 is the highest row, but an agent's leaf: the chain starts at 1
    assert code == 0 and out["currency_state"] == "in-force", out
    assert out["policy_history"]["listing_last_leaf"] == site.first
    assert any("names leaf 7 as a policy leaf, but it is no AICS-1 entry" in w and "the row is ignored" in w
               for w in out["warnings"]), out["warnings"]
    flood = [dict(agent_row, leaf_index=i) for i in range(3, 3 + 65)]
    h.fetcher.set(POLICIES_URL, site.listing(site.rows + flood))
    code, out = h.run("verify", "card")  # the history is not used; the bootstrap card stays verifiable
    assert code == 0 and out["currency"] == "bootstrap card; later policy events not checked", out
    assert "more than 64 rows that are not policy leaves" in out["policy_history"]["reason"]


def test_a_leaf_that_cannot_be_read_never_rolls_the_history_back(h):
    """A missing entry bundle under the latest policy leaf makes the history unavailable; it never makes an older
    leaf the head (that would hide the card in force)."""
    from conftest import TILES

    site = Site()
    site.filler(300)
    leaf = site.successor()  # in the second entry bundle
    h.clock[0] = NOW + 7 * DAY
    site.publish(h)
    site.policy(h)
    bundle = [u for u in h.fetcher.routes if u.startswith(TILES + "tile/entries/001")]
    assert bundle
    for u in bundle:
        del h.fetcher.routes[u]
    code, out = h.run("verify", "card")  # the old card: not "in force", only "not checked"
    assert code == 0 and out["currency"] == "bootstrap card; later policy events not checked", out
    assert f"leaf {leaf} could not be read" in out["policy_history"]["reason"]


def test_a_policy_leaf_signed_by_another_key_is_evidence(h):
    site = Site()
    other = idkeys.generate_keypair()
    card = site.make_card(issued_at=NOW - DAY - 2)
    site.policy_leaf(site.card_statement(card, not_before=NOW - DAY), ts=NOW - DAY, document=canonicalize(card),
                     key=other)
    site.publish(h)
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 2, out
    ev = out["evidence"]
    assert ev["type"] == "aics-policy-history-evidence/v1" and ev["reason"] == "authority"
    assert ev["leaves"][0]["leaf_index"] == 2 and ev["leaves"][0]["inclusion_proof"]


def test_two_policy_chains_are_evidence(h):
    site = Site()
    card = site.make_card(issued_at=NOW - DAY - 2)
    site.log_card(card, ts=NOW - DAY, not_before=NOW - DAY + site.notice, prev_policy_index=0)  # leaf 1's twin
    site.publish(h)
    site.policy(h)
    code, out = h.run("verify", "card")
    assert code == 2, out
    assert out["evidence"]["reason"] == "policy" and "not on the policy chain" in out["error"]
    assert sorted(x["leaf_index"] for x in out["evidence"]["leaves"]) == [1, 2]


def test_a_short_notice_does_not_authorise_a_weaker_witness_policy(h):
    w = Witness("witness.test/w1")
    site = Site(witnesses=[w], quorum=1)
    site.publish(h, cosigners=[(w, NOW - 5)])
    assert site.pin(h)[0] == 0  # quorum 1, stored
    leaf2 = site.successor(witnesses=[], quorum=0, notice=60)  # weaker, one minute of notice
    site.publish(h, served=leaf2, cosigners=[(w, NOW - 5)])
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "witness-downgrade", out
    assert out["notice"]["status"] == "short" and out["notice"]["given_seconds"] == 60


def test_a_weaker_card_in_force_after_its_notice_is_accepted_and_the_pin_kept(h):
    w = Witness("witness.test/w1")
    site = Site(witnesses=[w], quorum=1)
    site.publish(h, cosigners=[(w, NOW - 5)])
    assert site.pin(h)[0] == 0
    leaf2 = site.successor(witnesses=[], quorum=0)  # weaker, with the advertised notice
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=leaf2, cosigners=[(w, h.clock[0] - 5)])
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["witness_policy_vs_pinned"] == "weaker" and any("authorises the change" in x for x in out["warnings"])
    code, out = site.pin(h, force=True)  # adopting it stays the user's decision
    assert code == 1 and "--allow-weaker" in out["error"], out


def test_a_signed_card_that_is_not_logged_is_not_current(h):
    site = Site()
    site.publish(h)
    site.policy(h)
    h.fetcher.set(CARD_URL, json.dumps(site.make_card(issued_at=NOW - 60)))
    code, out = h.run("verify", "card")
    assert code == 1 and out["currency_state"] == "not-logged" and "stored" not in out, out
    assert not cards_index(h)


# --- a card URL is the card checked (the /v2/bodies note) --------------------------------------------------------------


def test_a_bodies_url_is_checked_as_the_card_it_serves(h):
    site = Site()
    leaf2 = site.successor()
    site.publish(h)
    site.policy(h)
    doc = canonicalize(site.card_of(leaf2))
    url = f"{API_BASE}/v2/bodies/{hashlib.sha256(doc).hexdigest()}"
    h.fetcher.set(url, doc)
    h.fetcher.requests.clear()
    code, out = h.run("verify", "card", url)
    assert code == 1 and out["url"] == url and out["currency_state"] == "pending", out
    assert CARD_URL not in h.fetcher.requests  # never the host's well-known card instead
    h.fetcher.set(url, canonicalize(site.card_of(site.first)))  # other bytes than the body the path names
    code, out = h.run("verify", "card", url)
    assert code == 1 and "does not hash to the digest" in out["error"], out
    h.fetcher.set(f"https://{DOMAIN}/card", "<html>a view of the card</html>")
    code, out = h.run("verify", "card", f"{DOMAIN}/card")
    assert code == 1 and "is not a card" in out["error"] and out["command"] == "verify card", out
    for site_arg in (DOMAIN, f"https://{DOMAIN}", f"https://{DOMAIN}/"):
        assert cardmod.resolve_url(site_arg, None) == CARD_URL
    assert cardmod.resolve_url(f"{POLICIES_URL}/2", None) == f"{POLICIES_URL}/2"


def test_a_url_and_a_file_together_are_refused(h, tmp_path):
    site = Site()
    site.publish(h)
    site.policy(h)
    code, out = h.run("verify", "card", CARD_URL, "--file", str(card_file(tmp_path, site.card_of(site.first))))
    assert code == 1 and "not both" in out["error"]
