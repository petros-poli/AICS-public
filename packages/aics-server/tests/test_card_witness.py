"""The card's witness policy (AICS_WITNESSES) and the successor-card flow.

AICS-1 sections 6.2-6.4 and 13, DESIGN.md G5, DECISIONS.md #30 (the founder-run witness host).

* The policy build: ``AICS_WITNESSES`` (the syntax the checkpoint feeder reads) gives the section 13.1
  members ``{name, vkey, trust_domain: founder, independent: false}``, quorum 1 and max_checkpoint_age 300.
* The skeleton states it, with a G5 row that stays promised ("a founder-run witness proves freshness, not
  independence") and tells agents how to check cosignatures and their age.
* A file card and a logged card may list only witnesses this server feeds.
* ``POST /v2/admin/card/preview`` signs and checks a successor body and logs nothing.
* ``OwnerClient.log_successor_card`` (``aics_client.py owner log-card --successor``) builds the successor of a
  logged bootstrap card, checks the signed bytes and logs them with the notice period.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aics_identity import canonicalize
from aics_server.app import create_app
from aics_server.card import (
    MAX_CHECKPOINT_AGE,
    NO_WITNESSES,
    CardError,
    build_skeleton,
    card_problems,
    g5_bound,
    parse_witness_policy,
    sign_card,
    verify_card,
)
from aics_server.db import POLICY_NOTICE_SECONDS
from aics_tlog import format_vkey, vkey_from_ed25519

from conftest import TEST_LIMITS
from test_client_sdk import _load_sdk, route_to_testclient

WITNESS_NAME = "witness.wesupport-ai.example/w1"
#: Nothing listens there: a feeder started by the setting fails at once, without a DNS lookup.
WITNESS_URL = "http://127.0.0.1:9/witness"


def cosignature_vkey(name: str = WITNESS_NAME) -> str:
    return format_vkey(vkey_from_ed25519(name, Ed25519PrivateKey.generate().public_key(), 0x04))


@pytest.fixture(scope="module")
def sdk():
    return _load_sdk("aics_client_card_witness")


@pytest.fixture()
def vkey() -> str:
    return cosignature_vkey()


@pytest.fixture()
def witness_env(vkey: str) -> str:
    return f"oracle={WITNESS_URL}={vkey}"


def unsigned(card: dict) -> dict:
    return {k: v for k, v in card.items() if k != "signatures"}


def g5(card: dict) -> dict:
    return next(a for a in card["assurances"] if a["id"] == "G5")


_APPS: list[TestClient] = []


@pytest.fixture(autouse=True)
def _stop_feeders():
    """Stop any witness feeder an app of this module started (AICS_WITNESSES also starts the feeder)."""
    yield
    while _APPS:
        stop = getattr(_APPS.pop().app.state.db, "stop_witness_feeder", None)
        if stop is not None:
            stop()


def make_app(db_path: Path, owner, keys_file: Path | None = None) -> TestClient:
    client = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, pubkeys_out=keys_file,
                                   announce=False, limits=TEST_LIMITS))
    owner.client = client
    owner.origin = client.get("/v2/tlog/checkpoint").json()["origin"]
    _APPS.append(client)
    return client


# ----------------------------------------------------------------------
# the policy build
# ----------------------------------------------------------------------


class TestPolicyBuild:
    def test_unset_is_the_launch_policy(self):
        assert parse_witness_policy(None) == parse_witness_policy("  ") == NO_WITNESSES
        assert NO_WITNESSES.policy() == {"quorum": 0, "witnesses": []}
        assert NO_WITNESSES.max_checkpoint_age == MAX_CHECKPOINT_AGE == 300

    def test_the_feeder_syntax_gives_founder_members_at_quorum_one(self, vkey, witness_env):
        config = parse_witness_policy(witness_env)
        # The card's name is the cosigner name the vkey carries, not the feeder's local label.
        assert config.policy() == {"quorum": 1, "witnesses": [
            {"name": WITNESS_NAME, "vkey": vkey, "trust_domain": "founder", "independent": False}]}
        assert config.max_checkpoint_age == 300 and config.witnesses[0].url == WITNESS_URL

    def test_the_json_file_the_feeder_reads(self, tmp_path, vkey):
        path = tmp_path / "witnesses.json"
        path.write_text(json.dumps({"witnesses": [{"name": "oracle", "url": WITNESS_URL, "vkey": vkey}]}))
        assert parse_witness_policy(str(path)).policy()["witnesses"][0]["vkey"] == vkey
        path.write_text(json.dumps([{"name": "oracle", "url": WITNESS_URL, "vkey": vkey, "independent": True}]))
        with pytest.raises(CardError, match="witnesses"):
            parse_witness_policy(str(path))

    @pytest.mark.parametrize("make, message", [
        (lambda v: f"w=ftp://w.example={v}", "URL"),
        (lambda v: "w=https://w.example=not-a-vkey", "verifier key"),
        (lambda v: f"w=https://w.example={v},x=https://x.example={v}", "unique"),
        (lambda v: "w=https://w.example", "name=url=vkey"),
        (lambda v: "w=https://w.example=" + format_vkey(vkey_from_ed25519(
            "log.example/x", Ed25519PrivateKey.generate().public_key())), "type 0x04"),
    ])
    def test_malformed_settings_are_refused(self, vkey, make, message):
        with pytest.raises(CardError, match=message):
            parse_witness_policy(make(vkey))

    def test_g5_bound(self, vkey):
        founder = {"name": WITNESS_NAME, "vkey": vkey, "trust_domain": "founder", "independent": False}
        assert "quorum 0" in g5_bound({"quorum": 0, "witnesses": []})
        assert "proves freshness, not independence" in g5_bound({"quorum": 1, "witnesses": [founder]})
        external = [{"name": f"w{i}", "vkey": cosignature_vkey(f"w{i}.example/w"), "trust_domain": f"org-{i}",
                     "independent": True} for i in range(3)]
        assert g5_bound({"quorum": 2, "witnesses": external}) is None
        assert "intersect" in g5_bound({"quorum": 2, "witnesses": [founder, *external[:2]]})


# ----------------------------------------------------------------------
# the skeleton states it
# ----------------------------------------------------------------------


class TestSkeleton:
    def test_the_served_skeleton_lists_the_fed_witness_and_g5_stays_promised(
            self, db_path, owner, monkeypatch, vkey, witness_env):
        monkeypatch.setenv("AICS_WITNESSES", witness_env)
        client = make_app(db_path, owner)
        card = client.get("/.well-known/aics-card.json").json()
        assert card["witness_policy"] == {"quorum": 1, "witnesses": [
            {"name": WITNESS_NAME, "vkey": vkey, "trust_domain": "founder", "independent": False}]}
        assert card["max_checkpoint_age"] == 300
        row = g5(card)
        assert row["status"] == "promised"
        text = " ".join(row["assumptions"])
        assert "Witness policy of this card: quorum 1 of 1 listed witness(es)" in text
        assert "A founder-run witness proves freshness, not independence." in text
        for words in ("cosignature/v1", "now - 300 <= t <= now + 30", "max_checkpoint_age", "stale",
                      "never with keys taken from the checkpoint", f"{WITNESS_URL}/<hex SHA-256 of the origin>/checkpoint",
                      "ML-DSA-44", "sign-subtree", "intersect in an honest", "Relies on witness independence"):
            assert words in text, words
        assert verify_card(card, client.app.state.db.policy_pub)
        page = client.get("/card", headers={"Accept": "text/html"}).text
        assert "quorum 1;" in page
        # The HTML view shows the vkey too, where the homepage sends people for it (readiness docs pass).
        assert f"<code>{WITNESS_NAME}</code> (vkey <code>{vkey}</code>; founder, not independent)" in page
        # The skeleton with the witness is a card this server logs.
        assert owner.policy_now(client.get("/.well-known/aics-card.json").text).status_code == 201

    def test_without_the_setting_the_launch_text_stays(self, client):
        row = g5(client.get("/.well-known/aics-card.json").json())
        assert "quorum 0, no witness" in " ".join(row["assumptions"])
        assert "ML-DSA-44" in " ".join(row["assumptions"])  # AICS-1 section 13.3 asks for the deviation


# ----------------------------------------------------------------------
# a file card and a logged card list only fed witnesses
# ----------------------------------------------------------------------


class TestCheckedCards:
    def file_app(self, tmp_path, db_path, owner, monkeypatch, body) -> TestClient:
        path = tmp_path / "card-unsigned.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        monkeypatch.setenv("AICS_CARD_FILE", str(path))
        return make_app(db_path, owner)

    def test_a_file_card_at_quorum_zero_is_served_while_the_witness_is_fed(
            self, client, tmp_path, db_path, owner, monkeypatch, witness_env):
        body = unsigned(client.get("/.well-known/aics-card.json").json())
        monkeypatch.setenv("AICS_WITNESSES", witness_env)
        reviewed = self.file_app(tmp_path, db_path, owner, monkeypatch, body)
        served = reviewed.get("/.well-known/aics-card.json")
        assert served.headers["x-aics-card-source"] == "file"
        assert served.json()["witness_policy"] == {"quorum": 0, "witnesses": []}

    def test_a_file_card_naming_a_witness_this_server_does_not_feed_stops_the_start(
            self, client, tmp_path, db_path, owner, monkeypatch, vkey, witness_env):
        body = unsigned(client.get("/.well-known/aics-card.json").json())
        monkeypatch.setenv("AICS_WITNESSES", witness_env)
        body["witness_policy"] = {"quorum": 1, "witnesses": [
            {"name": "other.example/w", "vkey": cosignature_vkey("other.example/w"), "trust_domain": "founder",
             "independent": False}]}
        with pytest.raises(CardError, match="not one this server feeds"):
            self.file_app(tmp_path, db_path, owner, monkeypatch, body)
        body["witness_policy"] = parse_witness_policy(witness_env).policy()
        body["max_checkpoint_age"] = 900
        with pytest.raises(CardError, match="max_checkpoint_age"):
            self.file_app(tmp_path, db_path, owner, monkeypatch, body)
        body["max_checkpoint_age"] = 300
        g5(body)["status"] = "proven"
        with pytest.raises(CardError, match="founder-run witness proves freshness"):
            self.file_app(tmp_path, db_path, owner, monkeypatch, body)
        g5(body)["status"] = "promised"
        assert self.file_app(tmp_path, db_path, owner, monkeypatch, body).get(
            "/.well-known/aics-card.json").json()["witness_policy"]["quorum"] == 1

    def test_card_problems_checks_each_witness(self, client, vkey, witness_env):
        db = client.app.state.db
        config = parse_witness_policy(witness_env)
        body = unsigned(client.get("/.well-known/aics-card.json").json())
        parent = db.list_policies()["policies"][-1]["leaf_index"]

        def problems(**changes):
            card = sign_card(dict(body, **changes), db.policy_key, db.policy_did)
            return card_problems(card, db, parent_index=parent, witnesses=config)

        fed = config.policy()
        assert problems(witness_policy=fed) == []
        assert problems() == []  # quorum 0: fewer witnesses than are fed is allowed
        log_type = format_vkey(vkey_from_ed25519(WITNESS_NAME, Ed25519PrivateKey.generate().public_key()))
        bad = problems(witness_policy={"quorum": 1, "witnesses": [dict(fed["witnesses"][0], vkey=log_type)]})
        assert any("type 0x04" in p for p in bad) and any("not one this server feeds" in p for p in bad)
        independent = problems(witness_policy={"quorum": 1, "witnesses": [dict(fed["witnesses"][0], independent=True)]})
        assert any("never independent" in p for p in independent)
        assurances = [dict(a, status="proven") if a["id"] == "G5" else a for a in body["assurances"]]
        assert any("proves freshness, not independence" in p
                   for p in problems(witness_policy=fed, assurances=assurances))

    def test_the_server_refuses_to_log_a_card_naming_an_unfed_witness(self, client, owner, witness_env):
        db = client.app.state.db
        body = unsigned(client.get("/.well-known/aics-card.json").json())
        body["witness_policy"] = parse_witness_policy(witness_env).policy()  # this server feeds none
        document = canonicalize(sign_card(body, db.policy_key, db.policy_did)).decode()
        refused = owner.policy_now(document)
        assert refused.status_code == 400 and "not one this server feeds" in refused.text


# ----------------------------------------------------------------------
# the preview endpoint and the successor flow
# ----------------------------------------------------------------------


@pytest.fixture()
def bootstrapped(client, tmp_path, db_path, owner, monkeypatch, keys_file, witness_env):
    """The production situation: a logged bootstrap card at quorum 0, then the witness fed (AICS_WITNESSES set)."""
    body = unsigned(client.get("/.well-known/aics-card.json").json())
    path = tmp_path / "card-unsigned.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setenv("AICS_CARD_FILE", str(path))
    monkeypatch.setenv("AICS_WITNESSES", witness_env)
    app = make_app(db_path, owner, keys_file)
    bootstrap = app.get("/.well-known/aics-card.json").content
    logged = owner.policy_now(bootstrap.decode())
    assert logged.status_code == 201, logged.text
    assert app.get("/.well-known/aics-card.json").headers["x-aics-card-source"] == "logged"
    return app, bootstrap, logged.json()["policy"]["leaf_index"]


def successor_overlay(app: TestClient, witness_env: str) -> dict:
    """The reviewed successor body: the fed witness at quorum 1 and the G5 row stating it."""
    db = app.app.state.db
    config = parse_witness_policy(witness_env)
    skeleton = build_skeleton(db, app.app.state.card.site, witnesses=config)
    current = app.get("/.well-known/aics-card.json").json()
    assurances = [g5(skeleton) if a["id"] == "G5" else a for a in current["assurances"]]
    return {"witness_policy": config.policy(), "max_checkpoint_age": config.max_checkpoint_age,
            "assurances": assurances}


class TestPreview:
    def preview(self, owner, body) -> dict:
        response = owner.admin("/v2/admin/card/preview", {"body": json.dumps(body)})
        assert response.status_code == 200, response.text
        return response.json()

    def body(self, app, witness_env, parent, **changes) -> dict:
        current = unsigned(app.get("/.well-known/aics-card.json").json())
        now = int(time.time())
        return {**current, **successor_overlay(app, witness_env), "issued_at": now, "expires": now + 365 * 86400,
                "policy_parent_index": parent, **changes}

    def test_owner_only(self, client):
        assert client.post("/v2/admin/card/preview", json={"body": "{}"}).status_code == 401

    def test_before_any_card_is_logged(self, client, owner):
        body = unsigned(client.get("/.well-known/aics-card.json").json())
        answer = self.preview(owner, body)
        assert answer["document"] is None and any("no card is logged yet" in p for p in answer["problems"])

    def test_a_reviewed_successor_is_signed_checked_and_not_logged(self, bootstrapped, owner, witness_env):
        app, bootstrap, leaf = bootstrapped
        db = app.app.state.db
        size = app.get("/v2/tlog/checkpoint").json()["tree_size"]
        body = self.body(app, witness_env, leaf)
        answer = self.preview(owner, body)
        assert answer["problems"] == [], answer["problems"]
        document = answer["document"].encode()
        card = json.loads(document)
        assert canonicalize(card) == document and unsigned(card) == body and verify_card(card, db.policy_pub)
        assert answer["document_hash"] == hashlib.sha256(document).hexdigest()
        assert answer["payload_sha256"] == hashlib.sha256(canonicalize(body)).hexdigest()
        assert answer["policy_parent_index"] == leaf
        assert answer["current"] == {"leaf_index": leaf, "document_hash": hashlib.sha256(bootstrap).hexdigest()}
        assert answer["pending"] is None and answer["notice_seconds"] == POLICY_NOTICE_SECONDS
        assert answer["not_before_min"] >= int(time.time()) + POLICY_NOTICE_SECONDS - 5
        assert {"witness_policy", "assurances"} <= set(answer["changed_members"])
        assert app.get("/v2/tlog/checkpoint").json()["tree_size"] == size  # a preview writes no leaf
        assert app.get("/.well-known/aics-card.json").content == bootstrap

    @pytest.mark.parametrize("change, message", [
        (lambda b: b.update(policy_parent_index=0), "policy_parent_index"),
        (lambda b: b.update(expires=int(time.time()) + 40 * 86400), "two notice periods"),
        (lambda b: b.update(issued_at=1), "issued_at must not lie before"),
        (lambda b: b.update(witness_policy={"quorum": 1, "witnesses": [
            {"name": "other.example/w", "vkey": cosignature_vkey("other.example/w"), "trust_domain": "founder",
             "independent": False}]}), "not one this server feeds"),
        (lambda b: b["assurances"][0].update(claim="<FILL:CLAIM>"), "placeholders"),
        (lambda b: b.update(signatures=[]), "unsigned body"),
    ])
    def test_problems_are_listed_and_nothing_is_signed(self, bootstrapped, owner, witness_env, change, message):
        app, _, leaf = bootstrapped
        body = self.body(app, witness_env, leaf)
        change(body)
        answer = self.preview(owner, body)
        assert answer["document"] is None and any(message in p for p in answer["problems"]), answer["problems"]

    def test_strict_json(self, bootstrapped, owner):
        response = owner.admin("/v2/admin/card/preview", {"body": '{"spec": 1.5}'})
        assert response.status_code == 200 and "integer" in response.json()["problems"][0]


class TestSuccessorFlow:
    def owner_client(self, sdk, app, owner):
        return sdk.OwnerClient(owner.key, base_url="http://testserver", transport_fn=route_to_testclient(app, sdk),
                               log_vkey=app.app.state.db.server_vkey)

    def test_the_owner_logs_a_successor_with_the_notice_period(self, sdk, bootstrapped, owner, witness_env):
        app, bootstrap, leaf = bootstrapped
        boss = self.owner_client(sdk, app, owner)
        overlay = successor_overlay(app, witness_env)
        size = app.get("/v2/tlog/checkpoint").json()["tree_size"]
        dry = boss.log_successor_card(overlay, dry_run=True)
        assert dry["dry_run"] is True and dry["problems"] == [] and dry["base"]["leaf_index"] == leaf
        assert app.get("/v2/tlog/checkpoint").json()["tree_size"] == size
        before = int(time.time())
        result = boss.log_successor_card(overlay)
        policy = result["policy"]
        successor = result["successor"]
        assert policy["kind"] == "card" and policy["prev_policy_index"] == leaf
        assert policy["document_hash"] == successor["document_hash"]
        assert policy["not_before"] >= before + POLICY_NOTICE_SECONDS + sdk.CARD_NOTICE_MARGIN_SECONDS
        assert result["receipt"] == "verified"
        # The successor waits for its notice period; the bootstrap card is served until then.
        assert app.get("/.well-known/aics-card.json").content == bootstrap
        logged = app.get(f"/v2/policies/{policy['leaf_index']}").content
        assert hashlib.sha256(logged).hexdigest() == policy["document_hash"]
        taken = app.app.state.card.current(now=policy["not_before"] + 1)
        assert taken.source == "logged" and taken.leaf_index == policy["leaf_index"]
        assert taken.card["witness_policy"]["quorum"] == 1 and g5(taken.card)["status"] == "promised"
        assert taken.card["policy_parent_index"] == leaf and taken.card["issued_at"] >= before
        assert verify_card(taken.card, app.app.state.db.policy_pub) and sdk.verify_card_signature(taken.card)
        # Another successor waits until this one is in effect.
        with pytest.raises(sdk.AICSClientError, match="waiting for its notice period"):
            boss.log_successor_card(overlay)

    def test_the_tool_refuses_other_keys_and_an_early_not_before(self, sdk, bootstrapped, owner, witness_env):
        app, _, _ = bootstrapped
        boss = self.owner_client(sdk, app, owner)
        overlay = successor_overlay(app, witness_env)
        with pytest.raises(sdk.AICSClientError, match="same keys"):
            boss.log_successor_card(dict(overlay, log_vkey="other.example/log+00000000+AQ"))
        with pytest.raises(sdk.AICSClientError, match="inside the notice period"):
            boss.log_successor_card(overlay, not_before=int(time.time()) + 86400)
        with pytest.raises(sdk.AICSClientError, match="would not log"):
            boss.log_successor_card(dict(overlay, max_checkpoint_age=900))

    def test_the_tool_needs_a_logged_card(self, sdk, client, owner):
        boss = self.owner_client(sdk, client, owner)
        with pytest.raises(sdk.AICSClientError, match="no card is logged yet"):
            boss.log_successor_card({})

    def test_the_command_line(self, sdk, bootstrapped, owner, witness_env, tmp_path, monkeypatch, capsys):
        from cryptography.hazmat.primitives import serialization

        app, bootstrap, leaf = bootstrapped
        key_file = tmp_path / "owner.pem"
        key_file.write_bytes(owner.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
        overlay_file = tmp_path / "successor.json"
        overlay_file.write_text(json.dumps(successor_overlay(app, witness_env)), encoding="utf-8")
        inner = route_to_testclient(app, sdk)
        monkeypatch.setattr(sdk, "_default_transport", lambda m, u, h, b, timeout: inner(m, u, h, b))
        base = ["owner", "--key", str(key_file), "--base-url", "http://testserver",
                "--log-vkey", app.app.state.db.server_vkey, "log-card"]
        assert sdk.main([*base, "--successor", str(overlay_file), "--dry-run"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["dry_run"] is True and out["policy_parent_index"] == leaf
        assert sdk.main([*base, "--document-file", str(overlay_file), "--dry-run"]) == 1  # --dry-run is --successor's
        capsys.readouterr()
        assert sdk.main([*base, "--successor", str(overlay_file)]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["policy"]["kind"] == "card" and out["successor"]["document_hash"] == out["policy"]["document_hash"]
        overlay_file.write_text('{"max_checkpoint_age": 300, "max_checkpoint_age": 301}', encoding="utf-8")
        assert sdk.main([*base, "--successor", str(overlay_file), "--dry-run"]) == 1
        assert "repeats" in capsys.readouterr().err


class TestNoticeOfTheCardInEffect:
    """AICS-1 section 6.4: a change gives the old card's advertised notice period, never less than the server's."""

    def test_the_bootstrap_card_advertises_the_servers_period(self, bootstrapped):
        app, _, _ = bootstrapped
        assert app.app.state.db.policy_notice_seconds() == POLICY_NOTICE_SECONDS

    def test_a_longer_advertised_period_is_enforced_when_logging(self, bootstrapped, owner, monkeypatch):
        import aics_server.card as card_module

        app, _, _ = bootstrapped
        db = app.app.state.db
        longer = 2 * POLICY_NOTICE_SECONDS
        strict = card_module._parse_strict

        # This server only logs cards advertising its own period, so a card advertising more is simulated:
        # the logged bootstrap card read back with a longer policy_notice_seconds (its signature then no longer
        # covers it, so verification is stubbed for this read).
        def advertising_longer(data):
            card = strict(data)
            return dict(card, policy_notice_seconds=longer) if isinstance(card, dict) else card

        monkeypatch.setattr(card_module, "_parse_strict", advertising_longer)
        monkeypatch.setattr(card_module, "verify_card", lambda card, key: True)
        assert db.policy_notice_seconds() == longer
        size = app.get("/v2/tlog/checkpoint").json()["tree_size"]
        early = owner.policy(not_before=int(time.time()) + POLICY_NOTICE_SECONDS + 86400)
        assert early.status_code == 400 and f"{longer // 86400} days" in early.text, early.text
        assert app.get("/v2/tlog/checkpoint").json()["tree_size"] == size + 1  # the refusal leaf, no policy leaf
        late = owner.policy(not_before=int(time.time()) + longer + 60)
        assert late.status_code == 201, late.text
        assert late.json()["policy"]["kind"] == "change"
