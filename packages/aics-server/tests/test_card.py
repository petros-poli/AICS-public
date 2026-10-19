"""The assurance card at /card and /.well-known/aics-card.json (AICS-1 section 13, DESIGN.md G10).

The card is signed with the policy key as AICS-1 section 13.2 says (JWS over
JCS: the A2A v1.0.0 card procedure) and checked here with the policy key from
the out-of-band key file, never from the API.  The built-in skeleton advertises the
profile this server implements, AICS-1+SUP-1 (section 20.9): every section 13.1 member
and the profile's ``sup``, the status column of DESIGN.md section 3 (G2 proven;
the other G rows promised; N1 to N5 not offered), the placeholder witness
policy, this server's limits, closed code lists, secret patterns and spec
versions.  Once the owner logs a card as a policy leaf, that logged card is
what is served; a reviewed card body can be supplied with ``AICS_CARD_FILE``.
"""

from __future__ import annotations

import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonicalize, keys
from aics_server.app import create_app
from aics_server.card import (
    BASE_CARD_MEMBERS,
    CARD_MEMBERS,
    SPEC_VERSIONS,
    CardError,
    pattern_hash,
    sign_card,
    verify_card,
)
from aics_server.db import (
    AUDIT_OUTCOMES,
    BASE_REFUSAL_REGISTRY,
    CONTRIBUTION_TX_RETENTION_SECONDS,
    ENCRYPTION_SCHEMES,
    FREEZE_REASONS,
    INTENT_CLAIM_SECONDS,
    INTENT_TTL_SECONDS,
    NOTICE_OUTCOMES,
    POLICY_NOTICE_SECONDS,
    REFUSAL_REASONS,
    SUP_REFUSAL_REASONS,
    SUSPENSION_REASONS,
    TOMBSTONE_REASONS,
)
from aics_server import identity as ident
from aics_server.moderation import SECRET_PATTERN_DEFINITIONS, SECRET_PATTERNS

from conftest import PRIVACY_TEXT, TERMS_TEXT, TEST_LIMITS, Signer

HTML = {"Accept": "text/html"}
#: DESIGN.md section 3, status column: "exists" is proven, a week of the build or "promised" is promised.
EXPECTED_STATUS = {
    "G1": "promised", "G2": "proven", "G3": "promised", "G4": "promised", "G5": "promised", "G6": "promised",
    "G7": "promised", "G8": "promised", "G9": "promised", "G10": "promised",
    "N1": "not-offered", "N2": "not-offered", "N3": "not-offered", "N4": "not-offered", "N5": "not-offered",
}
CLAIM_NAMES = {
    "G1": "Authentic authorship", "G2": "Tamper-evident order", "G3": "No leaf deletion",
    "G4": "No silent censorship evidence", "G5": "Single view", "G6": "Private content",
    "G7": "Running code tied to source", "G8": "Verification survives the service",
    "G9": "Consent and inbox completeness", "G10": "Signed, logged card",
}


def jws_verifies(card: dict, public_key) -> bool:
    """AICS-1 section 13.2, written out here independently of aics_server.card."""
    (sig,) = card["signatures"]
    body = {k: v for k, v in card.items() if k != "signatures"}
    protected = keys.b64u_encode(canonicalize({"alg": "EdDSA", "kid": body["policy_kid"], "typ": "JOSE"}))
    if sig["protected"] != protected or set(sig) != {"protected", "signature"}:
        return False
    signing_input = f"{protected}.{keys.b64u_encode(canonicalize(body))}".encode("ascii")
    try:
        public_key.verify(keys.b64u_decode(sig["signature"]), signing_input)
    except Exception:
        return False
    return True


class TestServedCard:
    def test_both_paths_serve_the_same_signed_bytes(self, client, oob):
        response = client.get("/.well-known/aics-card.json")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        document = response.content
        assert client.get("/card").content == document  # agents fetching /card get the same bytes
        assert client.get("/card", params={"format": "json"}, headers=HTML).content == document
        card = json.loads(document)
        assert document == canonicalize(card)  # J(card), exactly
        assert response.headers["x-aics-card-sha256"] == hashlib.sha256(document).hexdigest()
        assert response.headers["x-aics-card-source"] == "skeleton"
        assert response.headers["x-aics-card-leaf"] == "none"
        assert jws_verifies(card, oob.policy_public)  # the key from the published key file, not from the API
        assert verify_card(card, oob.policy_public)
        assert not verify_card(card, Signer().public)

    def test_every_section_13_1_member_and_this_servers_keys(self, client):
        card = client.get("/.well-known/aics-card.json").json()
        assert list(card) == sorted(CARD_MEMBERS)  # JCS order; every member present, nothing else
        assert set(CARD_MEMBERS) == set(BASE_CARD_MEMBERS) | {"sup"}
        cp = client.get("/v2/tlog/checkpoint").json()
        assert card["spec"] == "AICS-1+SUP-1" and card["version"] == "0.2-draft"
        assert card["origin"] == cp["origin"] and card["log_vkey"] == cp["log_vkey"]
        assert card["policy_kid"] == cp["policy_did"] and card["policy_kid"].startswith("did:key:z6Mk")
        assert card["policy_kid"] == cp["policy_kid"] and keys.is_did_key(cp["policy_kid"])
        assert card["owner_kid"] == client.app.state.db.owner_did
        assert card["issued_at"] < card["expires"] and card["issued_at"] <= time.time() < card["expires"]
        assert card["policy_parent_index"] == 0  # the charter, the only policy leaf so far
        assert card["tile_prefixes"] == ["https://api.wesupport-ai.com/tiles", "https://tiles.wesupport-ai.com/tiles"]
        assert card["api_base"] == "https://api.wesupport-ai.com"
        assert card["gate"] == {
            "tls_host": "gate.wesupport-ai.com", "tls_port": 7700, "plaintext_port": 7701,
            "https_url": "https://api.wesupport-ai.com/t",
        }
        modes = {p["host"]: p["mode"] for p in card["proxy"]}
        assert modes == {
            "wesupport-ai.com": "cloudflare", "www.wesupport-ai.com": "cloudflare", "tiles.wesupport-ai.com": "cloudflare",
            "api.wesupport-ai.com": "dns-only", "gate.wesupport-ai.com": "dns-only", "ip.wesupport-ai.com": "dns-only",
        }
        assert card["policies"]["charter_hash"] == client.app.state.db.charter()["document_hash"]
        # AICS-1 section 13.1 types both as hash: the operator's AICS_TERMS_FILE and AICS_PRIVACY_FILE.
        assert card["policies"]["terms_hash"] == hashlib.sha256(TERMS_TEXT).hexdigest()
        assert card["policies"]["privacy_hash"] == hashlib.sha256(PRIVACY_TEXT).hexdigest()
        assert card["retention"]["ciphertext_budget_bytes"] == client.app.state.db.limits["ciphertext_budget_bytes"] > 0
        assert card["spec_versions"] == SPEC_VERSIONS

    def test_the_status_column_of_the_design(self, client):
        card = client.get("/.well-known/aics-card.json").json()
        rows = {a["id"]: a for a in card["assurances"]}
        assert [a["id"] for a in card["assurances"]] == list(EXPECTED_STATUS)
        assert {aid: a["status"] for aid, a in rows.items()} == EXPECTED_STATUS
        for aid, name in CLAIM_NAMES.items():
            assert rows[aid]["claim"].startswith(name + ":"), aid
        for aid, row in rows.items():
            assert set(row) == {"id", "status", "claim", "assumptions", "evidence"}
            assert row["assumptions"], aid
            if row["status"] == "promised":
                assert not any(w in row["claim"].lower() for w in ("cannot", "impossible", "prevents", "guaranteed")), aid
        assert "end-to-end encrypted" in rows["N1"]["claim"]

    def test_witness_placeholder_limits_codes_and_patterns(self, client):
        card = client.get("/.well-known/aics-card.json").json()
        db = client.app.state.db
        assert card["witness_policy"] == {"quorum": 0, "witnesses": []}
        assert card["max_checkpoint_age"] == 300 and card["mmd_seconds"] == 60
        assert card["policy_notice_seconds"] == POLICY_NOTICE_SECONDS == 2592000
        limits = card["limits"]
        assert limits["writes"] == db.limits["writes"] and limits["registrations"] == db.limits["registrations"]
        assert limits["preidentity"] == db.limits["preidentity"]
        assert limits["ciphertext_bytes"] == db.limits["ciphertext_bytes"] == 65536
        assert limits["public_body_bytes"] == 32768 and limits["envelope_window_seconds"] == 300
        assert limits["future_skew_seconds"] == 30 and limits["session_idle_seconds"] == 900
        assert card["retention"]["dm_seconds"] == 2**53 - 1
        assert card["retention"]["capsule_max_seconds"] == db.limits["capsule_max_seconds"]
        assert card["schemes"] == list(ENCRYPTION_SCHEMES)
        assert card["tiers"] == list(ident.TIERS)
        codes = card["reason_codes"]
        patterns = [p["id"] for p in card["secret_patterns"]]
        assert patterns == [pid for pid, _ in SECRET_PATTERNS]
        # AICS-1 sections 13.1 and 17.2: the registry of the advertised profile, charter-compatible spellings and
        # the profile's twelve codes included, plus one secret_format:<id> per published pattern; sorted here.
        expected = {*BASE_REFUSAL_REGISTRY, *SUP_REFUSAL_REASONS, *(f"secret_format:{p}" for p in patterns)}
        assert codes["refusal"] == sorted(expected) and len(codes["refusal"]) == 41 + 12 + len(patterns)
        assert set(REFUSAL_REASONS) <= expected  # every code this server writes is registered
        assert codes["tombstone"] == list(TOMBSTONE_REASONS)
        assert codes["suspension"] == list(SUSPENSION_REASONS) == ["order", "flood"]
        assert codes["freeze"] == list(FREEZE_REASONS)
        assert codes["revocation"] == list(ident.REVOKE_REASONS)
        assert codes["outcome"] == [*NOTICE_OUTCOMES, *AUDIT_OUTCOMES]
        # AICS-1 section 13.1: each pattern_hash is hexH(J(definition)) of its published entry {id, regex, note}.
        for entry, definition in zip(card["secret_patterns"], SECRET_PATTERN_DEFINITIONS, strict=True):
            assert set(definition) == {"id", "regex", "note"} and entry["id"] == definition["id"]
            expected = hashlib.sha256(canonicalize(definition)).hexdigest()
            assert entry["pattern_hash"] == pattern_hash(definition) == expected

    def test_the_sup_member_of_the_profile(self, client):
        """AICS-1 section 20.9: ``sup = {asset_hash, contributions, intent_seconds, claim_seconds, record_seconds, storage}``."""
        card = client.get("/.well-known/aics-card.json").json()
        sup = card["sup"]
        assert set(sup) == {"asset_hash", "contributions", "intent_seconds", "claim_seconds", "record_seconds", "storage"}
        asset = client.get("/v2/sup/asset")
        assert sup["asset_hash"] == hashlib.sha256(asset.content).hexdigest()
        assert sup["contributions"] == []  # no network is credited without a configured, checkable address
        assert 0 < sup["intent_seconds"] == INTENT_TTL_SECONDS <= sup["claim_seconds"] == INTENT_CLAIM_SECONDS
        assert sup["record_seconds"] == CONTRIBUTION_TX_RETENTION_SECONDS <= 31536000
        assert sup["storage"] is None  # capsules have no quota by default

    def test_the_sup_member_lists_each_credited_network(self, client, chain):
        sup = client.app.state.db.sup_card_member()
        networks = [c["network"] for c in sup["contributions"]]
        assert networks == ["base-usdc", "solana-usdc"]
        for entry in sup["contributions"]:
            assert set(entry) == {"network", "asset", "decimals", "address", "units_per_sup"}
            assert entry["asset"] == "USDC" and entry["decimals"] == 6 and entry["units_per_sup"] == 10**4

    def test_the_card_is_stable_until_the_policy_changes(self, client):
        first = client.get("/.well-known/aics-card.json").content
        assert client.get("/.well-known/aics-card.json").content == first
        restarted = client.app.state.card
        restarted._cache = None  # a fresh signature over the same state gives the same bytes
        assert client.get("/.well-known/aics-card.json").content == first

    def test_html_view_for_people(self, client):
        page = client.get("/card", headers=HTML)
        assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
        assert page.headers["vary"] == "Accept"
        text = page.text
        for aid in EXPECTED_STATUS:
            assert f'id="{aid}"' in text
        assert "status-proven" in text and "status-promised" in text and "status-not-offered" in text
        assert "No policy leaf carries its hash yet" in text
        assert "quorum 0; no witness" in text
        assert hashlib.sha256(client.get("/.well-known/aics-card.json").content).hexdigest() in text


class TestLoggedCard:
    def test_the_owner_logs_the_card_and_it_is_served_as_logged(self, client, owner, db_path):
        document = client.get("/.well-known/aics-card.json").content
        logged = owner.policy_now(document.decode("utf-8"))
        assert logged.status_code == 201, logged.text
        leaf = logged.json()["policy"]
        assert leaf["document_hash"] == hashlib.sha256(document).hexdigest()
        response = client.get("/.well-known/aics-card.json")
        assert response.content == document
        assert response.headers["x-aics-card-source"] == "logged"
        assert response.headers["x-aics-card-leaf"] == str(leaf["leaf_index"])
        assert "carries its hash, so you can check its inclusion" in client.get("/card", headers=HTML).text

    @pytest.mark.parametrize(
        "kind",
        ["not a card", "unsigned", "signed by another key", "expired", "not JCS", "null budget", "another parent",
         "unsigned terms", "another registry"],
    )
    def test_a_document_that_is_not_a_signed_section_13_1_card_is_never_logged(self, client, owner, kind):
        """The first card's hash becomes the trust bundle's bootstrap_card_hash (AICS-1 section 6.4): whatever its
        profile, a card leaf names exactly J(card) of a signed section 13.1 card this server follows."""
        before = client.get("/.well-known/aics-card.json").json()
        unsigned = {k: v for k, v in before.items() if k != "signatures"}
        db = client.app.state.db

        def signed(**changes):
            return canonicalize(sign_card(dict(unsigned, **changes), db.policy_key, db.policy_did)).decode()

        document = {
            "not a card": "not a card at all",
            "unsigned": json.dumps(unsigned),
            "signed by another key": json.dumps(sign_card(unsigned, Signer().key, unsigned["policy_kid"])),
            "expired": signed(issued_at=1, expires=2),
            "not JCS": json.dumps(sign_card(unsigned, db.policy_key, db.policy_did), indent=1),
            "null budget": signed(retention={**unsigned["retention"], "ciphertext_budget_bytes": None}),
            "another parent": signed(policy_parent_index=7),
            "unsigned terms": signed(policies={**unsigned["policies"], "terms_hash": None}),
            "another registry": signed(reason_codes={**unsigned["reason_codes"], "refusal": ["malformed"]}),
        }[kind]
        size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
        refused = owner.policy_now(document)
        assert refused.status_code == 400, refused.text
        # No policy leaf: the owner's authenticated request is refused with a refusal leaf naming its tuple
        # (AICS-1 section 10.2), and the served card does not change.
        assert client.get("/v2/tlog/checkpoint").json()["tree_size"] == size + 1
        leaf = refused.json()["detail"]["refusal"]["entry"]
        assert leaf["type"] == "refusal" and leaf["payload"]["reason_code"] == "malformed"
        assert leaf["payload"]["attempt_kid"] == owner.kid
        response = client.get("/.well-known/aics-card.json")
        assert response.headers["x-aics-card-source"] == "skeleton" and response.json() == before
        assert verify_card(response.json(), db.policy_pub)

    def test_the_skeleton_without_operator_documents_is_served_but_never_logged(self, tmp_path, owner, monkeypatch):
        monkeypatch.delenv("AICS_TERMS_FILE")
        monkeypatch.delenv("AICS_PRIVACY_FILE")
        bare = TestClient(create_app(db_path=tmp_path / "bare.db", owner_public_key=owner.public_key_b64u,
                                     announce=False, limits=TEST_LIMITS))
        owner.client = bare
        card = bare.get("/.well-known/aics-card.json")
        assert card.json()["policies"]["terms_hash"] is None  # served (signed), so a development server works ...
        refused = owner.policy_now(card.text)  # ... but no such card is ever logged
        assert refused.status_code == 400 and "terms_hash" in refused.text

    def test_a_card_waiting_for_its_notice_period_is_not_served_yet(self, client, owner):
        first = client.get("/.well-known/aics-card.json").content
        assert owner.policy_now(first.decode()).status_code == 201
        assert client.get("/.well-known/aics-card.json").headers["x-aics-card-source"] == "logged"
        successor = client.app.state.card.current()  # still the logged first card
        assert successor.source == "logged" and successor.document == first
        later = int(time.time()) + POLICY_NOTICE_SECONDS + 60
        body = {k: v for k, v in json.loads(first).items() if k != "signatures"}
        db = client.app.state.db
        parent = client.get("/.well-known/aics-card.json").headers["x-aics-card-leaf"]
        second = canonicalize(sign_card(dict(body, issued_at=body["issued_at"] + 1, policy_parent_index=int(parent)),
                                        db.policy_key, db.policy_did)).decode()
        assert owner.policy(document=second, kind="card", not_before=later).status_code == 201
        assert client.get("/.well-known/aics-card.json").content == first  # the successor is not effective yet
        publisher = client.app.state.card
        assert publisher.current(now=later - 1).document == first
        taken = publisher.current(now=later + 1)  # its notice period has passed: the successor is served
        assert taken.source == "logged" and taken.document.decode() == second

    def test_the_skeleton_is_reissued_each_period_and_never_served_expired(self, client):
        publisher = client.app.state.card
        first = publisher.current()
        later = publisher.current(now=first.card["expires"] + 10)
        assert later.card["issued_at"] == first.card["expires"] and later.card["expires"] > first.card["expires"] + 10
        assert verify_card(later.card, client.app.state.db.policy_pub)


class TestCardFile:
    def body(self, client) -> dict:
        card = client.get("/.well-known/aics-card.json").json()
        body = {k: v for k, v in card.items() if k != "signatures"}
        body["assurances"][0]["assumptions"].append("A reviewed statement.")
        return body

    def app_with(self, tmp_path, owner, monkeypatch, body) -> TestClient:
        path = tmp_path / "card-unsigned.json"
        path.write_text(json.dumps(body, indent=2), encoding="utf-8")
        monkeypatch.setenv("AICS_CARD_FILE", str(path))
        return TestClient(create_app(db_path=tmp_path / "test.db", owner_public_key=owner.public_key_b64u,
                                     announce=False, limits=TEST_LIMITS))

    def test_a_reviewed_body_is_signed_and_served(self, client, tmp_path, owner, monkeypatch, oob):
        body = self.body(client)
        reviewed = self.app_with(tmp_path, owner, monkeypatch, body)
        response = reviewed.get("/.well-known/aics-card.json")
        assert response.headers["x-aics-card-source"] == "file"
        card = response.json()
        assert {k: v for k, v in card.items() if k != "signatures"} == body
        assert jws_verifies(card, oob.policy_public)

    @pytest.mark.parametrize(
        "change, message",
        [
            (lambda b: b.update(log_vkey="example.org/log+00000000+AQ"), "log_vkey"),
            (lambda b: b.update(policy_kid=keys.did_key(Signer().public)), "policy_kid"),
            (lambda b: b.update(origin="other.example/tiles"), "origin"),
            (lambda b: b.update(issued_at="<FILL:ISSUED_AT>"), "placeholders"),
            (lambda b: b.pop("witness_policy"), "missing"),
            (lambda b: b.update(signatures=[]), "extra"),
        ],
    )
    def test_a_body_this_server_will_not_sign_stops_the_start(self, client, tmp_path, owner, monkeypatch, change, message):
        body = self.body(client)
        change(body)
        with pytest.raises(CardError, match=message):
            self.app_with(tmp_path, owner, monkeypatch, body)

    def test_a_reviewed_base_profile_body_is_still_served(self, client, tmp_path, owner, monkeypatch):
        body = self.body(client)
        body.pop("sup")
        body["spec"] = "AICS-1"
        reviewed = self.app_with(tmp_path, owner, monkeypatch, body)
        card = reviewed.get("/.well-known/aics-card.json").json()
        assert card["spec"] == "AICS-1" and "sup" not in card

    @pytest.mark.parametrize(
        "change, message",
        [
            (lambda b: b.update(spec="AICS-1+UNKNOWN-1"), "spec must be one of"),
            (lambda b: b.pop("sup"), "missing"),
            (lambda b: b.update(spec="AICS-1"), "extra"),
        ],
    )
    def test_a_body_must_have_the_members_of_its_profile(self, client, tmp_path, owner, monkeypatch, change, message):
        body = self.body(client)
        change(body)
        with pytest.raises(CardError, match=message):
            self.app_with(tmp_path, owner, monkeypatch, body)

    def test_strict_json_only(self, client, tmp_path, owner, monkeypatch):
        path = tmp_path / "card-unsigned.json"
        path.write_text('{"spec": "AICS-1", "spec": "again"}', encoding="utf-8")
        monkeypatch.setenv("AICS_CARD_FILE", str(path))
        with pytest.raises(CardError, match="duplicate"):
            create_app(db_path=tmp_path / "test.db", owner_public_key=owner.public_key_b64u, announce=False)
        path.write_text('{"spec": 1.5}', encoding="utf-8")
        with pytest.raises(CardError, match="integer"):
            create_app(db_path=tmp_path / "test.db", owner_public_key=owner.public_key_b64u, announce=False)


def test_sign_card_refuses_a_signed_body_or_another_key():
    signer = Signer()
    body = {"policy_kid": keys.did_key(signer.public), "spec": "AICS-1"}
    card = sign_card(body, signer.key, body["policy_kid"])
    assert verify_card(card, signer.public)
    with pytest.raises(CardError):
        sign_card(card, signer.key, body["policy_kid"])
    with pytest.raises(CardError):
        sign_card(body, signer.key, keys.did_key(Signer().public))
    tampered = dict(card, spec="AICS-2")
    assert not verify_card(tampered, signer.public)
    two = dict(card, signatures=card["signatures"] * 2)
    assert not verify_card(two, signer.public)
