"""The reviewed first card of genesis v2 (card/card-content.json) on this server, in the order card/README.md gives.

The relaunch of 2026-10-20 logs a first card that already names the founder-run witness at quorum 1 and proves G1,
G4, G6, G8 and G9 (card/README.md "Genesis v2").  This runs that order against the real app on a production genesis:

1. a first start without ``AICS_CARD_FILE`` and ``AICS_WITNESSES`` writes leaf 0 and the key file;
2. the reviewed body, filled with this server's keys by card/validate_card.py, is refused at start while
   ``AICS_WITNESSES`` is unset (the card names a witness this server does not feed);
3. with both set the server starts and serves the body signed, unlogged (``X-AICS-Card-Source: file``);
4. the owner's preview (``POST /v2/admin/card/preview``) answers one problem only: no card is logged yet;
5. the served bytes, logged by the owner as the bootstrap card, are the next leaf, and the server then serves them as
   the logged card under that index.

It runs twice: once as planned, the card at leaf 1, and once with a UTC midnight between leaf 0 and the card, when the
daily count report of leaf 0's day lands first (AICS-1 section 10.2) and the card is leaf 2.  The card's text and the
README's checks hold either way: they name the index the owner tool prints, never a literal 1.

The conformance reports the proven rows name are card/'s launch check; here their hashes are test values (the server
checks only that each evidence hash is a hash).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aics_server.app import create_app
from aics_server.card import CardError
from aics_tlog import format_vkey, vkey_from_ed25519

from conftest import Owner

REPO = Path(__file__).resolve().parents[3]
CARD_DIR = REPO / "card"
#: The two runs of the relaunch build (card/README.md "Genesis v2", step 0): at quorum 0 and at the card's quorum 1.
CONFORMANCE_REPORTS = ("docs/evidence/conformance-2026-10-20-relaunch-build.json",
                       "docs/evidence/conformance-2026-10-20-relaunch-build-quorum1.json")
#: A new witness identity for the new log: w1 cosigned the discarded one (card/validate_card.py RETIRED_WITNESS).
WITNESS_NAME = "witness.wesupport-ai.com/w2"
#: Nothing listens there: the feeder the setting starts fails at once, without a DNS lookup.
WITNESS_URL = "http://127.0.0.1:9/witness"
CUSTODIAN_HOLDS = ("named successor; receives a sealed offline copy of the server seed and the owner key when the "
                   "handover (decision 17b) is recorded")

pytestmark = pytest.mark.skipif(not (CARD_DIR / "card-content.json").is_file(), reason="card/ is not in this checkout")


def _validator() -> ModuleType:
    """card/validate_card.py (standard library only), loaded from the checkout."""
    name = "validate_card_genesis_v2"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, CARD_DIR / "validate_card.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


@pytest.fixture()
def production(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The production genesis of runbook step 4: the repository's charter, an owner key, no development waiver."""
    for var in ("AICS_DEV_GENESIS", "AICS_SERVER_SEED_HEX", "AICS_TILES_AUDIT", "AICS_ORIGIN", "AICS_PUBKEYS_OUT",
                "AICS_CARD_FILE", "AICS_WITNESSES", "AICS_LIMITS_FILE", "AICS_ALLOWED_HOSTS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AICS_PRODUCTION", "1")
    monkeypatch.setenv("AICS_CHARTER_FILE", str(REPO / "docs/legal/charter.md"))
    monkeypatch.setenv("AICS_TERMS_FILE", str(REPO / "docs/legal/terms.md"))
    monkeypatch.setenv("AICS_PRIVACY_FILE", str(REPO / "docs/legal/retention.md"))
    monkeypatch.setenv("AICS_TILES_DIR", str(tmp_path / "tiles"))
    return tmp_path


_APPS: list[TestClient] = []


@pytest.fixture(autouse=True)
def _stop_feeders():
    """Stop the witness feeder an app of this module started (AICS_WITNESSES starts it)."""
    yield
    while _APPS:
        stop = getattr(_APPS.pop().app.state.db, "stop_witness_feeder", None)
        if stop is not None:
            stop()


def start(root: Path, owner: Owner) -> TestClient:
    """One start of the server on the same database (DEFAULT_LIMITS: the windows the card states)."""
    client = TestClient(create_app(db_path=root / "aics.db", owner_public_key=owner.public_key_b64u,
                                   pubkeys_out=root / "pubkeys.txt", announce=False))
    _APPS.append(client)
    owner.client = client
    owner.origin = client.get("/v2/tlog/checkpoint").json()["origin"]
    return client


@pytest.mark.parametrize("midnight_first", [False, True], ids=["card-at-leaf-1", "daily-report-first"])
def test_the_genesis_v2_order_logs_the_reviewed_card_first(production: Path, monkeypatch: pytest.MonkeyPatch,
                                                           midnight_first: bool):
    vc = _validator()
    owner = Owner()

    # 1. First start: no card file and no witness; leaf 0 is the charter, the card served is the skeleton.
    first = start(production, owner)
    assert first.get("/.well-known/aics-card.json").headers["x-aics-card-source"] == "skeleton"
    assert [(p["leaf_index"], p["kind"]) for p in first.get("/v2/policies").json()["policies"]] == [(0, "charter")]
    pub = dict(re.findall(r"^(origin|log|policy|owner|charter-sha256) (\S+)$",
                          (production / "pubkeys.txt").read_text(), re.MULTILINE))
    assert pub["origin"] == vc.ORIGIN and pub["log"] != vc.DISCARDED_LOG["log_vkey"]
    # README "Genesis v2", the gate that ends step 1: leaf 0 pins the exported charter (here the checkout's).
    assert pub["charter-sha256"] == hashlib.sha256((REPO / "docs/legal/charter.md").read_bytes()).hexdigest()
    report_index = None
    if midnight_first:
        # A UTC midnight passes before the card is logged: the pass that runs on requests and every few minutes
        # appends the daily count report of leaf 0's day first (AICS-1 section 10.2).
        leaf0_day = int(first.app.state.db.get_tlog_proof(0)["leaf_data"]["ts"]) // 86400
        written = first.app.state.db.write_daily_reports(now=(leaf0_day + 1) * 86400 + 60)
        assert written == [1]
        report_index = written[0]

    # 2. The reviewed body, filled with this server's keys and the founder-run witness.
    witness_vkey = format_vkey(vkey_from_ed25519(WITNESS_NAME, Ed25519PrivateKey.generate().public_key(), 0x04))
    now = int(time.time())
    values = {
        "ISSUED_AT": str(now), "EXPIRES": str(now + 365 * 86400), "LOG_VKEY": pub["log"], "POLICY_KID": pub["policy"],
        "OWNER_KID": pub["owner"], "WITNESS_NAME": WITNESS_NAME, "WITNESS_VKEY": witness_vkey,
        "CIPHERTEXT_BUDGET_BYTES": str(first.get("/v2/limits").json()["limits"]["ciphertext_budget_bytes"]),
        "CUSTODIAN_NAME": "[custodian name withheld pending written agreement]", "CUSTODIAN_HOLDS": CUSTODIAN_HOLDS,
        **{f"SHA256:{rel}": hashlib.sha256(f"a test stand-in for {rel}".encode()).hexdigest()
           for rel in CONFORMANCE_REPORTS},
    }
    patterns = vc.load_json((REPO / "docs/legal/secret-patterns.json").read_bytes())
    body = vc.fill(vc.load_json((CARD_DIR / "card-content.json").read_bytes()), values, REPO, patterns)
    reviewed = vc.validate(body, final=True, patterns=patterns)
    assert reviewed.report.errors == []
    path = production / "card-unsigned.json"
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 3. AICS_CARD_FILE without AICS_WITNESSES: the server refuses to start on a card naming a witness it does not feed.
    monkeypatch.setenv("AICS_CARD_FILE", str(path))
    with pytest.raises(CardError, match="is not one this server feeds"):
        start(production, owner)

    # 4. Both set: the reviewed body is served, signed by the policy key, not yet logged.
    monkeypatch.setenv("AICS_WITNESSES", f"founder-w2={WITNESS_URL}={witness_vkey}")
    app = start(production, owner)
    served = app.get("/.well-known/aics-card.json")
    assert (served.headers["x-aics-card-source"], served.headers["x-aics-card-leaf"]) == ("file", "none")
    signed = vc.validate(vc.load_json(served.content), final=True, signed=True, patterns=patterns)
    assert signed.report.errors == [] and signed.payload == reviewed.payload

    # 5. The preview checks the signed card as a card leaf would be checked; for a first card its one problem is that
    #    no card is logged yet (the successor tool, owner log-card --successor --dry-run, needs a logged card).  A
    #    daily report is no policy leaf, so the card's parent is the charter either way.
    preview = owner.admin("/v2/admin/card/preview", {"body": path.read_text(encoding="utf-8")})
    assert preview.status_code == 200, preview.text
    assert [p.split(":")[0] for p in preview.json()["problems"]] == ["no card is logged yet"]
    assert preview.json()["policy_parent_index"] == 0

    # 6. The owner logs exactly the served bytes, effective at once, and the server serves it as logged, under the
    #    index the answer names (what `aics_client.py owner log-card` prints as policy.leaf_index).
    logged = owner.admin("/v2/admin/policy", {"kind": "card", "document": served.content.decode("utf-8"),
                                              "not_before": int(time.time())})
    assert logged.status_code == 201, logged.text
    leaf = logged.json()["policy"]
    assert leaf["kind"] == "card" and leaf["prev_policy_index"] == 0
    assert leaf["leaf_index"] == (2 if midnight_first else 1)
    if report_index is not None:
        assert leaf["leaf_index"] > report_index
    after = app.get("/.well-known/aics-card.json")
    assert after.content == served.content
    assert (after.headers["x-aics-card-source"], after.headers["x-aics-card-leaf"]) == ("logged",
                                                                                        str(leaf["leaf_index"]))
    cards = [p for p in app.get("/v2/policies").json()["policies"] if p["kind"] == "card"]
    assert [(c["leaf_index"], c["document_hash"]) for c in cards] == [
        (leaf["leaf_index"], hashlib.sha256(served.content).hexdigest())]
