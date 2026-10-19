"""aics trust build (runbook step 5): the AICS-1 §6.4 trust bundle from pubkeys.txt and the logged card."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from aics_identity import keys as idkeys
from aics_identity.canonical import canonicalize

from aics_cli.card import sign_card
from aics_cli.encoding import b64u_d
from aics_cli.trust import bundle_from_text

from conftest import API_BASE, Instance, Log, did

CHARTER_SHA = "c4" * 32


class Launch:
    """The launch directory of runbook step 5: pubkeys.txt, the logged card and the /v2/policies listing."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.inst = Instance(Log(3))
        self.card = self.inst.card
        self.card_bytes = canonicalize(self.card)
        self.pubkeys = {"origin": self.inst.log.origin, "log": self.inst.log.vkey,
                        "log-kid": did(self.inst.log.key),
                        "policy": did(self.inst.policy_key), "policy-kid": did(self.inst.policy_key),
                        "owner": did(self.inst.owner_key), "owner-kid": did(self.inst.owner_key),
                        "charter-index": "0", "charter-sha256": CHARTER_SHA}
        self.policies: dict[str, Any] = {"count": 2, "notice_seconds": 0, "tree_size": 3, "policies": [
            {"leaf_index": 0, "leaf_hash_hex": "00" * 32, "kind": "charter", "document_hash": CHARTER_SHA,
             "size": 100, "prev_policy_index": None, "effective_after": 0, "not_before": 0},
            {"leaf_index": 1, "leaf_hash_hex": "01" * 32, "kind": "card", "document_hash": self.card_hash,
             "size": len(self.card_bytes), "prev_policy_index": 0, "effective_after": 1, "not_before": 0}]}

    @property
    def card_hash(self) -> str:
        return hashlib.sha256(self.card_bytes).hexdigest()

    def write(self) -> list[str]:
        (self.root / "pubkeys.txt").write_text(
            "# Keys of the AICS log, written by aics-server at start-up.\n"
            + "".join(f"{k} {v}\n" for k, v in self.pubkeys.items()), "utf-8")
        (self.root / "card.json").write_bytes(self.card_bytes)
        (self.root / "policies.json").write_text(json.dumps(self.policies), "utf-8")
        return ["trust", "build", "--pubkeys", str(self.root / "pubkeys.txt"), "--card", str(self.root / "card.json")]

    def args(self) -> list[str]:
        return [*self.write(), "--policies-file", str(self.root / "policies.json")]


@pytest.fixture
def launch(tmp_path: Path) -> Launch:
    return Launch(tmp_path)


def test_the_bundle_and_its_published_forms(h, launch):
    code, out = h.run(*launch.args())
    assert code == 0, out
    jcs = out["bundle_jcs"].encode("utf-8")
    assert json.loads(jcs) == {"v": 1, "origin": launch.inst.log.origin, "log_vkey": launch.inst.log.vkey,
                               "policy_kid": did(launch.inst.policy_key), "owner_kid": did(launch.inst.owner_key),
                               "bootstrap_card_hash": launch.card_hash}
    assert canonicalize(json.loads(jcs)) == jcs
    assert out["sha256"] == hashlib.sha256(jcs).hexdigest()
    assert out["txt"].startswith("aics1=") and b64u_d(out["txt"][len("aics1="):]) == jcs
    assert out["card_leaf_index"] == 1 and out["card_hash"] == launch.card_hash
    assert out["bundle"] == launch.inst.bundle.to_dict()  # the conftest instance's own bundle
    # the README block is what aics policy init --bundle reads, digest line included
    block = out["readme_block"]
    assert f"\n{out['txt']}\nsha256: {out['sha256']}\n" in block
    assert bundle_from_text(block).jcs == jcs
    assert bundle_from_text("".join("    " + line + "\n" for line in block.splitlines())).jcs == jcs


def test_the_text_output_carries_every_form(h, launch):
    code, text = h.run_text(*launch.args())
    assert code == 0, text
    code, out = h.run(*launch.args())
    for line in (out["bundle_jcs"], out["txt"], f"sha256 {out['sha256']}", f"    sha256: {out['sha256']}"):
        assert line in text.splitlines(), line


def test_the_listing_is_fetched_from_the_card_api_base(h, launch):
    h.fetcher.set(API_BASE + "/v2/policies", json.dumps(launch.policies))
    code, out = h.run(*launch.write())
    assert code == 0, out
    assert out["policies_source"] == API_BASE + "/v2/policies"


def test_an_explicit_policies_url(h, launch):
    h.fetcher.set("https://elsewhere.test/v2/policies", json.dumps(launch.policies))
    code, out = h.run(*launch.write(), "--policies-url", "https://elsewhere.test/v2/policies")
    assert code == 0 and out["policies_source"] == "https://elsewhere.test/v2/policies", out
    code, out = h.run(*launch.write(), "--policies-url", "https://nowhere.test/v2/policies")
    assert code == 1 and "HTTP 404" in out["error"], out


@pytest.mark.parametrize("change", ["pretty", "newline", "reordered"])
def test_the_card_file_must_be_j_card(h, launch, change):
    launch.card_bytes = {
        "pretty": json.dumps(launch.card, indent=1).encode(),
        "newline": canonicalize(launch.card) + b"\n",
        "reordered": json.dumps(dict(reversed(list(launch.card.items()))), separators=(",", ":")).encode(),
    }[change]
    code, out = h.run(*launch.args())
    assert code == 1 and "not J(card)" in out["error"], out


def test_no_policy_leaf_names_the_card(h, launch):
    launch.policies["policies"][1]["document_hash"] = "ee" * 32
    code, out = h.run(*launch.args())
    assert code == 1 and "no policy leaf of kind card names this card" in out["error"], out


def test_a_leaf_of_another_kind_does_not_count(h, launch):
    launch.policies["policies"][1]["kind"] = "terms"
    code, out = h.run(*launch.args())
    assert code == 1 and "no policy leaf of kind card" in out["error"], out


def test_the_leaf_size_must_be_the_files(h, launch):
    launch.policies["policies"][1]["size"] += 1
    code, out = h.run(*launch.args())
    assert code == 1 and "size" in out["error"], out


def test_a_later_card_leaf_is_noted(h, launch):
    earlier = dict(launch.policies["policies"][1], leaf_index=1, document_hash="dd" * 32)
    launch.policies["policies"][1]["leaf_index"] = 2
    launch.policies["policies"].insert(1, earlier)
    code, out = h.run(*launch.args())
    assert code == 0 and out["card_leaf_index"] == 2, out
    assert any("not the log's first card leaf" in n for n in out["notes"]), out


def test_leaf_zero_must_be_the_charter_of_pubkeys(h, launch):
    launch.pubkeys["charter-sha256"] = "ab" * 32
    code, out = h.run(*launch.args())
    assert code == 1 and "charter" in out["error"], out


@pytest.mark.parametrize("label", ["origin", "log", "policy", "owner"])
def test_the_keys_must_be_the_cards(h, launch, label):
    other = Instance(Log(1, origin="other.test/tiles"))
    launch.pubkeys[label] = {"origin": other.log.origin, "log": other.log.vkey, "policy": did(other.policy_key),
                             "owner": did(other.owner_key)}[label]
    launch.pubkeys.pop("log-kid", None)
    launch.pubkeys.pop(f"{label}-kid", None)
    code, out = h.run(*launch.args())
    assert code == 1, out
    assert "not pubkeys.txt's" in out["error"] or "signature" in out["error"], out


def test_the_card_must_be_signed_by_the_policy_key(h, launch):
    stranger = idkeys.generate_keypair()
    launch.card = sign_card(launch.card, stranger, did(launch.inst.policy_key))
    launch.card_bytes = canonicalize(launch.card)
    launch.policies["policies"][1].update(document_hash=launch.card_hash, size=len(launch.card_bytes))
    code, out = h.run(*launch.args())
    assert code == 1 and "no signature of the card verifies with the policy key" in out["error"], out


def test_the_card_must_be_a_section_13_1_card(h, launch):
    body = {k: v for k, v in launch.card.items() if k not in ("signatures", "retention")}
    launch.card = sign_card(body, launch.inst.policy_key, did(launch.inst.policy_key))
    launch.card_bytes = canonicalize(launch.card)
    code, out = h.run(*launch.args())
    assert code == 1 and "cannot be the bootstrap card" in out["error"], out


@pytest.mark.parametrize("edit,message", [
    (lambda p: p.pop("owner"), "no owner line"),
    (lambda p: p.update(owner="none", **{"owner-kid": "none"}), "names no owner key"),
    (lambda p: p.update(**{"policy-kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}),
     "policy-kid"),
    (lambda p: p.update(**{"log-kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}), "log-kid"),
])
def test_pubkeys_txt_is_checked(h, launch, edit, message):
    edit(launch.pubkeys)
    code, out = h.run(*launch.args())
    assert code == 1 and message in out["error"], out


def test_a_repeated_label_with_another_value_is_refused(h, launch):
    args = launch.args()
    with (launch.root / "pubkeys.txt").open("a", encoding="utf-8") as f:
        f.write(f"policy {did(launch.inst.owner_key)}\n")
    code, out = h.run(*args)
    assert code == 1 and "two different values for 'policy'" in out["error"], out


def test_policies_url_and_file_exclude_each_other(h, launch):
    code, out = h.run(*launch.args(), "--policies-url", "https://x.test/v2/policies")
    assert code == 1 and "not both" in out["error"], out


def test_a_listing_that_is_not_v2_policies_is_refused(h, launch):
    args = launch.args()
    (launch.root / "policies.json").write_text('{"items": []}', "utf-8")
    code, out = h.run(*args)
    assert code == 1 and "'policies' array" in out["error"], out
