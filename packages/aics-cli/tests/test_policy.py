"""aics policy init / show / diff: the AICS-1 §6.4 trust bundle from DNS,
the PyPI constant and the README; the witness policy from the bootstrap
card; never a key from the API host alone."""

from __future__ import annotations

import json
import tomllib

import pytest
from aics_identity import keys as idkeys
from aics_tlog import format_vkey, vkey_from_ed25519

from aics_cli import published_keys
from aics_cli.errors import PolicyError
from aics_cli.policy import Policy, dumps, loads, parse_policy_key
from aics_cli.trust import bundle_from_jcs, bundle_from_text, parse_txt

from conftest import CARD_URL, CHECKPOINT_URL, DOMAIN, MIRROR, NOW, PREFIX, TXT_NAME, Instance, Log, Witness, did

API_CP = "https://api.log.test/v2/tlog/checkpoint"


def serve_api(h, log, vkey=None):
    h.fetcher.set(API_CP, json.dumps({"origin": log.origin, "server_vkey": vkey or log.vkey,
                                      "signed_checkpoint": log.note()}))


def test_init_from_dns_pins_the_bundle_and_the_bootstrap_card(h, placeholder_pypi):
    w = Witness("witness.test/w1")
    inst = Instance(Log(3), witnesses=[w], quorum=1, max_age=300)
    raw = inst.bundle.txt
    h.dns.records[TXT_NAME] = [raw[:100] + raw[100:]]  # character-strings are joined before parsing
    h.fetcher.set(CARD_URL, json.dumps(inst.card))
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 0, out
    pol = out["policy"]
    assert pol["origin"] == inst.log.origin and pol["log_vkey"] == inst.log.vkey
    assert pol["policy_kid"] == did(inst.policy_key) and pol["owner_kid"] == did(inst.owner_key)
    assert pol["bootstrap_card_hash"] == inst.bundle.bootstrap_card_hash
    assert pol["trust_bundle_sha256"] == inst.bundle.sha256
    assert pol["witness_vkeys"] == [w.vkey] and pol["quorum"] == 1 and pol["max_checkpoint_age"] == 300
    # the card's statements about its witnesses are recorded as the operator's declarations
    assert pol["witness_meta"] == {w.name: {"declared_trust_domain": "founder", "declared_independent": False}}
    assert out["trust_root"] == "dns only, unauthenticated"
    assert pol["sources"]["log_vkey"] == [f"dns:{TXT_NAME}"]
    assert pol["sources"]["quorum"][0].startswith("card:bootstrap:")
    assert pol["checkpoint_url"] == CHECKPOINT_URL and pol["tiles_url"] == PREFIX
    assert pol["mirrors"] == [MIRROR]
    assert pol["consistency_url"] == "https://api.log.test/v2/tlog/consistency?from={old}&to={new}"
    assert tomllib.loads((h.home / "policy.toml").read_text())["log_vkey"] == inst.log.vkey
    assert any("placeholder" in x for x in out["warnings"])
    assert any("DNSSEC" in x for x in out["warnings"])
    assert h.run("verify", "card")[0] == 0  # the stored bootstrap card verifies at once


def test_bundle_format_round_trip_and_strictness():
    inst = Instance(Log(1))
    b = inst.bundle
    assert bundle_from_text(b.txt) == b
    assert bundle_from_text(b.jcs.decode()) == b
    assert bundle_from_jcs(b.jcs).sha256 == b.sha256
    with pytest.raises(PolicyError, match="JCS"):
        bundle_from_jcs(json.dumps(b.to_dict(), indent=1).encode())
    with pytest.raises(PolicyError, match="exactly"):
        bundle_from_jcs(json.dumps({**b.to_dict(), "extra": 1}, separators=(",", ":"), sort_keys=True).encode())
    same_key = {**b.to_dict(), "owner_kid": b.policy_kid}
    from aics_identity.canonical import canonicalize

    with pytest.raises(PolicyError, match="distinct"):
        bundle_from_jcs(canonicalize(same_key))


def readme_block(bundle, digest=None):
    return f"AICS trust bundle (AICS-1 §6.4):\n{bundle.txt}\nsha256: {bundle.sha256 if digest is None else digest}\n"


def test_readme_block_digest_must_match_its_bytes(h):
    """AICS-1 §6.4: README and PyPI carry the bytes and their hexH digest; a contradiction stops bootstrap."""
    inst, other = Instance(Log(3)), Instance(Log(3))
    assert bundle_from_text(readme_block(inst.bundle)) == inst.bundle
    for bad, message in ((readme_block(inst.bundle, "0" * 64), "does not match"),
                         (readme_block(inst.bundle, other.bundle.sha256), "does not match"),
                         (readme_block(inst.bundle, inst.bundle.sha256.upper()), "64 lowercase hex"),
                         (readme_block(inst.bundle, "<hex digest>"), "64 lowercase hex"),
                         (readme_block(inst.bundle) + "sha256: " + "0" * 64 + "\n", "more than one"),
                         (readme_block(inst.bundle) + other.bundle.txt + "\n", "different aics1=")):
        with pytest.raises(PolicyError, match=message):
            bundle_from_text(bad)
        code, out = h.run("policy", "init", "--bundle", bad, "--require-sources", "1", "--no-card", "--quorum", "0")
        assert code == 1 and message in out["error"], out
        assert not (h.home / "policy.toml").exists()
    code, out = h.run("policy", "init", "--bundle", readme_block(inst.bundle), "--require-sources", "1", "--no-card",
                      "--quorum", "0")
    assert code == 0, out
    assert out["policy"]["trust_bundle_sha256"] == inst.bundle.sha256


def test_txt_records_other_records_and_conflicts():
    inst, other = Instance(Log(1)), Instance(Log(1))
    parsed = parse_txt(["google-site-verification=abc", inst.bundle.txt])
    assert parsed.bundle == inst.bundle
    with pytest.raises(PolicyError, match="different"):
        parse_txt([inst.bundle.txt, other.bundle.txt])
    with pytest.raises(PolicyError, match="no aics1="):
        parse_txt(["v=spf1 -all"])
    legacy = parse_txt([f"aics-log-vkey {inst.log.vkey}"])
    assert legacy.bundle is None and legacy.legacy_log_vkey == inst.log.vkey
    with pytest.raises(PolicyError, match="different log keys"):
        parse_txt([inst.bundle.txt, f"aics-log-vkey {other.log.vkey}"])


def test_init_refuses_an_api_only_key(h):
    log = Log(3)
    serve_api(h, log)
    code, out = h.run("policy", "init", "--from-api", API_CP)
    assert code == 1, out
    assert "API host alone" in out["error"]
    assert out["api_claims"]["log_vkey"] == log.vkey
    assert not (h.home / "policy.toml").exists()


def test_init_refuses_when_only_the_api_gives_the_origin(h):
    inst = Instance(Log(3))
    h.dns.records[TXT_NAME] = [f"aics-log-vkey {inst.log.vkey}"]  # the legacy record has no origin
    serve_api(h, inst.log)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--from-api", API_CP,
                      "--no-card")
    assert code == 1
    assert "API host alone" in out["error"]
    assert not (h.home / "policy.toml").exists()


def test_api_agreeing_with_dns_is_recorded_but_does_not_count(h):
    inst = Instance(Log(3))
    inst.publish(h)
    serve_api(h, inst.log)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--from-api", API_CP)
    assert code == 0, out
    assert out["policy"]["sources"]["log_vkey"] == [f"dns:{TXT_NAME}", f"api:{API_CP}"]
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--from-api", API_CP, "--require-sources", "2",
                      "--force")
    assert code == 1 and "out-of-band" in out["error"]


def test_api_disagreeing_with_dns_stops_bootstrap(h):
    inst = Instance(Log(3))
    inst.publish(h)
    serve_api(h, inst.log, vkey=Log(1).vkey)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--from-api", API_CP)
    assert code == 2
    assert out["evidence"]["fields"][0]["field"] == "log_vkey"
    assert not (h.home / "policy.toml").exists()


def test_readme_bundle_must_agree_with_dns(h):
    inst, other = Instance(Log(3)), Instance(Log(3))
    inst.publish(h)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--bundle", other.bundle.txt)
    assert code == 2 and not (h.home / "policy.toml").exists()
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--bundle", inst.bundle.jcs.decode(),
                      "--require-sources", "2")
    assert code == 0, out
    assert out["policy"]["sources"]["log_vkey"] == [f"dns:{TXT_NAME}", "readme"]


def test_pypi_constant_disagreeing_with_dns_stops_bootstrap(h, monkeypatch):
    inst, other = Instance(Log(3)), Instance(Log(3))
    inst.publish(h)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE", other.bundle.jcs)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_SHA256", other.bundle.sha256)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_DOMAIN", DOMAIN)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 2
    assert "log_vkey" in {r["field"] for r in out["evidence"]["fields"]}


def test_pypi_constant_agreeing_counts_as_a_second_source(h, monkeypatch):
    inst = Instance(Log(3))
    inst.publish(h)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE", inst.bundle.jcs)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_SHA256", inst.bundle.sha256)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_DOMAIN", DOMAIN)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "2")
    assert code == 0, out
    assert len(out["policy"]["sources"]["log_vkey"]) == 2


def test_a_non_bootstrap_card_is_not_taken_for_the_witness_policy(h):
    w = Witness("w.test/1")
    inst = Instance(Log(3), witnesses=[w], quorum=1)
    inst.publish(h, card=inst.make_card(issued_at=NOW - 60))  # a later card than the bootstrap one
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 1 and "not the bootstrap card" in out["error"]
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--accept-signed-card")
    assert code == 0 and out["policy"]["quorum"] == 1
    assert out["policy"]["sources"]["quorum"][0].startswith("card-signature-only:")
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--no-card", "--witness",
                      w.vkey, "--quorum", "1", "--max-age", "300", "--force")
    assert code == 0 and out["policy"]["sources"]["quorum"] == ["manual"]


def test_a_card_signed_by_another_key_is_refused(h):
    inst = Instance(Log(3))
    impostor = idkeys.generate_keypair()
    from aics_cli.card import sign_card

    body = {k: v for k, v in inst.card.items() if k != "signatures"}
    inst.publish(h, card=sign_card(body, impostor, did(inst.policy_key)))
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 2 and not (h.home / "policy.toml").exists()


def test_unreachable_card_needs_no_card_flag(h):
    inst = Instance(Log(3))
    h.dns.records[TXT_NAME] = [inst.bundle.txt]
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 1 and "--no-card" in out["error"]
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--no-card")
    assert code == 1 and "--quorum" in out["error"]  # the bundle pins a card: say what replaces it
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--no-card", "--quorum", "0")
    assert code == 0 and out["policy"]["quorum"] == 0
    assert out["policy"]["checkpoint_url"] == CHECKPOINT_URL  # from the origin api.log.test/tiles


def test_no_dns_record_is_an_error(h):
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 1 and "no TXT record" in out["error"]


def test_manual_keys_from_the_readme(h):
    log = Log(3)
    code, out = h.run("policy", "init", "--domain", DOMAIN, "--origin", log.origin, "--log-vkey", log.vkey,
                      "--no-card")
    assert code == 1 and "--require-sources 1" in out["error"]  # one source: accepted only when asked for
    code, out = h.run("policy", "init", "--domain", DOMAIN, "--require-sources", "1", "--origin", log.origin,
                      "--log-vkey", log.vkey, "--no-card")
    assert code == 0, out
    assert out["policy"]["sources"]["log_vkey"] == ["manual"]
    assert out["trust_root"] == "manual only"


def test_existing_policy_is_never_silently_replaced(h):
    inst = Instance(Log(3))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")[0] == 0
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 1 and "--force" in out["error"]
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--force")[0] == 0
    assert len(list((h.home / "policy-history").iterdir())) == 1


def test_bad_witness_key_type_is_refused(h):
    log = Log(3)
    plain = format_vkey(vkey_from_ed25519("w.test/1", idkeys.generate_keypair().public_key()))  # 0x01, not 0x04
    code, out = h.run("policy", "init", "--domain", DOMAIN, "--require-sources", "1", "--origin", log.origin,
                      "--log-vkey", log.vkey, "--no-card", "--witness", plain, "--quorum", "1", "--max-age", "300")
    assert code == 1 and "cosignature key" in out["error"]


def test_policy_show_prints_the_bundle(h):
    inst = Instance(Log(3))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")[0] == 0
    code, out = h.run("policy", "show")
    assert code == 0
    assert out["txt_record"] == inst.bundle.txt and out["trust_bundle_sha256"] == inst.bundle.sha256


def test_policy_diff_agreement(h, placeholder_pypi):
    inst = Instance(Log(3))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")[0] == 0
    code, out = h.run("policy", "diff")
    assert code == 0, out
    assert all(r["agree"] for r in out["rows"])
    row = next(r for r in out["rows"] if r["field"] == "log_vkey")
    assert row["missing"] == ["pypi"] and out["pypi"] == "placeholder"


def test_policy_diff_reports_a_changed_dns_bundle(h):
    inst = Instance(Log(3))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")[0] == 0
    h.dns.records[TXT_NAME] = [Instance(Log(3)).bundle.txt]  # DNS now says something else
    code, out = h.run("policy", "diff")
    assert code == 2
    assert {r["field"] for r in out["evidence"]["fields"]} >= {"log_vkey", "policy_kid"}


def test_policy_diff_reports_pypi_disagreement(h, monkeypatch):
    inst = Instance(Log(3))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")[0] == 0
    other = Instance(Log(3))
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE", other.bundle.jcs)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_SHA256", other.bundle.sha256)
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_DOMAIN", DOMAIN)
    code, out = h.run("policy", "diff")
    assert code == 2


def test_policy_diff_dns_failure_is_an_error(h):
    inst = Instance(Log(3))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")[0] == 0
    del h.dns.records[TXT_NAME]
    code, out = h.run("policy", "diff")
    assert code == 1 and "DNS" in out["error"]


def test_toml_round_trip_and_validation():
    log, w = Log(1), Witness("w.test/1")
    pk = idkeys.generate_keypair()
    pol = Policy(origin=log.origin, log_vkey=log.vkey, policy_kid=did(pk), witness_vkeys=[w.vkey], quorum=1,
                 max_checkpoint_age=60, witness_meta={w.name: {"trust_domain": "x \"y\"", "independent": True}},
                 domain=DOMAIN, checkpoint_url="https://x.test/a\\b", mirrors=["https://m.test/"],
                 sources={"log_vkey": ["dns:_aics.log.test"]})
    again = loads(dumps(pol))
    assert again.summary() | {"path": None} == pol.summary() | {"path": None}
    with pytest.raises(PolicyError, match="quorum"):
        loads(dumps(Policy(origin=log.origin, log_vkey=log.vkey, quorum=1)))
    with pytest.raises(PolicyError, match="at least 60"):
        loads(dumps(Policy(origin=log.origin, log_vkey=log.vkey, max_checkpoint_age=59)))
    with pytest.raises(PolicyError, match="max_checkpoint_age"):
        loads(dumps(Policy(origin=log.origin, log_vkey=log.vkey, witness_vkeys=[w.vkey], quorum=1)))


def test_policy_key_forms():
    import base64

    sk = idkeys.generate_keypair()
    raw = sk.public_key().public_bytes_raw()
    while "+" not in base64.b64encode(raw).decode():  # check '+' in raw base64 is not taken for a vkey
        sk = idkeys.generate_keypair()
        raw = sk.public_key().public_bytes_raw()
    b64 = base64.b64encode(raw).decode()
    kid = did(sk)
    vkey = format_vkey(vkey_from_ed25519("log.test/policy", sk.public_key()))
    for text in (b64, f"ed25519:{b64}", kid, vkey):
        pk = parse_policy_key(text)
        assert pk.public_key == raw and kid in pk.kids
    assert {"log.test/policy", vkey} <= parse_policy_key(vkey).kids
    with pytest.raises(PolicyError):
        parse_policy_key("not+a+key")


def test_policy_urls_must_be_https():
    log = Log(1)
    with pytest.raises(PolicyError, match="https"):
        loads(dumps(Policy(origin=log.origin, log_vkey=log.vkey, checkpoint_url="http://api.log.test/checkpoint")))
    with pytest.raises(PolicyError, match="https"):
        loads(dumps(Policy(origin=log.origin, log_vkey=log.vkey, mirrors=["ftp://m.test/"])))
    assert loads(dumps(Policy(origin=log.origin, log_vkey=log.vkey, tiles_url="http://127.0.0.1:8000/")))


def test_init_reads_a_sup_1_bootstrap_card_and_refuses_a_swarms_one(h):
    """AICS-1 §20.9: an AICS-1+SUP-1 card is a card this release reads; §19: a swarms card is an unsupported
    profile, and nothing is pinned from it."""
    from aics_cli.card import card_hash
    from aics_cli.trust import TrustBundle

    from test_card import sup

    for spec, expected in (("AICS-1+SUP-1", 0), ("AICS-1+SWARMS-1+SUP-1", 1)):
        inst = Instance(Log(3))
        card = inst.make_card(mutate=lambda b: (sup(b), b.update(spec=spec)))
        inst.bundle = TrustBundle(origin=inst.log.origin, log_vkey=inst.log.vkey, policy_kid=did(inst.policy_key),
                                  owner_kid=did(inst.owner_key), bootstrap_card_hash=card_hash(card))
        inst.publish(h, card=card)
        code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--force")
        assert code == expected, out
        if expected:
            assert "unsupported profile" in out["error"], out
