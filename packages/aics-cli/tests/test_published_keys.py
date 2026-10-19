"""The trust bundle this package ships (aics_cli.published_keys; AICS-1 §6.4): since production genesis it is the
real bundle of wesupport-ai.com, consistent with its own digest; it counts as a source, and guards bootstrap, for
that domain and its log origin only, and is reported - not held against anything - for any other."""

from __future__ import annotations

import hashlib

import pytest

from aics_cli import __version__, published_keys
from aics_cli.errors import PolicyError
from aics_cli.policy import parse_log_vkey
from aics_cli.trust import TrustBundle, bundle_from_jcs, published_bundle

from conftest import DOMAIN, ORIGIN, TXT_NAME, Instance, Log

REAL_DOMAIN = "wesupport-ai.com"
REAL_ORIGIN = "api.wesupport-ai.com/tiles"
REAL_TXT_NAME = f"_aics.{REAL_DOMAIN}"
ELSEWHERE = f"published for {REAL_DOMAIN} ({REAL_ORIGIN}), not {DOMAIN}"  # the status for the fake log.test
ONE = ("--require-sources", "1")
NO_CARD = ("--no-card", "--quorum", "0")


def shipped() -> TrustBundle:
    return bundle_from_jcs(published_keys.AICS_TRUST_BUNDLE)


def test_the_constant_is_published_and_matches_its_own_digest():
    assert published_keys.PLACEHOLDER is False
    raw = published_keys.AICS_TRUST_BUNDLE
    assert isinstance(raw, bytes)
    assert hashlib.sha256(raw).hexdigest() == published_keys.AICS_TRUST_BUNDLE_SHA256
    b = bundle_from_jcs(raw)  # strict: JCS bytes, exactly the bundle members, v 1, three distinct keys
    assert b.jcs == raw and b.sha256 == published_keys.AICS_TRUST_BUNDLE_SHA256


def test_the_constant_is_the_bundle_of_wesupport_ai_com():
    b = shipped()
    assert published_keys.AICS_TRUST_BUNDLE_DOMAIN == REAL_DOMAIN
    assert b.origin == REAL_ORIGIN
    assert parse_log_vkey(b.log_vkey).name == REAL_ORIGIN  # the log key is named for the same origin


def test_the_constant_applies_to_its_domain_and_its_origin_only():
    b = shipped()
    assert published_bundle(REAL_DOMAIN) == (b, "published")
    assert published_bundle(None, REAL_ORIGIN) == (b, "published")  # a policy pinned from the README: no domain
    assert published_bundle(DOMAIN, ORIGIN) == (None, ELSEWHERE)
    pub, status = published_bundle(None)
    assert pub is None and status.startswith("not compared") and REAL_DOMAIN in status


def test_a_constant_contradicting_its_digest_is_refused(h, monkeypatch):
    monkeypatch.setattr(published_keys, "AICS_TRUST_BUNDLE_SHA256", "00" * 32)
    with pytest.raises(PolicyError, match="own published digest"):
        published_bundle(REAL_DOMAIN)
    h.dns.records[REAL_TXT_NAME] = [shipped().txt]
    code, out = h.run("policy", "init", "--from-dns", REAL_DOMAIN, *ONE, *NO_CARD)
    assert code != 0 and not (h.home / "policy.toml").exists()


def test_policy_diff_for_the_real_domain_reports_the_published_constant(h):
    h.dns.records[REAL_TXT_NAME] = [shipped().txt]
    code, out = h.run("policy", "diff", "--domain", REAL_DOMAIN)
    assert code == 0, out
    assert out["pypi"] == "published"
    assert out["rows"] and all(r["agree"] and r["missing"] == [] for r in out["rows"])


def test_dns_and_the_constant_pin_the_real_domain_with_two_sources(h):
    h.dns.records[REAL_TXT_NAME] = [shipped().txt]
    code, out = h.run("policy", "init", "--from-dns", REAL_DOMAIN, *NO_CARD)  # no --require-sources needed
    assert code == 0, out
    pol = out["policy"]
    assert pol["origin"] == REAL_ORIGIN and pol["trust_bundle_sha256"] == published_keys.AICS_TRUST_BUNDLE_SHA256
    assert pol["sources"]["log_vkey"] == [f"dns:{REAL_TXT_NAME}", f"pypi:aics-cli=={__version__}"]
    assert out["trust_root"] == "dns + pypi"
    assert not any("placeholder" in w or "nothing to cross-check" in w for w in out["warnings"])
    code, out = h.run("policy", "show")
    assert code == 0 and out["pypi_constant"] == "agrees"


def test_dns_contradicting_the_constant_stops_bootstrap_of_the_real_domain(h):
    impostor = Instance(Log(3, origin=REAL_ORIGIN))  # another log key for the same origin
    h.dns.records[REAL_TXT_NAME] = [impostor.bundle.txt]
    code, out = h.run("policy", "init", "--from-dns", REAL_DOMAIN, *ONE, *NO_CARD)
    assert code == 2 and not (h.home / "policy.toml").exists()
    assert "log_vkey" in {r["field"] for r in out["evidence"]["fields"]}
    code, out = h.run("policy", "diff", "--domain", REAL_DOMAIN)
    assert code == 2 and out["pypi"] == "published"


def test_another_domain_is_reported_and_not_held_against_the_constant(h):
    inst = Instance(Log(3))
    inst.publish(h)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE)
    assert code == 0, out
    assert f"the aics-cli package's AICS_TRUST_BUNDLE constant: {ELSEWHERE}; nothing to cross-check" in out["warnings"]
    assert out["policy"]["sources"]["log_vkey"] == [f"dns:{TXT_NAME}"]
    h.serve(inst.log)
    code, out = h.run("verify", "checkpoint")
    assert code == 0, out
    assert out["key_sources"]["pypi_constant"] == ELSEWHERE
    assert out["trust_root"] == "dns only, unauthenticated"
    code, out = h.run("policy", "diff")
    assert code == 0 and out["pypi"] == ELSEWHERE
    assert all(r["missing"] == ["pypi"] for r in out["rows"])
