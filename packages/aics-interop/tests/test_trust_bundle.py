"""Item 7: the out-of-band trust bundle (AICS-1 §6.4).

Producer: the suite's reference (``spec.J``, ``spec.txt_record``,
``spec.readme_block``, a DNS response message with the TXT RR split into
character-strings).  Consumers: aics (``aics_cli.trust``: ``bundle_from_text``,
``parse_txt``, ``published_bundle``; ``aics_cli.dnstxt.parse_response``; and
``aics policy init`` / ``policy show`` / ``policy diff`` end to end, with the
``AICS_TRUST_BUNDLE`` PyPI constant set in process), aics-conformance
(``Policy(trust=...)``, which takes the bundle as a JSON object), and the
canonicalizers of aics-identity and aics-tlog.  The repository README block
and the published constant are checked against each other.  ``aics trust
build`` (runbook step 5) is run over the real server's key file and logged
card, and must print the reference's bundle in every form.
"""

from __future__ import annotations

import hashlib
import re

import pytest

from aics_interop import aicslog, appendix_a, drivers, spec

DOMAIN = aicslog.DOMAIN
TXT_NAME = f"_aics.{DOMAIN}"
BUNDLE = aicslog.trust_bundle(card_hash=spec.hexH(b"interop bootstrap card"))
RAW = spec.J(BUNDLE)
OTHER = spec.J(aicslog.trust_bundle(card_hash=spec.hexH(b"another card")))
SHA = hashlib.sha256(RAW).hexdigest()


@pytest.fixture
def pypi(monkeypatch):
    """Set the aics-cli package's AICS_TRUST_BUNDLE constant (published_keys.py) for this test."""
    from aics_cli import published_keys as pk

    def publish(raw: bytes | None = RAW, sha: str | None = SHA, domain: str = DOMAIN) -> None:
        monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE", raw)
        monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_SHA256", sha)
        monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_DOMAIN", domain)
        monkeypatch.setattr(pk, "PLACEHOLDER", raw is None)

    return publish


def init(tmp_path, *argv: str, txt: list[str] | None = None) -> drivers.CliResult:
    cli = drivers.AicsCli(home=tmp_path / "home", txt={TXT_NAME: txt} if txt is not None else {})
    return cli.run("policy", "init", *argv, "--no-card", "--quorum", "0")


# ---------------------------------------------------------------------------
# bytes
# ---------------------------------------------------------------------------


def test_canonical_bytes_agree_across_canonicalizers():
    from aics_cli.trust import bundle_from_object
    from aics_identity import canonicalize
    from aics_tlog.bundle import canonical_json

    b = bundle_from_object(dict(BUNDLE))
    assert RAW == b.jcs == canonicalize(BUNDLE) == canonical_json(BUNDLE)
    assert RAW.startswith(b'{"bootstrap_card_hash":') and RAW.endswith(b',"v":1}')
    assert b.sha256 == SHA
    assert spec.validate_trust_bundle(RAW) == BUNDLE


def test_txt_record_agrees_and_parses():
    from aics_cli.trust import bundle_from_object, bundle_from_u64, parse_txt

    txt = spec.txt_record(RAW)
    assert txt == bundle_from_object(dict(BUNDLE)).txt == "aics1=" + spec.U64(RAW)
    assert bundle_from_u64(txt[len("aics1="):]).jcs == RAW
    assert parse_txt([txt]).bundle.jcs == RAW
    assert spec.validate_trust_bundle(spec.dU64(txt[len("aics1="):])) == BUNDLE


@pytest.mark.parametrize("chunk", [255, 64, 7, 1])
def test_dns_character_strings_are_concatenated(chunk):
    """§6.4: one TXT RR; its character-strings are joined before parsing (aics's stdlib DNS parser)."""
    from aics_cli.dnstxt import parse_response
    from aics_cli.trust import parse_txt

    txt = spec.txt_record(RAW)
    strings = spec.txt_character_strings(txt, chunk)
    assert len(txt) > 255 and (chunk == 255) == (len(strings) == -(-len(txt) // 255))
    msg = spec.dns_txt_response(TXT_NAME, 0x1D5, [strings])
    _flags, rcode, records = parse_response(msg, 0x1D5, TXT_NAME)
    assert rcode == 0 and records == [txt.encode("ascii")]
    assert parse_txt([r.decode("ascii") for r in records]).bundle.jcs == RAW


def test_readme_block_parses_to_the_same_bundle():
    from aics_cli.trust import bundle_from_text

    block = spec.readme_block(RAW)
    assert block.splitlines()[1] == spec.txt_record(RAW) and block.splitlines()[2] == f"sha256: {SHA}"
    assert bundle_from_text(block).jcs == RAW
    assert bundle_from_text(RAW.decode()).jcs == RAW  # the JSON form of the block is accepted too


# ---------------------------------------------------------------------------
# aics policy init / show / diff
# ---------------------------------------------------------------------------


def test_policy_init_from_the_readme_block(tmp_path):
    r = init(tmp_path, "--bundle", spec.readme_block(RAW), "--require-sources", "1")
    assert r.code == 0, r.data
    pinned = r.data["policy"]
    assert {k: pinned[k] for k in ("origin", "log_vkey", "policy_kid", "owner_kid", "bootstrap_card_hash")} == {
        k: BUNDLE[k] for k in ("origin", "log_vkey", "policy_kid", "owner_kid", "bootstrap_card_hash")}
    show = drivers.AicsCli(home=tmp_path / "home").run("policy", "show")
    assert (show.code, show.data["txt_record"], show.data["trust_bundle_sha256"]) == (0, spec.txt_record(RAW), SHA)
    assert show.data["trust_bundle"] == BUNDLE


def test_dns_and_the_pypi_constant_meet_the_default_two_sources(tmp_path, pypi):
    pypi()
    r = init(tmp_path, "--from-dns", DOMAIN, txt=[spec.txt_record(RAW)])
    assert r.code == 0, r.data
    sources = r.data["policy"]["sources"]["log_vkey"]
    assert sources[0] == f"dns:{TXT_NAME}" and sources[1].startswith("pypi:aics-cli==")
    r = drivers.AicsCli(home=tmp_path / "home", txt={TXT_NAME: [spec.txt_record(RAW)]}).run("policy", "diff")
    assert r.code == 0 and all(row["agree"] for row in r.data["rows"]), r.data


def test_all_three_publications_agree(tmp_path, pypi):
    pypi()
    r = init(tmp_path, "--from-dns", DOMAIN, "--bundle", spec.readme_block(RAW), txt=[spec.txt_record(RAW)])
    assert r.code == 0, r.data
    kinds = {s.split(":")[0] for s in r.data["policy"]["sources"]["log_vkey"]}
    assert kinds == {"dns", "readme", "pypi"}


def test_dns_alone_is_refused_by_default(tmp_path):
    r = init(tmp_path, "--from-dns", DOMAIN, txt=[spec.txt_record(RAW)])
    assert r.code == 1 and "independent kinds are required" in r.data["error"]


@pytest.mark.parametrize("where", ["readme", "pypi"])
def test_a_disagreeing_publication_stops_bootstrap(tmp_path, pypi, where):
    """§6.4: disagreements MUST stop bootstrap; no majority vote."""
    pypi(OTHER, hashlib.sha256(OTHER).hexdigest()) if where == "pypi" else pypi()
    argv = ["--from-dns", DOMAIN] + (["--bundle", spec.readme_block(OTHER)] if where == "readme" else [])
    r = init(tmp_path, *argv, txt=[spec.txt_record(RAW)])
    assert r.code == 2, r.data
    assert r.evidence["type"] == "aics-key-source-disagreement/v1"
    assert [f["field"] for f in r.evidence["fields"]] == ["bootstrap_card_hash"]


def test_two_distinct_bundles_at_one_name_are_refused(tmp_path):
    r = init(tmp_path, "--from-dns", DOMAIN, "--require-sources", "1",
             txt=[spec.txt_record(RAW), spec.txt_record(OTHER)])
    assert r.code == 1 and "different aics1= trust bundles" in r.data["error"]


def test_the_pypi_constant_must_match_its_own_digest(tmp_path, pypi):
    pypi(RAW, "0" * 64)
    r = init(tmp_path, "--bundle", spec.readme_block(RAW))
    assert r.code == 1 and "does not match its own published digest" in r.data["error"]


def test_a_readme_block_must_match_its_own_digest(tmp_path):
    """README and PyPI carry the bytes and their digest (§6.4); both digests are checked against the bytes."""
    block = spec.readme_block(RAW).replace(SHA, "0" * 64)
    r = init(tmp_path, "--bundle", block, "--require-sources", "1")
    assert r.code != 0, "aics pinned a README block whose sha256 line contradicts its bytes"


# ---------------------------------------------------------------------------
# strictness: what each consumer accepts
# ---------------------------------------------------------------------------

BAD = {
    "missing-v": {k: v for k, v in BUNDLE.items() if k != "v"},
    "unknown-member": {**BUNDLE, "note": "x"},
    "v-2": {**BUNDLE, "v": 2},
    "v-true": {**BUNDLE, "v": True},
    "policy-is-owner": {**BUNDLE, "owner_kid": BUNDLE["policy_kid"]},
    "uppercase-card-hash": {**BUNDLE, "bootstrap_card_hash": "AB" * 32},
    "origin-with-scheme": {**BUNDLE, "origin": "https://" + BUNDLE["origin"]},
}


def _conformance_accepts(obj) -> bool:
    try:
        drivers.conformance_policy(obj)
    except ValueError:  # Policy.__post_init__ and parse_vkey refuse with ValueError
        return False
    return True


@pytest.mark.parametrize("case", sorted(BAD))
def test_invalid_bundles_are_refused_by_aics_and_the_reference(case):
    from aics_cli.errors import PolicyError
    from aics_cli.trust import bundle_from_jcs

    raw = spec.J(BAD[case])
    with pytest.raises(ValueError):
        spec.validate_trust_bundle(raw)
    with pytest.raises(PolicyError):
        bundle_from_jcs(raw)


@pytest.mark.parametrize("case", sorted(BAD))
def test_invalid_bundles_are_refused_by_aics_conformance(case):
    assert not _conformance_accepts(BAD[case])


def test_non_canonical_bytes_are_refused():
    from aics_cli.errors import PolicyError
    from aics_cli.trust import bundle_from_u64

    pretty = RAW.decode().replace(",", ", ").encode()
    for raw in (pretty, RAW + b"\n"):
        with pytest.raises(ValueError):
            spec.validate_trust_bundle(raw)
        with pytest.raises(PolicyError):
            bundle_from_u64(spec.U64(raw))


def test_conformance_and_aics_take_the_same_values(tmp_path):
    """The valid bundle pins the same five values in both consumers."""
    p = drivers.conformance_policy(dict(BUNDLE))
    r = init(tmp_path, "--bundle", spec.readme_block(RAW), "--require-sources", "1")
    assert {k: p.trust[k] for k in spec.TRUST_MEMBERS[1:]} == {k: r.data["policy"][k] for k in spec.TRUST_MEMBERS[1:]}


# ---------------------------------------------------------------------------
# the repository's own publications
# ---------------------------------------------------------------------------


def _readme_block() -> list[str]:
    text = (appendix_a.REPO_ROOT / "README.md").read_text("utf-8")
    m = re.search(r"AICS trust bundle \(AICS-1 §6\.4\)[^\n]*\n((?:[ \t]+[^\n]*\n){1,3})", text)
    assert m, "the repository README has no labelled trust bundle block"
    return [line.strip() for line in m.group(1).splitlines()]


def test_repository_readme_block_and_pypi_constant_are_equivalent(tmp_path):
    """README and the AICS_TRUST_BUNDLE constant are both placeholders, or both carry the same bytes and digest."""
    from aics_cli import published_keys as pk

    lines = _readme_block()
    txt = next(line for line in lines if line.startswith("aics1="))
    real = re.fullmatch(r"aics1=([A-Za-z0-9_-]+)", txt)
    if real is None:
        assert pk.AICS_TRUST_BUNDLE is None and pk.AICS_TRUST_BUNDLE_SHA256 is None and pk.PLACEHOLDER is True
        r = init(tmp_path, "--bundle", "\n".join(lines), "--require-sources", "1")
        assert r.code == 1, "aics pinned the README placeholder"
        return
    raw = spec.dU64(real.group(1))
    spec.validate_trust_bundle(raw)
    sha = next(line.split(":", 1)[1].strip() for line in lines if line.startswith("sha256:"))
    assert sha == spec.hexH(raw)
    assert pk.PLACEHOLDER is False and pk.AICS_TRUST_BUNDLE == raw and pk.AICS_TRUST_BUNDLE_SHA256 == sha


# ---------------------------------------------------------------------------
# aics trust build against the real server (runbook step 5)
# ---------------------------------------------------------------------------


def test_trust_build_over_the_real_servers_key_file_and_logged_card(tmp_path):
    """``aics trust build`` reads the key file aics-server writes and the card exactly as served after the owner
    logged it, and prints the bundle the reference builds from the same values, in every published form."""
    from aics_interop import server

    instance = server.ServerInstance(tmp_path / "instance", tcp=False)
    card = instance.log_card()
    (tmp_path / "card.json").write_bytes(card)
    listing = instance.get("/v2/policies")
    assert listing.status == 200
    (tmp_path / "policies.json").write_bytes(listing.body)
    cli = drivers.AicsCli(home=tmp_path / "home")
    r = cli.run("trust", "build", "--pubkeys", str(tmp_path / "instance" / "aics-keys.txt"),
                "--card", str(tmp_path / "card.json"), "--policies-file", str(tmp_path / "policies.json"))
    assert r.code == 0, r.data
    raw = spec.J(instance.oob.trust_bundle(spec.hexH(card)))
    assert r.data["bundle_jcs"].encode("utf-8") == raw
    assert spec.validate_trust_bundle(raw)["bootstrap_card_hash"] == spec.hexH(card)
    assert (r.data["txt"], r.data["sha256"]) == (spec.txt_record(raw), hashlib.sha256(raw).hexdigest())
    assert r.data["readme_block"].splitlines()[1:] == spec.readme_block(raw).splitlines()[1:]
    # the README block pins exactly that bundle in aics policy init (with the TXT record as the second source)
    cli.txt[TXT_NAME] = [r.data["txt"]]
    (tmp_path / "readme-block.txt").write_text(r.data["readme_block"], "utf-8")
    pinned = cli.run("policy", "init", "--from-dns", DOMAIN, "--bundle", str(tmp_path / "readme-block.txt"),
                     "--no-card", "--quorum", "0")
    assert pinned.code == 0, pinned.data
    show = cli.run("policy", "show")
    assert show.data["trust_bundle"] == spec.strict_json(raw)
    # before the owner logged it, no policy leaf names the card: nothing is built
    before = spec.strict_json(listing.body)
    before["policies"] = [p for p in before["policies"] if p["kind"] != "card"]
    (tmp_path / "before.json").write_bytes(spec.J(before))
    r = cli.run("trust", "build", "--pubkeys", str(tmp_path / "instance" / "aics-keys.txt"),
                "--card", str(tmp_path / "card.json"), "--policies-file", str(tmp_path / "before.json"))
    assert r.code == 1 and "no policy leaf of kind card names this card" in r.data["error"], r.data
    assert "bundle_jcs" not in r.data
