"""Implementations of the ``aics`` commands.

Each command takes the parsed arguments and an :class:`Env` (network,
DNS, clock, home directory - injectable for tests) and returns a
:class:`Result`, or raises :class:`~aics_cli.errors.AicsError` (exit 1:
error, incomplete, stale or unproven) or
:class:`~aics_cli.errors.VerificationFailed` (exit 2: invalid, with
evidence).

Exit 2 is kept for what the output can back with evidence: log-signed
conflicts (an equal-size split, a constructive not-a-prefix proof, a
smaller head that is not a prefix of a saved one), a log-signed checkpoint
no log can produce, an invalid checkpoint served by the log origin itself,
an invalid or downgrading signed card, and a disagreement between the
out-of-band key sources.  A stale or under-witnessed head, an older head
that is consistent with the saved one, and an invalid note from a mirror,
a peer or a file exit 1: anyone on those paths can produce them.
"""

from __future__ import annotations

import json
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from aics_identity import linesig as idlinesig
from aics_tlog import format_vkey, parse_checkpoint, parse_note

from . import __version__
from . import card as cardmod
from . import home as _home
from . import keystore
from . import message as msgmod
from .checkpoints import (
    DEFAULT_MAX_SKEW,
    CheckpointStore,
    Cp,
    NoteCheck,
    SavedNote,
    api_key_warnings,
    check_note,
    extract_note,
    fetch_checkpoint,
    log_signed,
)
from .consistency import Attempt, EndpointSource, GivenProof, Relation, TileSource, relate
from .dnstxt import TxtResult, lookup_txt
from .encoding import b64e, escape_untrusted, parse_hash_lines
from .errors import (
    EXIT_OK,
    EXIT_UNAVAILABLE,
    AicsError,
    DnsError,
    FetchError,
    PolicyError,
    UsageError,
    VerificationFailed,
)
from .evidence import split_bundle
from .net import Fetcher, HttpFetcher, join_url
from .policy import (
    TRUST_FIELDS,
    Policy,
    SourceValues,
    archived_log_keys,
    compare_sources,
    default_urls,
    is_out_of_band,
    load,
    malformed,
    parse_log_vkey,
    parse_policy_key,
    parse_witness_vkey,
    policy_path,
    prefix_urls,
    save,
)
from .tiles_http import HttpTileReader, TileSourceError
from .trust import TrustBundle, bundle_from_text, parse_txt, published_bundle

UNAVAILABLE_MESSAGE = "not available until the server ships this"
DEFAULT_REQUIRED_SOURCES = 2

#: Reasons a log-signed note is self-contained evidence, whoever served it.
SELF_CONTAINED_EVIDENCE = ("bad_empty_root",)


@dataclass
class Env:
    fetcher: Fetcher = field(default_factory=HttpFetcher)
    resolve_txt: Callable[..., TxtResult] = lookup_txt
    clock: Callable[[], float] = time.time
    home: Path | None = None
    stdin: Any = None

    def now(self) -> int:
        return int(self.clock())


@dataclass
class Result:
    code: int
    data: dict[str, Any]
    text: list[str]


def _home_dir(args: Any, env: Env) -> Path:
    h = getattr(args, "home", None)
    if h:
        return Path(h).expanduser()
    if env.home is not None:
        return env.home
    return _home.default_home()


def _iso(ts: int | None) -> str | None:
    return None if ts is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _ok(data: dict[str, Any], text: list[str]) -> Result:
    return Result(EXIT_OK, {"ok": True, **data}, text)


# ---------------------------------------------------------------------------
# keys and line signatures
# ---------------------------------------------------------------------------


def cmd_keys_new(args: Any, env: Env) -> Result:
    directory = Path(args.dir).expanduser() if args.dir else _home_dir(args, env)
    ident, paths = keystore.new_keys(directory)
    data = {**ident.to_dict(), "dir": str(directory), "files": [str(p) for p in paths]}
    text = ident.lines() + [f"# private keys written to {directory} with mode 0600; nobody else has them"]
    return _ok(data, text)


def cmd_keys_show(args: Any, env: Env) -> Result:
    directory = Path(args.dir).expanduser() if args.dir else _home_dir(args, env)
    ident, warnings = keystore.show_keys(directory)
    data = {**ident.to_dict(), "dir": str(directory), "warnings": warnings}
    return _ok(data, ident.lines() + [f"# warning: {w}" for w in warnings])


def _signing_key(args: Any, env: Env):
    if getattr(args, "key", None):
        return keystore.load_ed25519_private(Path(args.key).expanduser())
    directory = Path(args.dir).expanduser() if getattr(args, "dir", None) else _home_dir(args, env)
    return keystore.load_ed25519_private(directory / _home.ED25519_KEY)


def cmd_sign_line(args: Any, env: Env) -> Result:
    key = _signing_key(args, env)
    try:
        sig = idlinesig.sign_line(args.session, args.line, key)
    except (ValueError, TypeError) as exc:
        raise AicsError(str(exc)) from None
    pub = key.public_key().public_bytes_raw()
    data = {"sig": sig, "reply": f"sig {sig}", "session": args.session, "line": args.line,
            "pub": f"pub {b64e(pub)}"}
    return _ok(data, [f"sig {sig}"])


def _sig_arg(args: Any, env: Env) -> str:
    """The signature from --sig, or from --sig-file (a file, or '-' for stdin)."""
    if getattr(args, "sig_file", None):
        if args.sig is not None:
            raise UsageError("give --sig or --sig-file, not both")
        if args.sig_file == "-":
            return (env.stdin or sys.stdin).read()
        try:
            return Path(args.sig_file).expanduser().read_text("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise AicsError(f"cannot read {args.sig_file}: {exc}") from None
    if args.sig is None:
        raise UsageError("give the signature with --sig=SIG (or --sig-file FILE, '-' for stdin)")
    return args.sig


def cmd_verify_line(args: Any, env: Env) -> Result:
    sig_text = _sig_arg(args, env)
    pub = keystore.parse_public_key_text(args.pub) if args.pub else _signing_key(args, env).public_key()
    pub_text = f"pub {b64e(pub.public_bytes_raw())}"
    leeway = not args.strict
    try:
        form = idlinesig.verify_line(args.session, args.line, sig_text, pub, leeway=leeway)
    except idlinesig.InvalidLineSignature as exc:
        tried = idlinesig.candidate_messages(args.session, args.line, leeway=leeway)
        raise VerificationFailed(
            f"line signature does not verify for this session id, line and key: {exc}",
            evidence={
                "type": "aics-line-signature-failure/v1",
                "session": args.session,
                "line": args.line,
                "sig": sig_text,
                "pub": pub_text,
                "signed_bytes_tried_base64": [b64e(m) for m in tried],
            },
        ) from None
    except idlinesig.MalformedLineSignature as exc:
        raise AicsError(f"malformed signature: {exc}") from None
    except (ValueError, TypeError) as exc:
        raise AicsError(str(exc)) from None
    return _ok({"valid": True, "form": form, "pub": pub_text}, [f"ok: {form} signature valid"])


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def _dns_trust(domain: str, env: Env, nameserver: str | None) -> tuple[list[SourceValues], TrustBundle | None,
                                                                          dict[str, Any]]:
    name = f"_aics.{domain.rstrip('.')}"
    txt = env.resolve_txt(name, nameserver=nameserver)
    info: dict[str, Any] = {"name": name, "records": txt.records, "dnssec_ad": txt.ad, "resolver": txt.resolver}
    if not txt.records:
        raise PolicyError(f"no TXT record at {name}" + (" (NXDOMAIN)" if txt.nxdomain else ""), dns=info)
    parsed = parse_txt(txt.records)
    info["notes"] = parsed.notes
    sources: list[SourceValues] = []
    if parsed.bundle is not None:
        sources.append(SourceValues(f"dns:{name}", parsed.bundle.values()))
        info["bundle_sha256"] = parsed.bundle.sha256
    elif parsed.legacy_log_vkey is not None:
        sources.append(SourceValues(f"dns-log-vkey:{name}", {"log_vkey": parsed.legacy_log_vkey}))
    return sources, parsed.bundle, info


def _api_claims(url: str, env: Env) -> SourceValues:
    resp = env.fetcher.get(url, max_bytes=1024 * 1024, accept="application/json, text/plain;q=0.5")
    if resp.status != 200:
        raise FetchError(f"{url}: HTTP {resp.status}")
    values: dict[str, Any] = {}
    try:
        fetched = extract_note(resp.body, url)
        values["origin"] = parse_checkpoint(parse_note(fetched.note_text).text).origin
        claims = fetched.api_claims
    except (AicsError, ValueError):
        try:
            obj = cardmod.loads_strict(resp.body)
        except (ValueError, UnicodeDecodeError):
            obj = {}
        claims = obj if isinstance(obj, dict) else {}
        if isinstance(claims.get("origin"), str):
            values["origin"] = claims["origin"]
    for k in ("log_vkey", "server_vkey", "vkey"):
        if isinstance(claims.get(k), str):
            values["log_vkey"] = claims[k].strip()
            break
    for k in ("policy_kid", "owner_kid"):
        if isinstance(claims.get(k), str):
            values[k] = claims[k].strip()
    return SourceValues(f"api:{url}", values)


def _manual_trust(args: Any) -> dict[str, Any]:
    v: dict[str, Any] = {}
    for f, flag in (("origin", args.origin), ("log_vkey", args.log_vkey), ("policy_kid", args.policy_kid),
                    ("owner_kid", args.owner_kid)):
        if flag:
            v[f] = flag
    return v


def _verify_card_signature(card: dict[str, Any], policy_kid: str) -> list[cardmod.SigCheck]:
    return cardmod.check_signatures(card, [parse_policy_key(policy_kid)])


def _refuse_unsupported_profile(card: dict[str, Any], what: str, **details: Any) -> None:
    """AICS-1 §19: a client without a profile rejects a card of that profile; it never reads it as a base card."""
    profile = cardmod.unsupported_profile(card)
    if profile is not None:
        raise AicsError(
            f"unsupported profile: {what} is a {escape_untrusted(profile)} card, and this aics release verifies only "
            f"{' and '.join(cardmod.SUPPORTED_PROFILES)} cards; AICS-1 §19 requires a client without the profile to "
            "reject it rather than read it as a base card (use a verifier that implements it)",
            profile=profile, supported_profiles=list(cardmod.SUPPORTED_PROFILES), **details)


def _bootstrap_card(url: str, trust: dict[str, Any], env: Env, home: Path, *, accept_signed: bool,
                    allow_weaker: bool, warnings: list[str]) -> tuple[dict[str, Any], str]:
    """Fetch the card and check it under the trust values, with the same
    saved-card rules as ``aics verify card``; returns (card, label)."""
    try:
        raw = cardmod.fetch_card(env.fetcher, url)
    except FetchError as exc:
        raise PolicyError(f"cannot fetch the card for the witness policy: {exc.message}; pass --card-url, or "
                          "--no-card with --witness/--quorum/--max-age from an independent source") from None
    try:
        card = cardmod.loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PolicyError(f"the card at {url} is not strict JSON: {exc}") from None
    if not isinstance(card, dict):
        raise PolicyError(f"the card at {url} is not a JSON object")
    checks = _verify_card_signature(card, trust["policy_kid"])
    evidence = {"type": "aics-card-failure/v1", "url": url, "card": card,
                "signatures": [c.report() for c in checks]}
    if not any(c.status == "valid" for c in checks) or any(c.status == "invalid" for c in checks):
        raise VerificationFailed("the card is not validly signed by the pinned policy key; nothing was pinned",
                                 evidence=evidence)
    _refuse_unsupported_profile(card, f"the card at {url}")
    problems = cardmod.schema_problems(card)
    if problems:
        raise VerificationFailed("the card does not follow the AICS-1 §13.1 schema; nothing was pinned",
                                 evidence={**evidence, "schema_problems": problems})
    now = env.now()
    if card["issued_at"] > now + cardmod.FUTURE_SKEW or now >= card["expires"]:
        raise VerificationFailed("the card is not currently valid (issued_at/expires); nothing was pinned",
                                 evidence={**evidence, "checked_at": now})
    pseudo = Policy(origin=trust["origin"], log_vkey=trust["log_vkey"], policy_kid=trust.get("policy_kid"),
                    owner_kid=trust.get("owner_kid"))
    mism = cardmod.anchor_mismatches(card, pseudo)
    if mism:
        raise VerificationFailed("the card's keys differ from the trust bundle; nothing was pinned",
                                 evidence={**evidence, "mismatches": mism})
    for p in cardmod.assurance_problems(card):
        warnings.append(f"the card states an assurance outside the AICS-1 §13.3 bounds (aics verify card rejects "
                        f"the card for it): {p}")
    h = cardmod.card_hash(card)
    bootstrap = bool(trust.get("bootstrap_card_hash")) and h == trust["bootstrap_card_hash"]
    if not bootstrap and not accept_signed:
        raise PolicyError(
            "the served card is signed by the pinned policy key but is not the bootstrap card the trust bundle pins "
            f"(card hash {h}); proving a later card current needs the log's policy entries "
            f"({UNAVAILABLE_MESSAGE}). Give --witness/--quorum/--max-age from an independent source, --no-card, "
            "or --accept-signed-card",
            card_hash=h, bootstrap_card_hash=trust.get("bootstrap_card_hash"),
        )
    hist = cardmod.compare_with_saved(cardmod.CardStore(home / "cards"), trust["policy_kid"], card)
    problem = hist.problem()
    if problem is not None and not (problem == "witness-downgrade" and allow_weaker):
        hint = " (pass --allow-weaker to adopt it anyway)" if problem == "witness-downgrade" else ""
        raise VerificationFailed(
            f"{cardmod.HISTORY_MESSAGES[problem]}; nothing was pinned{hint}",
            evidence={**evidence, "reason": problem, "card_hash": h,
                      "saved_card": hist.previous.card if hist.previous else None,
                      "saved": hist.previous.meta if hist.previous else None},
        )
    if problem == "witness-downgrade":
        warnings.append("--allow-weaker: the card weakens the witness policy of the card saved earlier "
                        "for this policy key")
    if bootstrap:
        return card, f"card:bootstrap:{h}"
    warnings.append("the served card is not the bootstrap card the bundle pins; its witness policy was taken "
                    "on its signature alone (--accept-signed-card): its currency is unproven")
    return card, f"card-signature-only:{url}"


def _card_urls(card: dict[str, Any], origin: str) -> dict[str, Any]:
    prefixes = [p if p.endswith("/") else p + "/" for p in card["tile_prefixes"]]
    own = f"https://{origin}/"
    main = own if own in prefixes else prefixes[0]
    out = prefix_urls(main, card["api_base"])
    out["mirrors"] = [p for p in prefixes if p != main]
    return out


def _source_kinds(labels: list[str]) -> list[str]:
    kinds: list[str] = []
    for s in labels:
        if not is_out_of_band(s):
            continue
        k = s.split(":", 1)[0]
        k = "dns" if k == "dns-log-vkey" else k
        if k not in kinds:
            kinds.append(k)
    return kinds


def _trust_root(policy: Policy, pypi_status: str) -> str:
    """Where the pinned log key comes from, in a few words."""
    kinds = _source_kinds(policy.key_sources("log_vkey"))
    if pypi_status == "agrees" and "pypi" not in kinds:
        kinds.append("pypi")
    if kinds == ["dns"]:
        return "dns only, unauthenticated"
    if len(kinds) == 1:
        return f"{kinds[0]} only"
    return " + ".join(kinds) if kinds else "none recorded"


def _existing_policy(home: Path, warnings: list[str]) -> tuple[Policy | None, str | None, str | None]:
    """The policy being replaced (if any): (policy, origin, log_vkey)."""
    p = policy_path(home)
    if not p.exists():
        return None, None, None
    try:
        old = load(home)
        return old, old.origin, old.log_vkey
    except PolicyError as exc:
        warnings.append(f"the existing policy could not be loaded ({exc.message}); it is archived, and only its "
                        "origin and log key are compared")
    try:
        data = tomllib.loads(p.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None, None, None
    origin = data.get("origin") if isinstance(data.get("origin"), str) else None
    vkey = data.get("log_vkey") if isinstance(data.get("log_vkey"), str) else None
    try:
        vkey = format_vkey(parse_log_vkey(vkey)) if vkey else None
    except PolicyError:
        vkey = None
    return None, origin, vkey


def _repin_checks(old: Policy | None, old_origin: str | None, old_log_vkey: str | None, new: Policy, home: Path,
                  args: Any, env: Env, warnings: list[str]) -> dict[str, Any]:
    """What re-pinning may not do silently (AICS-1 §6.3, §6.4): adopt a
    weaker witness policy, or orphan the saved checkpoint history."""
    out: dict[str, Any] = {}
    if old is not None:
        before, after = cardmod.policy_terms(old), cardmod.policy_terms(new)
        cmp = cardmod.compare_witness(before, after)
        out["witness_policy_vs_previous"] = cmp
        if cmp == "weaker":
            if not args.allow_weaker:
                raise PolicyError(
                    "refusing to replace the pinned witness policy with a weaker one: the new terms accept "
                    "checkpoints the pinned ones reject. Witness-policy changes need a logged card under the "
                    "previously trusted policy, and a client must not bootstrap a weaker quorum (AICS-1 §6.3); "
                    "nothing was pinned. Pass --allow-weaker to adopt it anyway",
                    previous=cardmod.terms_dict(before), new=cardmod.terms_dict(after),
                )
            warnings.append("--allow-weaker: the new witness policy is weaker than the one it replaces "
                            f"(was quorum {old.quorum} of {len(old.witness_vkeys)}, max age "
                            f"{old.max_checkpoint_age or 'unset'})")
    store = CheckpointStore(home / "checkpoints")
    reset = bool(args.reset_history)
    if old_origin is None:
        if reset:
            warnings.append("--reset-history ignored: no policy was pinned before")
        return out
    old_notes = store.notes(old_origin)
    if not old_notes:
        if reset:
            warnings.append(f"--reset-history ignored: no checkpoint is saved for {old_origin}")
        return out
    files = [n.file for n in old_notes]
    if old_origin != new.origin:
        if not reset:
            raise PolicyError(
                f"the new trust material names the origin {new.origin!r}, but {len(old_notes)} checkpoint(s) are "
                f"saved for the pinned origin {old_origin!r}; re-pinning would silently orphan that history. Pass "
                "--reset-history to start a new history (recorded in the checkpoint index; no file is deleted); "
                "nothing was pinned",
                saved=len(old_notes), previous_origin=old_origin,
            )
        store.reset(old_origin, now=env.now(), files=files, policy=old,
                    reason=f"aics policy init --reset-history: the origin changed to {new.origin}")
        warnings.append(f"--reset-history: {len(files)} saved checkpoint(s) of {old_origin} no longer take part in "
                        f"continuity checks (files kept, reset recorded in {store.index})")
        out["history_reset"] = {"origin": old_origin, "dropped": len(files)}
    elif reset:
        store.reset(old_origin, now=env.now(), files=files, policy=old,
                    reason="aics policy init --reset-history")
        warnings.append(f"--reset-history: {len(files)} saved checkpoint(s) of {old_origin} no longer take part in "
                        f"continuity checks (files kept, reset recorded in {store.index})")
        out["history_reset"] = {"origin": old_origin, "dropped": len(files)}
    elif old_log_vkey is not None and old_log_vkey != new.log_vkey:
        warnings.append(
            f"the log key changes from {old_log_vkey} to {new.log_vkey}: the {len(old_notes)} saved checkpoint(s) "
            "stay verified under the key they were saved under, and verify checkpoint / verify consistency need a "
            "consistency proof from them to the new log's head (AICS-1 §6.4: replacing a key does not reset history)"
        )
        out["log_key_change"] = {"from": old_log_vkey, "to": new.log_vkey, "saved": len(old_notes)}
    return out


def cmd_policy_init(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    warnings: list[str] = []
    existing = policy_path(home)
    if existing.exists() and not args.force:
        raise PolicyError(f"{existing} exists; pass --force to replace it (the old one is archived)")
    old, old_origin, old_log_vkey = _existing_policy(home, warnings)
    oob: list[SourceValues] = []
    bundles: list[TrustBundle] = []
    dns_info: dict[str, Any] | None = None
    domain = (args.from_dns or args.domain or "").strip().rstrip(".").lower() or None
    if args.from_dns:
        srcs, b, dns_info = _dns_trust(domain, env, args.nameserver)
        oob += srcs
        if b is not None:
            bundles.append(b)
        if not dns_info["dnssec_ad"]:
            warnings.append(f"the DNS answer for {dns_info['name']} was not DNSSEC-authenticated (AD bit unset): "
                            "DNS alone is not a secure root (AICS-1 §6.4)")
    if args.bundle:
        b = bundle_from_text(args.bundle)
        bundles.append(b)
        oob.append(SourceValues("readme", b.values()))
    manual = _manual_trust(args)
    if manual:
        oob.append(SourceValues("manual", manual))
    origin_hint = next((str(s.values["origin"]) for s in oob if s.values.get("origin")), None)
    pub, pub_status = published_bundle(domain, origin_hint)
    if pub is not None:
        bundles.append(pub)
        oob.append(SourceValues(f"pypi:aics=={__version__}", pub.values()))
    else:
        warnings.append(f"the aics package's AICS_TRUST_BUNDLE constant: {pub_status}; nothing to cross-check")
    api = _api_claims(args.from_api, env) if args.from_api else None

    if not oob:
        if api is not None:
            raise PolicyError(
                "refusing to pin a key obtained from the API host alone: the server under scrutiny cannot vouch "
                "for its own key (AICS-1 §6.4); use --from-dns DOMAIN or --bundle from the public README",
                api_claims=api.values,
            )
        raise UsageError("give --from-dns DOMAIN, --bundle (the README block), or the keys by hand")

    rows = compare_sources(oob + ([api] if api is not None else []))
    bad = malformed(rows, {s.label for s in oob})
    if bad:
        raise PolicyError("malformed key material; nothing was pinned: " + "; ".join(bad))
    if api is not None:
        for r in rows:
            if api.label in r["errors"]:
                warnings.append(f"ignored a malformed {r['field']} from the API host")
                api.values.pop(r["field"], None)
    disagreements = [r for r in rows if not r["agree"]]
    if disagreements:
        raise VerificationFailed(
            "out-of-band sources disagree; bootstrap stopped and nothing was pinned (AICS-1 §6.4)",
            evidence={"type": "aics-key-source-disagreement/v1", "fields": disagreements, "dns": dns_info},
        )

    trust: dict[str, Any] = {}
    sources: dict[str, list[str]] = {}
    for f in TRUST_FIELDS:
        for s in oob:
            v = s.values.get(f)
            if v is None:
                continue
            trust.setdefault(f, v)
            sources.setdefault(f, []).append(s.label)
        if f in trust and api is not None and api.values.get(f) is not None:
            sources[f].append(api.label)  # confirms; never counts as a source
    for f in ("origin", "log_vkey"):
        if f not in trust:
            if api is not None and api.values.get(f) is not None:
                raise PolicyError(f"refusing to pin {f} from the API host alone; no out-of-band source gives it",
                                  api_claims=api.values)
            raise PolicyError(f"no out-of-band source gives {f}")
    kinds = _source_kinds(sources["log_vkey"])
    required = args.require_sources if args.require_sources is not None else DEFAULT_REQUIRED_SOURCES
    if len(kinds) < required:
        if args.require_sources is None:
            raise PolicyError(
                f"only {len(kinds)} out-of-band source ({', '.join(kinds)}) gives the log key, and "
                f"{DEFAULT_REQUIRED_SOURCES} independent kinds are required by default"
                + (": DNS that this tool cannot DNSSEC-validate is not a secure root by itself (AICS-1 §6.4)"
                   if kinds == ["dns"] else "")
                + ". Add another source (--bundle with the public README block, or the aics package's constant once "
                  "it is published), or pass --require-sources 1 to pin from a single source knowingly; nothing was "
                  "pinned",
                sources=sources["log_vkey"],
            )
        raise PolicyError(
            f"only {len(kinds)} out-of-band source(s) give the log key; --require-sources is {required}",
            sources=sources["log_vkey"],
        )
    if len(kinds) == 1:
        warnings.append(f"the log key rests on one kind of source ({kinds[0]}), accepted with --require-sources 1")

    bundle_card = trust.get("bootstrap_card_hash")
    urls = default_urls(domain, str(trust["origin"]))
    witness: dict[str, Any] = {"witness_vkeys": [], "quorum": 0, "max_checkpoint_age": None, "witness_meta": {}}
    card_label = None
    card_obj = None
    card_url = args.card_url or urls["card_url"]
    if args.no_card:
        if bundle_card and args.quorum is None:
            raise UsageError(
                "the trust bundle pins a bootstrap card, and the card carries the witness policy; with --no-card give "
                "the witness policy yourself from an independent source: --witness/--quorum/--max-age (--quorum 0 "
                "accepts checkpoints without witnesses)"
            )
    elif not trust.get("policy_kid"):
        warnings.append("no policy key: the witness policy was not read from a card")
    elif not card_url:
        if bundle_card:
            raise PolicyError(
                "the trust bundle pins a bootstrap card, but no card URL could be formed (no domain, and the origin "
                "is not a host name): pass --card-url URL or --domain DOMAIN, or --no-card with "
                "--witness/--quorum/--max-age; nothing was pinned"
            )
        warnings.append("no card URL: the witness policy was not read from a card")
    else:
        card_obj, card_label = _bootstrap_card(card_url, trust, env, home, accept_signed=args.accept_signed_card,
                                               allow_weaker=args.allow_weaker, warnings=warnings)
        wp = card_obj["witness_policy"]
        witness = {
            "witness_vkeys": [format_vkey(parse_witness_vkey(w["vkey"])) for w in wp["witnesses"]],
            "quorum": wp["quorum"],
            "max_checkpoint_age": card_obj["max_checkpoint_age"],
            # the operator's own declarations, kept as such (AICS-1 §6.3)
            "witness_meta": {w["name"]: {"declared_trust_domain": w["trust_domain"],
                                         "declared_independent": w["independent"]}
                             for w in wp["witnesses"]},
        }
        urls.update(_card_urls(card_obj, str(trust["origin"])))
        for f in ("witness_vkeys", "quorum", "max_checkpoint_age"):
            sources[f] = [card_label]
    card_terms = (witness["quorum"], frozenset(witness["witness_vkeys"]),
                  witness["max_checkpoint_age"] or cardmod.UINT_MAX)
    if args.witness is not None:
        witness["witness_vkeys"] = [format_vkey(parse_witness_vkey(w)) for w in args.witness]
        witness["witness_meta"] = {k: v for k, v in witness["witness_meta"].items()
                                   if any(w.startswith(k + "+") for w in witness["witness_vkeys"])}
        sources["witness_vkeys"] = ["manual"]
    if args.quorum is not None:
        witness["quorum"] = args.quorum
        sources["quorum"] = ["manual"]
    if args.max_age is not None:
        witness["max_checkpoint_age"] = args.max_age
        sources["max_checkpoint_age"] = ["manual"]
    if args.independent:
        names = {parse_witness_vkey(w).name for w in witness["witness_vkeys"]}
        for name in args.independent:
            if name not in names:
                raise UsageError(f"--independent {name!r} is not one of the pinned witnesses "
                                 f"({', '.join(sorted(names)) or 'none'})")
            witness["witness_meta"].setdefault(name, {}).update(independent=True, independent_source="manual")
        sources["witness_independence"] = ["manual"]
    if card_obj is not None:
        mine = (witness["quorum"], frozenset(witness["witness_vkeys"]),
                witness["max_checkpoint_age"] or cardmod.UINT_MAX)
        if not cardmod.at_least_as_strict(mine, card_terms):
            warnings.append("the witness terms given by hand are weaker than the card's")
    for f, flag in (("checkpoint_url", args.checkpoint_url), ("tiles_url", args.tiles_url),
                    ("consistency_url", args.consistency_url)):
        if flag is not None:
            urls[f] = flag
    if args.mirror is not None:
        urls["mirrors"] = list(args.mirror)

    full_bundle = bundles[0] if bundles else None
    policy = Policy(
        origin=str(trust["origin"]),
        log_vkey=format_vkey(parse_log_vkey(str(trust["log_vkey"]))),
        policy_kid=parse_policy_key(trust["policy_kid"]).did if trust.get("policy_kid") else None,
        owner_kid=parse_policy_key(trust["owner_kid"]).did if trust.get("owner_kid") else None,
        bootstrap_card_hash=trust.get("bootstrap_card_hash"),
        trust_bundle_sha256=full_bundle.sha256 if full_bundle else None,
        witness_vkeys=witness["witness_vkeys"],
        quorum=int(witness["quorum"]),
        max_checkpoint_age=witness["max_checkpoint_age"],
        witness_meta=witness["witness_meta"],
        domain=domain,
        checkpoint_url=urls["checkpoint_url"],
        tiles_url=urls["tiles_url"],
        card_url=card_url or "",
        consistency_url=urls["consistency_url"],
        mirrors=list(urls["mirrors"]),
        sources=sources,
        created_at=_iso(env.now()) or "",
    )
    policy.validate()
    if not policy.policy_kid:
        warnings.append("no policy key pinned: aics verify card cannot run until one is pinned")
    if policy.quorum == 0:
        warnings.append("witness quorum 0: checkpoint freshness is unproven and single view (G5) is promised")
    repin = _repin_checks(old, old_origin, old_log_vkey, policy, home, args, env, warnings)
    path = save(policy, home, force=args.force)
    if card_obj is not None:
        cardmod.CardStore(home / "cards").save(policy.policy_kid, card_url, card_obj, now=env.now(),
                                               status="bootstrap" if card_label.startswith("card:") else
                                               "signature-only")
    trust_root = _trust_root(policy, "agrees" if pub is not None else pub_status)
    data = {"policy": policy.summary(), "path": str(path), "dns": dns_info, "trust_root": trust_root,
            "repin": repin, "warnings": warnings}
    text = [f"pinned policy written to {path}",
            f"origin     {policy.origin}",
            f"log key    {policy.log_vkey}   [{', '.join(sources['log_vkey'])}]",
            f"trust root {trust_root}",
            f"policy     {policy.policy_kid or '(none)'}",
            f"witnesses  {len(policy.witness_vkeys)}, quorum {policy.quorum}, "
            f"max checkpoint age {policy.max_checkpoint_age or 'unset'}"
            + (f"   [{', '.join(sources.get('quorum', []))}]" if sources.get("quorum") else "")]
    text += [f"warning: {w}" for w in warnings]
    return _ok(data, text)


def _bundle_of(policy: Policy) -> TrustBundle | None:
    if all(getattr(policy, f) for f in TRUST_FIELDS):
        return TrustBundle(origin=policy.origin, log_vkey=policy.log_vkey, policy_kid=policy.policy_kid,
                           owner_kid=policy.owner_kid, bootstrap_card_hash=policy.bootstrap_card_hash)
    return None


def cmd_policy_show(args: Any, env: Env) -> Result:
    policy = load(_home_dir(args, env))
    status, disagree = _pypi_check(policy)
    b = _bundle_of(policy)
    data = {"policy": policy.summary(), "trust_bundle": b.to_dict() if b else None,
            "trust_bundle_sha256": b.sha256 if b else None, "txt_record": b.txt if b else None,
            "pypi_constant": status, "trust_root": _trust_root(policy, status)}
    if status == "disagrees":
        raise VerificationFailed(
            "the pinned policy contradicts the trust bundle published in this aics package (run: aics policy diff)",
            evidence={"type": "aics-key-source-disagreement/v1", "fields": disagree}, **data)
    text = [f"{k} = {json.dumps(v)}" for k, v in policy.summary().items()]
    text.append(f"trust root: {data['trust_root']}; pypi constant: {status}")
    if b:
        text.append(f"trust bundle (TXT _aics.<domain>): {b.txt}")
        text.append(f"trust bundle sha256: {b.sha256}")
    return _ok(data, text)


def cmd_policy_diff(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    try:
        policy: Policy | None = load(home)
    except PolicyError as exc:
        if "no pinned policy" not in exc.message:
            raise
        policy = None
    domain = (args.domain or (policy.domain if policy else None) or "").strip().rstrip(".").lower()
    if not domain:
        raise UsageError("no domain: pass --domain or pin a policy with policy init --from-dns")
    sources: list[SourceValues] = []
    dns_error = None
    dns_info = None
    try:
        srcs, _b, dns_info = _dns_trust(domain, env, args.nameserver)
        sources += [SourceValues("dns", s.values) for s in srcs]
    except (DnsError, PolicyError) as exc:
        dns_error = exc.message
    try:
        pub, pub_status = published_bundle(domain, policy.origin if policy else None)
    except PolicyError as exc:
        pub, pub_status = None, f"invalid: {exc.message}"
    sources.append(SourceValues("pypi", pub.values() if pub else {}))
    if policy is not None:
        sources.append(SourceValues("policy", policy.trust_values()))
    rows = compare_sources(sources)
    for r in rows:
        r["missing"] = [s.label for s in sources if s.values.get(r["field"]) is None]
    disagree = [r for r in rows if not r["agree"]]
    bad = malformed(rows)
    data = {
        "domain": domain,
        "rows": rows,
        "malformed": bad,
        "dns": dns_info,
        "dns_error": dns_error,
        "pypi": pub_status,
        "policy_path": str(policy.path) if policy else None,
    }
    text = [f"{'FIELD':<20} {'AGREE':<6} SOURCES"]
    for r in rows:
        vals = "; ".join(f"{k}={escape_untrusted(v)}" for k, v in r["values"].items()) or "(nobody publishes it)"
        miss = f"   [not published: {', '.join(r['missing'])}]" if r["missing"] else ""
        text.append(f"{r['field']:<20} {'yes' if r['agree'] else 'NO':<6} {vals}{miss}")
    text.append(f"pypi constant: {pub_status}")
    if disagree:
        raise VerificationFailed(
            f"sources disagree on: {', '.join(r['field'] for r in disagree)}",
            evidence={"type": "aics-key-source-disagreement/v1", "fields": disagree, "dns": dns_info},
            **data,
        )
    if dns_error:
        raise AicsError(f"DNS could not be checked: {dns_error}", **data)
    if bad:
        raise AicsError("malformed key material: " + "; ".join(bad), **data)
    return _ok(data, text)


# ---------------------------------------------------------------------------
# the pinned policy, as every verifying command loads it
# ---------------------------------------------------------------------------


def _pypi_check(policy: Policy) -> tuple[str, list[dict[str, Any]]]:
    try:
        pub, status = published_bundle(policy.domain, policy.origin)
    except PolicyError as exc:
        return f"invalid: {exc.message}", []
    if pub is None:
        return status, []
    rows = compare_sources([SourceValues("pypi", pub.values()), SourceValues("policy", policy.trust_values())])
    bad = [r for r in rows if not r["agree"]]
    return ("disagrees" if bad else "agrees"), bad


def _load_policy(home: Path) -> tuple[Policy, str]:
    """Load the pinned policy and hold it against the trust bundle shipped in
    this package: a policy the package contradicts is not used by any
    command (exit 2, the disagreement is the evidence)."""
    policy = load(home)
    status, bad = _pypi_check(policy)
    if status == "disagrees":
        raise VerificationFailed(
            "the pinned policy contradicts the trust bundle published in this aics package; nothing was checked "
            "(compare the sources with: aics policy diff)",
            evidence={"type": "aics-key-source-disagreement/v1", "fields": bad},
        )
    return policy, status


def _key_sources(policy: Policy, pypi_status: str) -> dict[str, Any]:
    return {
        "recorded": {f: policy.key_sources(f) for f in ("origin", "log_vkey", "policy_kid", "witness_vkeys", "quorum")
                     if f in policy.sources or f in ("origin", "log_vkey")},
        "pypi_constant": pypi_status,
        "trust_root": _trust_root(policy, pypi_status),
        "dns": "compare with: aics policy diff",
    }


# ---------------------------------------------------------------------------
# checkpoints
# ---------------------------------------------------------------------------


def _failure(chk: NoteCheck, policy: Policy, note_text: str, source: str) -> VerificationFailed:
    return VerificationFailed(
        f"checkpoint from {source}: {chk.error}",
        evidence={
            "type": "aics-checkpoint-failure/v1",
            "reason": chk.reason,
            "source": source,
            "note": note_text,
            "pinned": {"origin": policy.origin, "log_vkey": policy.log_vkey,
                       "witness_vkeys": policy.witness_vkeys, "quorum": policy.quorum,
                       "max_checkpoint_age": policy.max_checkpoint_age},
            "witnesses": chk.witnesses,
        },
        checkpoint=chk.report(),
    )


def _read_text_arg(arg: str, env: Env) -> tuple[str, str]:
    """A note given as a file path, '-' (stdin) or an https URL."""
    if arg == "-":
        stream = env.stdin or sys.stdin
        return stream.read(), "stdin"
    if arg.startswith("https://") or arg.startswith("http://"):
        return fetch_checkpoint(env.fetcher, arg).note_text, arg
    try:
        return Path(arg).expanduser().read_text("utf-8"), arg
    except (OSError, UnicodeDecodeError) as exc:
        raise AicsError(f"cannot read {arg}: {exc}") from None


def _check_or_raise(text: str, policy: Policy, env: Env, source: str, *, origin: bool,
                    max_skew: int = DEFAULT_MAX_SKEW, require_fresh: bool = True) -> NoteCheck:
    """Accept the note as a current head, or raise with the right exit code:
    2 only when the output is evidence (anything the log origin itself
    served, or a log-signed checkpoint no log can produce), 1 for a stale or
    under-witnessed head and for an invalid note from any other source."""
    chk = check_note(text, policy, source=source, now=env.now(), max_skew=max_skew, require_fresh=require_fresh)
    if chk.ok and chk.cp is not None:
        return chk
    if chk.reason == "malformed":
        raise AicsError(f"{source}: {chk.error}")
    if chk.reason == "quorum":
        raise AicsError(
            f"stale: the checkpoint from {source} is log-signed, but {chk.error}. A stale or under-witnessed head "
            "is not accepted as current; it is not evidence against the log",
            result="stale", reason=chk.reason, source=source, note=text, witnesses=chk.witnesses,
            checkpoint=chk.report(),
        )
    if origin or chk.reason in SELF_CONTAINED_EVIDENCE:
        raise _failure(chk, policy, text, source)
    raise AicsError(
        f"invalid: the checkpoint from {source} does not verify ({chk.error}). It did not come from the log origin, "
        "and anyone on that path can produce such a note, so it is not evidence against the log",
        result="invalid", reason=chk.reason, source=source, note=text, witnesses=chk.witnesses,
        checkpoint=chk.report(),
    )


def _current(policy: Policy, env: Env, url: str, *, max_skew: int, warnings: list[str]) -> tuple[Cp, NoteCheck]:
    fetched = fetch_checkpoint(env.fetcher, url)
    warnings += api_key_warnings(fetched, policy)
    chk = _check_or_raise(fetched.note_text, policy, env, url, origin=url == policy.checkpoint_url,
                          max_skew=max_skew)
    warnings += chk.warnings
    return chk.cp, chk


def _endpoint(policy: Policy, env: Env) -> list[Any]:
    if not policy.consistency_url:
        return []
    return [EndpointSource(f"consistency endpoint {policy.consistency_url}", policy.consistency_url, env.fetcher)]


def _proof_sources(policy: Policy, env: Env, ref: Cp | None, readers: dict[str, HttpTileReader]) -> list[Any]:
    """Tiles first (authenticated, and cached across many saved checkpoints),
    then mirrors, then the proof endpoint."""
    srcs: list[Any] = []
    bases = ([policy.tiles_url] if policy.tiles_url else []) + list(policy.mirrors)
    for base in bases:
        reader = readers.setdefault(base, HttpTileReader(base, env.fetcher))
        srcs.append(TileSource(f"tiles {base}", reader, ref=ref))
    return srcs + _endpoint(policy, env)


def _relate_current(old: Cp, current: Cp, sources: list[Any]) -> Relation:
    """``old`` (saved) against ``current``.  A current tree smaller than a
    saved one is never adopted (AICS-1 §14.1 step 4, §14.2 step 1): the
    histories are compared, a proven fork is ``split-proven``, a consistent
    older head is ``historical`` and anything else is ``unproven``."""
    if old.size <= current.size:
        return relate(old, current, sources)
    historical = [TileSource(s.label, s.reader, ref=None) if isinstance(s, TileSource) else s for s in sources]
    hist = relate(current, old, historical)
    if hist.status == "split-proven":
        return hist
    attempts = [Attempt("history", hist.status, "the smaller current head against the larger saved one",
                        current, old)] + hist.attempts
    if hist.status == "consistent":
        return Relation(status="historical", a=current, b=old, reason="older-consistent-head", attempts=attempts,
                        winning=hist.winning)
    return Relation(status="unproven", a=current, b=old, reason="older-head-unproven", attempts=attempts)


def _split_words(rel: Relation, current: Cp) -> str:
    if rel.reason == "bad-empty-root":
        return "a log-signed size-0 checkpoint carries a root that is not SHA-256(\"\")"
    if current.size < max(rel.a.size, rel.b.size):
        return "the log now serves a smaller tree that is not a prefix of the saved one: it rewrote its history"
    return "the log forked or rewrote its history"


def _saved_keys(saved: SavedNote, policy: Policy, archived: dict[str, tuple[str, str]]) -> list[str]:
    """Log keys other than the pinned one that ``saved`` was verified with
    when it was saved: recorded in the index, or in the archived policy
    whose digest the index recorded."""
    keys = list(saved.recorded_log_vkeys())
    for digest in saved.policy_digests():
        hit = archived.get(digest)
        if hit and hit[0] == policy.origin and hit[1] not in keys:
            keys.append(hit[1])
    return [k for k in keys if k != policy.log_vkey]


def _verify_saved(saved: SavedNote, policy: Policy, env: Env, home: Path,
                  cache: dict[str, Any]) -> tuple[Cp | None, str | None]:
    """Authenticate a saved note by its log signature: under the pinned key,
    or under the key it was saved under (a log-key replacement does not
    reset history, AICS-1 §6.4).  Witness lines play no part: continuity is
    about what the log signed."""
    chk = check_note(saved.text, policy, source=str(saved.path), now=env.now(), require_fresh=False)
    if chk.cp is not None:
        return chk.cp, None
    if chk.reason == "malformed":
        return None, chk.error
    if "archived" not in cache:
        cache["archived"] = archived_log_keys(home)
    for vkey in _saved_keys(saved, policy, cache["archived"]):
        try:
            cp, _err, _reason = log_signed(saved.text, origin=policy.origin, log_vkey=vkey, source=str(saved.path))
        except PolicyError:  # a malformed recorded key
            continue
        if cp is not None:
            return cp, None
    return None, chk.error


def _unverifiable(store: CheckpointStore, policy: Policy, env: Env, home: Path,
                  cache: dict[str, Any]) -> tuple[list[Cp], list[dict[str, Any]]]:
    good: list[Cp] = []
    bad: list[dict[str, Any]] = []
    for saved in store.notes(policy.origin):
        cp, err = _verify_saved(saved, policy, env, home, cache)
        if cp is None:
            bad.append({"file": saved.file, "path": str(saved.path), "reason": err})
        else:
            good.append(cp)
    return good, bad


def _reset_reason(command: str, bad: list[dict[str, Any]]) -> str:
    return (f"{command} --reset-history: unverifiable saved checkpoint(s): "
            + "; ".join(f"{b['file']}: {b['reason']}" for b in bad))


def _head(store: CheckpointStore, policy: Policy, env: Env, home: Path, warnings: list[str], *,
          reset_history: bool = False, command: str = "aics") -> tuple[Cp | None, dict[str, Any] | None]:
    """The saved head, authenticated by its log signature (under the pinned
    key or the key it was saved under).  A saved head that cannot be
    authenticated is never silently replaced: that is an error unless the
    user passes --reset-history, and the reset is recorded.  Returns
    (head, reset record)."""
    saved = store.head(policy.origin)
    if saved is None:
        return None, None
    cache: dict[str, Any] = {}
    cp, err = _verify_saved(saved, policy, env, home, cache)
    if cp is not None:
        if cp.log_vkey and cp.log_vkey != policy.log_vkey:
            warnings.append(f"the saved head {saved.path.name} is signed by the log key pinned when it was saved "
                            f"({cp.log_vkey}); continuity across the key change needs a consistency proof from it")
        return cp, None
    if not reset_history:
        raise AicsError(
            f"the saved head {saved.path} cannot be authenticated with the pinned log key or with the key it was "
            f"saved under: {err}. Continuity cannot be checked, so nothing was accepted. Inspect the file; to drop "
            f"the unverifiable saved checkpoints of {policy.origin} from continuity checks, rerun with "
            f"--reset-history (recorded in {store.index}; no file is deleted)",
            saved_head=str(saved.path), reason=err,
        )
    _good, bad = _unverifiable(store, policy, env, home, cache)
    files = sorted({b["file"] for b in bad} | {saved.file})
    store.reset(policy.origin, now=env.now(), files=files, policy=policy,
                reason=_reset_reason(command, bad or [{"file": saved.file, "reason": err}]))
    warnings.append(f"--reset-history: {len(files)} unverifiable saved checkpoint(s) no longer take part in "
                    f"continuity checks (files kept, reset recorded in {store.index})")
    head, _ = _head(store, policy, env, home, warnings, reset_history=False, command=command)
    return head, {"dropped": files, "reasons": bad}


def cmd_verify_checkpoint(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    policy, pypi_status = _load_policy(home)
    trust_root = _trust_root(policy, pypi_status)
    warnings: list[str] = []
    store = CheckpointStore(home / "checkpoints")
    reset_history = bool(getattr(args, "reset_history", False))
    history_reset = None
    continuity: dict[str, Any]
    if args.note:
        text, source = _read_text_arg(args.note, env)
        chk = _check_or_raise(text, policy, env, source, origin=False, max_skew=args.max_skew)
        warnings += chk.warnings
        cp = chk.cp
        continuity = {"status": "not checked (local note)"}
        saved = None
    else:
        url = args.url or policy.checkpoint_url
        if not url:
            raise PolicyError("no checkpoint URL: pass --url or pin checkpoint_url")
        cp, chk = _current(policy, env, url, max_skew=args.max_skew, warnings=warnings)
        head, history_reset = _head(store, policy, env, home, warnings, reset_history=reset_history,
                                    command="aics verify checkpoint")
        if reset_history and history_reset is None:
            warnings.append("--reset-history ignored: " + ("no checkpoint is saved for this origin" if head is None
                                                          else "the saved head verifies"))
        saved = None
        if head is None or head.sha256 == cp.sha256:
            if head is not None:
                status = "same as the saved head"
            else:
                status = "first (history reset)" if history_reset else "first"
            continuity = {"status": status}
            role = "head"
        else:
            rel = _relate_current(head, cp, _proof_sources(policy, env, cp, {}))
            continuity = {"status": rel.status, "saved_head": head.brief(), "detail": rel.report()}
            role = {"consistent": "head", "historical": "observed"}.get(rel.status, "evidence")
            if not args.no_save:
                s = store.save(cp, now=env.now(), role=role, continuity=rel.status, policy=policy)
                saved = {"path": str(s.path), "new": s.created, "role": role}
            if rel.status == "split-proven":
                raise VerificationFailed(
                    f"the checkpoint is valid but is not a continuation of the saved head (size {head.size}): "
                    + _split_words(rel, cp),
                    evidence=split_bundle(policy, rel, now=env.now(), context=f"aics verify checkpoint ({url})"),
                    checkpoint=chk.report(), saved=saved,
                )
            if rel.status == "historical":
                raise AicsError(
                    f"historical, not adopted: the served checkpoint (size {cp.size}) is older than the saved head "
                    f"(size {head.size}) and consistent with it; an older consistent head is historical only "
                    "(AICS-1 §14.1 step 4), so the head stays where it was",
                    result="historical", checkpoint=chk.report(), continuity=continuity, saved=saved,
                )
            if rel.status != "consistent":
                raise AicsError(
                    f"incomplete: the checkpoint verifies, but its consistency with the saved head (size {head.size}) "
                    "could not be proven, so the head was not advanced (AICS-1 §14.1 step 4); check tiles_url",
                    checkpoint=chk.report(), continuity=continuity, saved=saved,
                )
        if saved is None and not args.no_save:
            s = store.save(cp, now=env.now(), role=role, continuity=continuity["status"], policy=policy)
            saved = {"path": str(s.path), "new": s.created, "role": role}
    data = {**chk.report(), "source": cp.source, "continuity": continuity, "saved": saved,
            "trust_root": trust_root, "key_sources": _key_sources(policy, pypi_status), "warnings": warnings}
    if history_reset:
        data["history_reset"] = history_reset
    wit = ", ".join(f"{w['name']} {w['status']}" + (f" ({w['age_seconds']}s old)" if "age_seconds" in w else "")
                    for w in chk.witnesses) or "none pinned"
    text = [
        f"checkpoint ok: {cp.origin} size {cp.size} (trust root: {trust_root})",
        f"root       {cp.root_b64}",
        f"log key    {policy.log_vkey} [{', '.join(policy.key_sources('log_vkey'))}; pypi constant: {pypi_status}]",
        f"witnesses  {chk.counted}/{policy.quorum} required: {wit}",
        f"freshness  {chk.freshness}",
        f"continuity {continuity['status']}",
    ]
    if saved:
        text.append(f"saved      {saved['path']} ({'new' if saved['new'] else 'already saved'}, {saved['role']})")
    text += [f"warning: {w}" for w in warnings]
    return _ok(data, text)


def cmd_verify_consistency(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    policy, pypi_status = _load_policy(home)
    trust_root = _trust_root(policy, pypi_status)
    store = CheckpointStore(home / "checkpoints")
    warnings: list[str] = []
    url = args.url or policy.checkpoint_url
    if not url:
        raise PolicyError("no checkpoint URL: pass --url or pin checkpoint_url")
    verified, unverifiable = _unverifiable(store, policy, env, home, {})
    history_reset = None
    if unverifiable:
        if not getattr(args, "reset_history", False):
            raise AicsError(
                f"{len(unverifiable)} saved checkpoint(s) of {policy.origin} cannot be authenticated with the pinned "
                "log key or with the key they were saved under, so their consistency with today's log cannot be "
                "checked: " + "; ".join(f"{u['path']}: {u['reason']}" for u in unverifiable)
                + f". Inspect them; rerun with --reset-history to drop them from continuity checks (recorded in "
                  f"{store.index}; no file is deleted)",
                unverifiable=unverifiable,
            )
        store.reset(policy.origin, now=env.now(), files=[u["file"] for u in unverifiable], policy=policy,
                    reason=_reset_reason("aics verify consistency", unverifiable))
        history_reset = {"dropped": [u["file"] for u in unverifiable], "reasons": unverifiable}
        warnings.append(f"--reset-history: {len(unverifiable)} unverifiable saved checkpoint(s) no longer take part "
                        f"in continuity checks (files kept, reset recorded in {store.index})")
    elif getattr(args, "reset_history", False):
        warnings.append("--reset-history ignored: every saved checkpoint verifies")
    latest, chk = _current(policy, env, url, max_skew=args.max_skew, warnings=warnings)
    for cp in verified:
        if cp.log_vkey and cp.log_vkey != policy.log_vkey:
            warnings.append(f"saved size {cp.size} is checked under the log key it was saved under ({cp.log_vkey})")
    readers: dict[str, HttpTileReader] = {}
    results: list[Relation] = []
    for cp in verified:
        if cp.sha256 == latest.sha256:
            continue
        results.append(_relate_current(cp, latest, _proof_sources(policy, env, latest, readers)))
    failures = [r for r in results if r.status == "split-proven"]
    unproven = [r for r in results if r.status == "unproven"]
    historical = [r for r in results if r.status == "historical"]
    proven = [r for r in results if r.status == "consistent"]
    if failures or unproven:
        role = "evidence"
    elif historical:
        role = "observed"
    else:
        role = "head"
    first = (failures or unproven or historical or [None])[0]
    s = store.save(latest, now=env.now(), role=role, policy=policy,
                   continuity="consistent" if first is None else first.status)
    data: dict[str, Any] = {
        "latest": latest.brief(),
        "freshness": chk.freshness,
        "saved_latest": {"path": str(s.path), "new": s.created, "role": role},
        "checked": [r.report() for r in results],
        "consistent": len(proven),
        "trust_root": trust_root,
        "warnings": warnings,
    }
    if history_reset:
        data["history_reset"] = history_reset
    if failures:
        r = failures[0]
        raise VerificationFailed(
            f"{len(failures)} saved checkpoint(s) are not a prefix of the log served now (size {latest.size}): "
            + _split_words(r, latest),
            evidence=split_bundle(policy, r, now=env.now(), context=f"aics verify consistency --saved ({url})"),
            **data,
        )
    if unproven:
        raise AicsError(
            f"consistency unproven for {len(unproven)} saved checkpoint(s): no valid proof could be obtained. "
            "This is an availability alert, not evidence of a split (AICS-1 §14.6); check tiles_url/consistency_url",
            **data,
        )
    if historical:
        biggest = max(max(r.a.size, r.b.size) for r in historical)
        raise AicsError(
            f"historical, not adopted: the log serves size {latest.size}, older than {len(historical)} saved "
            f"checkpoint(s) (up to size {biggest}) and consistent with them; an older consistent head is historical "
            "only (AICS-1 §14.1 step 4)",
            result="historical", **data,
        )
    text = [f"consistent: {len(proven)} saved checkpoint(s) are prefixes of {latest.origin} size {latest.size} "
            f"(trust root: {trust_root})"]
    if not results:
        text = [f"no earlier checkpoint saved for {latest.origin}; saved size {latest.size} as the head "
                f"(trust root: {trust_root})"]
    for r in results:
        src = r.winning.source if r.winning else (r.reason or "")
        text.append(f"  size {r.a.size:<10} -> {r.b.size}: {r.status} ({src})")
    text += [f"warning: {w}" for w in data["warnings"]]
    return _ok(data, text)


# ---------------------------------------------------------------------------
# gossip-check
# ---------------------------------------------------------------------------


def _reference_sources(policy: Policy, env: Env, notes: list[str], witness_ok: dict[str, bool]) -> list[Any]:
    """Proof sources: the endpoint, then each tile prefix with its own current,
    log-signed checkpoint as the reference."""
    srcs: list[Any] = []
    pairs = []
    if policy.checkpoint_url and policy.tiles_url:
        pairs.append((policy.checkpoint_url, policy.tiles_url))
    pairs += [(join_url(m, "checkpoint"), m) for m in policy.mirrors]
    for cp_url, base in pairs:
        try:
            fetched = fetch_checkpoint(env.fetcher, cp_url)
        except (FetchError, AicsError) as exc:
            notes.append(f"{cp_url}: {exc.message}")
            continue
        chk = check_note(fetched.note_text, policy, source=cp_url, now=env.now(), require_fresh=False)
        if chk.cp is None or chk.reason in SELF_CONTAINED_EVIDENCE:
            notes.append(f"{cp_url}: reference checkpoint rejected: {chk.error}")
            continue
        witness_ok.setdefault(chk.cp.sha256, chk.witness_ok)
        srcs.append(TileSource(f"tiles {base} (reference size {chk.cp.size})", HttpTileReader(base, env.fetcher),
                               ref=chk.cp))
    return srcs + _endpoint(policy, env)


def _witness_reason(chk: NoteCheck) -> str | None:
    if chk.witness_ok:
        return None
    bad = [w["name"] for w in chk.witnesses if w["status"] == "invalid"]
    if bad:
        return f"an invalid cosignature line under pinned witness {', '.join(bad)}"
    return f"{chk.counted} valid cosignature(s) < quorum {chk.quorum}"


def cmd_gossip_check(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    policy, _pypi_status = _load_policy(home)
    cps: list[Cp] = []
    witness_ok: dict[str, bool] = {}
    witness_why: dict[str, str | None] = {}
    for i, arg in enumerate((args.note1, args.note2), 1):
        text, source = _read_text_arg(arg, env)
        chk = check_note(text, policy, source=source, now=env.now(), require_fresh=False)
        if chk.cp is None:  # not log-signed by the pinned key: proves nothing about this log
            raise AicsError(f"note {i} ({source}) is not evidence: {chk.error}", note=i, reason=chk.reason,
                            witnesses=chk.witnesses)
        # Evidence is authenticated by the log signature alone (AICS-1 §14.6
        # step 2); the witness status is reported separately.
        witness_ok[chk.cp.sha256] = chk.witness_ok
        witness_why[chk.cp.sha256] = _witness_reason(chk)
        cps.append(chk.cp)
    a, b = cps
    notes: list[str] = []
    sources: list[Any] = []
    if a.size != b.size:
        if args.proof:
            try:
                hashes = parse_hash_lines(Path(args.proof).expanduser().read_text("utf-8"))
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise AicsError(f"cannot read proof {args.proof}: {exc}") from None
            sources.append(GivenProof(f"proof file {args.proof}", hashes))
        if not args.offline:
            sources += _reference_sources(policy, env, notes, witness_ok)
    rel = relate(a, b, sources)
    checked = []
    for c in cps:
        entry = {**c.brief(), "witness_policy_met": witness_ok[c.sha256]}
        if witness_why[c.sha256]:
            entry["witness_reason"] = witness_why[c.sha256]
        checked.append(entry)
    data: dict[str, Any] = {
        "relation": rel.report(),
        "notes_checked": checked,
        "source_notes": notes,
    }
    if rel.status == "consistent":
        data["split"] = False
        how = rel.reason or (rel.winning.source if rel.winning else "")
        return _ok(data, [f"no split: size {rel.a.size} is a prefix of size {rel.b.size} ({escape_untrusted(how)})"])
    if rel.status == "split-proven":
        bundle = split_bundle(policy, rel, now=env.now(), context="aics gossip-check", witness_status=witness_ok)
        classification = bundle["classification"]
        # A split view (G5) is proven only between notes that all met the
        # witness policy; otherwise the log equivocated, but a client
        # following the policy would not have accepted both notes.
        data["relation"]["status"] = classification
        data["classification"] = classification
        data["split"] = classification == "split-proven"
        data["log_equivocation"] = True
        if args.out:
            out = Path(args.out).expanduser()
            try:
                _home.write_new(out, (json.dumps(bundle, indent=2) + "\n").encode("utf-8"))
            except FileExistsError:
                raise AicsError(f"{out} exists; evidence files are never overwritten") from None
            data["evidence_file"] = str(out)
        raise VerificationFailed(f"{classification}: {bundle['explanation']}", evidence=bundle, **data)
    data["split"] = None
    if a.size != b.size and not sources:
        raise AicsError("consistency-unproven: the notes differ in size and, offline, a proof is needed "
                        "(--proof FILE)", **data)
    raise AicsError("consistency-unproven: no valid consistency proof could be obtained. That is an availability "
                    "alert, not evidence of a split (AICS-1 §14.6 step 5)", **data)


# ---------------------------------------------------------------------------
# card
# ---------------------------------------------------------------------------

CARD_CHECKED = [
    "JWS-over-JCS signature by the pinned policy key (AICS-1 §13.2)",
    "schema (AICS-1 §13.1; the sup member and §20.8 codes of an AICS-1+SUP-1 card, §20.9) and status bounds "
    "(AICS-1 §13.3)",
    "validity window (issued_at, expires)",
    "origin and keys against the pinned trust bundle",
    "history against the card saved for this policy key (supersession, equivocation, witness downgrade)",
]
CARD_NOT_CHECKED = [
    "the evidence behind 'proven' assurances (not fetched or checked)",
    "the card's policy leaf, its inclusion and activation, notice periods and supersession by later policy events "
    "(AICS-1 §14.5 steps 3-4)",
]


def cmd_verify_card(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    policy, pypi_status = _load_policy(home)
    if not policy.policy_kid:
        raise PolicyError("no policy key is pinned, so the card cannot be verified; pin one (policy init)")
    url = cardmod.resolve_url(args.url, policy)
    if args.file:
        try:
            raw = Path(args.file).expanduser().read_bytes()
        except OSError as exc:
            raise AicsError(f"cannot read {args.file}: {exc}") from None
    else:
        raw = cardmod.fetch_card(env.fetcher, url)
    try:
        card = cardmod.loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AicsError(f"card is not strict JSON: {exc}") from None
    if not isinstance(card, dict):
        raise AicsError("card is not a JSON object")
    checks = cardmod.check_signatures(card, policy.policy_keys())
    sig_reports = [c.report() for c in checks]
    try:
        h = cardmod.card_hash(card)
    except ValueError as exc:
        raise AicsError(f"card cannot be canonicalised (RFC 8785): {exc}") from None
    base = {"type": "aics-card-failure/v1", "url": url, "card_hash": h, "signatures": sig_reports,
            "pinned_policy_kid": policy.policy_kid, "card": card}
    if any(c.status == "invalid" for c in checks):
        raise VerificationFailed("card signature does not verify: the card was altered after signing",
                                 evidence={**base, "reason": "invalid-signature"})
    if not any(c.status == "valid" for c in checks):
        raise VerificationFailed("the card carries no valid signature from the pinned policy key",
                                 evidence={**base, "reason": "no-pinned-signature"})
    _refuse_unsupported_profile(card, "the signed card", url=url, card_hash=h, signatures=sig_reports)
    problems = cardmod.schema_problems(card)
    if problems:
        raise VerificationFailed("the card does not follow the AICS-1 §13.1 schema",
                                 evidence={**base, "reason": "schema", "problems": problems})
    bounds = cardmod.assurance_problems(card)
    if bounds:
        raise VerificationFailed("the signed card claims statuses outside the AICS-1 §13.3 boundaries",
                                 evidence={**base, "reason": "assurance-bounds", "problems": bounds})
    now = env.now()
    if card["issued_at"] > now + cardmod.FUTURE_SKEW:
        raise VerificationFailed(f"the card is not valid yet (issued_at {_iso(card['issued_at'])})",
                                 evidence={**base, "reason": "not-yet-valid", "checked_at": _iso(now)})
    if now >= card["expires"]:
        raise VerificationFailed(f"the card expired at {_iso(card['expires'])} (stale)",
                                 evidence={**base, "reason": "expired", "checked_at": _iso(now)})
    anchors = cardmod.anchor_mismatches(card, policy)
    store = cardmod.CardStore(home / "cards")
    hist = cardmod.compare_with_saved(store, policy.policy_kid, card)
    bootstrap = bool(policy.bootstrap_card_hash) and h == policy.bootstrap_card_hash
    vs_pinned = cardmod.compare_witness(cardmod.policy_terms(policy), cardmod.witness_terms(card))
    table = cardmod.guarantee_table(card)
    trust_root = _trust_root(policy, pypi_status)
    data: dict[str, Any] = {
        "url": url,
        "card_hash": h,
        "signatures": sig_reports,
        "issued_at": _iso(card["issued_at"]),
        "expires": _iso(card["expires"]),
        "bootstrap": bootstrap,
        "currency": "bootstrap card; later policy events not checked" if bootstrap else
                    f"unproven: needs its policy leaf in the log ({UNAVAILABLE_MESSAGE})",
        "witness_policy_vs_saved_card": hist.witness,
        "witness_policy_vs_pinned": vs_pinned,
        "previous": hist.previous.meta if hist.previous else None,
        "diff": hist.diff,
        "table": table,
        "table_note": cardmod.TABLE_NOTE,
        "anchor_mismatches": anchors,
        "checked": CARD_CHECKED,
        "unproven": CARD_NOT_CHECKED,
        "trust_root": trust_root,
    }
    if anchors:
        raise VerificationFailed(
            "the signed card states keys that differ from the pinned trust bundle: "
            + ", ".join(m["field"] for m in anchors),
            evidence={**base, "reason": "anchor-mismatch", "mismatches": anchors}, **data)
    problem = hist.problem()
    if problem is not None:
        raise VerificationFailed(
            cardmod.HISTORY_MESSAGES[problem],
            evidence={**base, "reason": problem, "saved_card": hist.previous.card if hist.previous else None,
                      "saved": hist.previous.meta if hist.previous else None},
            **data)
    path, created = store.save(policy.policy_kid, url, card, now=now,
                               status="bootstrap" if bootstrap else "signature-only")
    data["stored"] = {"path": str(path), "new": created}
    text = [f"card: {escape_untrusted(url)}",
            f"signature  valid (policy key {policy.policy_kid})",
            f"validity   {_iso(card['issued_at'])} .. {_iso(card['expires'])}",
            f"currency   {data['currency']}"]
    text += [f"checked    {x}" for x in CARD_CHECKED]
    text += [f"unproven   {x}" for x in CARD_NOT_CHECKED]
    text += [f"witnesses  quorum {card['witness_policy']['quorum']} of {len(card['witness_policy']['witnesses'])}, "
             f"max age {card['max_checkpoint_age']}s ({vs_pinned} vs your pinned policy)",
             f"trust root {trust_root}",
             f"stored     {path} ({'new' if created else 'unchanged'})"]
    if hist.diff is None:
        text.append("changes    first card stored for this policy key")
    elif not hist.diff:
        text.append("changes    none since the stored card")
    else:
        text.append(f"changes    {len(hist.diff)} since the stored card:")
        for d in hist.diff[:50]:
            p = escape_untrusted(d["path"])
            if d["op"] == "changed":
                text.append(f"  ~ {p}: {json.dumps(d['old'])} -> {json.dumps(d['new'])}")
            elif d["op"] == "added":
                text.append(f"  + {p}: {json.dumps(d['new'])}")
            else:
                text.append(f"  - {p}: {json.dumps(d['old'])}")
    text.append("")
    text += cardmod.render_table(table)
    if vs_pinned == "stronger":
        text.append("note: the card's witness policy is stricter than your pinned one; re-pin to adopt it")
    if not bootstrap:
        raise AicsError(
            "incomplete: the card is signed by the pinned policy key, schema-valid and unexpired, but it is not the "
            "bootstrap card the trust bundle pins, and proving a later card current needs its policy leaf "
            f"({UNAVAILABLE_MESSAGE})", text_lines=text, **data)
    return _ok(data, text)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def cmd_status(args: Any, env: Env) -> Result:
    home = _home_dir(args, env)
    policy, pypi_status = _load_policy(home)
    trust_root = _trust_root(policy, pypi_status)
    store = CheckpointStore(home / "checkpoints")
    warnings: list[str] = []
    previous, _ = _head(store, policy, env, home, warnings, command="aics status")
    targets = [("origin", policy.checkpoint_url, policy.tiles_url)]
    if args.mirrors:
        if not policy.mirrors:
            warnings.append("no mirrors are pinned in the policy")
        targets += [(f"mirror {m}", join_url(m, "checkpoint"), m) for m in policy.mirrors]
    rows: list[dict[str, Any]] = []
    live: list[tuple[str, Cp, HttpTileReader | None]] = []
    evidence: list[dict[str, Any]] = []
    problems: list[str] = []
    for name, cp_url, tiles in targets:
        row: dict[str, Any] = {"name": name, "url": cp_url}
        try:
            fetched = fetch_checkpoint(env.fetcher, cp_url)
        except (FetchError, AicsError) as exc:
            row.update(status="unreachable", error=exc.message)
            rows.append(row)
            continue
        chk = check_note(fetched.note_text, policy, source=cp_url, now=env.now(), max_skew=args.max_skew)
        if not chk.ok or chk.cp is None:
            status = {"malformed": "malformed", "quorum": "stale"}.get(chk.reason or "", "invalid")
            row.update(status=status, error=chk.error, witnesses=chk.witnesses)
            # Only what the origin itself served, or a log-signed note no log
            # can produce, is evidence; a mirror's bad note may be the edge's.
            if status == "invalid" and (name == "origin" or chk.reason in SELF_CONTAINED_EVIDENCE):
                evidence.append(_failure(chk, policy, fetched.note_text, cp_url).evidence)
                row["evidence"] = True
                problems.append(f"{name} served an invalid checkpoint")
            rows.append(row)
            continue
        store.save(chk.cp, now=env.now(), role="observed", policy=policy)
        row.update(status="ok", size=chk.cp.size, root=chk.cp.root_b64, sha256=chk.cp.sha256,
                   fresh_cosignatures=chk.counted, freshness=chk.freshness)
        rows.append(row)
        live.append((name, chk.cp, HttpTileReader(tiles, env.fetcher) if tiles else None))
    endpoint = _endpoint(policy, env)
    comparisons = [(live[i][0], live[i][1], live[j][0], live[j][1])
                   for i in range(len(live)) for j in range(i + 1, len(live))]
    origin_live = next((c for n, c, _ in live if n == "origin"), None)
    if previous is not None and origin_live is not None and previous.sha256 != origin_live.sha256:
        comparisons.append(("saved head", previous, "origin", origin_live))
    pairs: list[dict[str, Any]] = []
    for na, ca, nb, cb in comparisons:
        big = cb if cb.size >= ca.size else ca
        # A saved head larger than what the origin serves is compared against
        # tiles authenticated by the saved head's own root (any live reader).
        older_origin = na == "saved head" and big is ca
        srcs: list[Any] = []
        for _n, c, reader in sorted(live, key=lambda t: (t[1] is not big, -t[1].size)):
            if reader is not None and (c.size >= big.size or older_origin):
                srcs.append(TileSource(f"tiles {reader.base_url} (reference size {c.size})", reader, ref=c))
        rel = _relate_current(ca, cb, srcs + endpoint) if na == "saved head" else relate(ca, cb, srcs + endpoint)
        pairs.append({"a": na, "b": nb, "a_size": ca.size, "b_size": cb.size, "status": rel.status,
                      "detail": rel.report()})
        if rel.status == "split-proven":
            evidence.append(split_bundle(policy, rel, now=env.now(), context=f"aics status: {na} vs {nb}"))
            problems.append(f"{na} ~ {nb}: split-proven")
    not_provable = [p for p in pairs if p["status"] != "consistent"]
    data: dict[str, Any] = {
        "sources": rows,
        "pairs": pairs,
        "not_provable": [{"a": p["a"], "b": p["b"], "status": p["status"]} for p in not_provable],
        "saved": {"count": store.count(policy.origin), "head_size": previous.size if previous else None},
        "trust_root": trust_root,
        "warnings": warnings,
    }
    text = [f"{'SOURCE':<40} {'STATUS':<12} {'SIZE':>10}  ROOT"]
    for r in rows:
        text.append(f"{r['name'][:40]:<40} {r['status']:<12} {str(r.get('size', '-')):>10}  "
                    f"{r.get('root', r.get('error', ''))}")
    for p in pairs:
        mark = "ok" if p["status"] == "consistent" else p["status"].upper()
        text.append(f"pair {p['a']} ({p['a_size']}) ~ {p['b']} ({p['b_size']}): {mark}")
    text.append(f"trust root: {trust_root}")
    text += [f"warning: {w}" for w in warnings]
    if evidence:
        raise VerificationFailed("; ".join(problems), evidence={"type": "aics-status-evidence/v1", "items": evidence},
                                 **data)
    gaps = [f"{r['name']} {r['status']}" for r in rows if r["status"] != "ok"]
    gaps += [f"{p['a']} ~ {p['b']}: consistency unproven" for p in pairs if p["status"] == "unproven"]
    gaps += [f"{p['a']} ~ {p['b']}: historical (the origin serves an older head than the saved one; not adopted)"
             for p in pairs if p["status"] == "historical"]
    if gaps:
        raise AicsError("status incomplete: " + "; ".join(gaps), **data)
    return _ok(data, text)


# ---------------------------------------------------------------------------
# verify message (AICS-1 §14.3)
# ---------------------------------------------------------------------------


def _read_input(path: str, env: Env) -> bytes:
    if path == "-":
        stream = env.stdin if env.stdin is not None else sys.stdin.buffer
        data = stream.read(msgmod.INPUT_MAX_BYTES + 1)
        return data.encode("utf-8") if isinstance(data, str) else data
    try:
        with Path(path).expanduser().open("rb") as f:
            return f.read(msgmod.INPUT_MAX_BYTES + 1)
    except OSError as exc:
        raise AicsError(f"cannot read {path}: {exc}") from None


def _prefix_reader(args: Any, policy: Policy, env: Env) -> tuple[Any, str] | None:
    """Where the entry prefix comes from when the input carries none: --tiles (a directory, or a URL online),
    else the pinned tile prefix unless --offline."""
    from aics_tlog import FileSystemTileReader

    if args.tiles:
        if args.tiles.startswith(("https://", "http://")):
            if args.offline:
                raise UsageError("--offline reads nothing from the network: give --tiles a local directory")
            return HttpTileReader(args.tiles, env.fetcher), f"the tiles at {args.tiles}"
        root = Path(args.tiles).expanduser()
        if not root.is_dir():
            raise UsageError(f"--tiles {args.tiles}: not a directory")
        return FileSystemTileReader(root), f"the tile directory {root}"
    if args.offline or not policy.tiles_url:
        return None
    return HttpTileReader(policy.tiles_url, env.fetcher), f"the pinned tiles at {policy.tiles_url}"


def cmd_verify_message(args: Any, env: Env) -> Result:
    if not args.bundle:
        raise UsageError("verify message needs --bundle FILE: an AICS-1 §14.3 wire bundle (GET /v2/entries/<index> "
                         "serves one) or a verification package; '-' reads it from stdin")
    home = _home_dir(args, env)
    policy, pypi_status = _load_policy(home)
    if not policy.policy_kid or not policy.owner_kid:
        raise PolicyError("the history check needs the pinned policy and owner keys (the trust bundle's policy_kid "
                          "and owner_kid): pin them with aics policy init")
    try:
        inp = msgmod.parse_input(_read_input(args.bundle, env), policy)
    except msgmod.InputProblem as exc:
        raise AicsError(str(exc), result="invalid-input") from None
    reader = None if inp.prefix is not None else _prefix_reader(args, policy, env)

    def prefix_source(size: int) -> tuple[list[bytes] | None, str]:
        if reader is None:
            return None, ("no entry prefix: the input is a bare bundle, so give a §14.3 package, --tiles DIR, or run "
                          "without --offline to read the pinned tiles")
        tiles, label = reader
        try:
            return msgmod.read_prefix(tiles, size), f"the entry bundles of {label}"
        except (ValueError, TileSourceError, OSError) as exc:
            return None, f"the entry prefix of size {size} could not be read from {label}: {exc}"

    larger_head = None
    if not args.offline:
        readers: dict[str, HttpTileReader] = {}

        def larger_head(bundle_cp: Cp, saved_cp: Cp) -> tuple[str, str]:
            rel = relate(bundle_cp, saved_cp, _proof_sources(policy, env, None, readers))
            detail = {"consistent": "a consistency proof from the tiles verifies",
                      "split-proven": "the tiles prove the two log-signed checkpoints inconsistent"}.get(
                rel.status, "no consistency proof could be obtained from the tiles")
            return rel.status, detail

    store = CheckpointStore(home / "checkpoints")
    saved = [(n.text, f"saved checkpoint {n.file}") for n in store.notes(policy.origin)]
    outcome = msgmod.verify(inp, policy, now=env.now(), prefix_source=prefix_source, saved=saved,
                            larger_head=larger_head)
    data = {**outcome.data, "offline": bool(args.offline), "trust_root": _trust_root(policy, pypi_status)}
    if outcome.input_problem:
        raise AicsError(outcome.message, text_lines=outcome.text, **data)
    if outcome.evidence is not None:
        raise VerificationFailed(outcome.message, evidence=outcome.evidence, **data)
    if outcome.result != "valid":
        raise AicsError(outcome.message, text_lines=outcome.text, **data)
    return _ok(data, outcome.text)


# ---------------------------------------------------------------------------
# not yet available
# ---------------------------------------------------------------------------

UNAVAILABLE_DETAIL: dict[str, str] = {}


def cmd_unavailable(args: Any, env: Env) -> Result:
    data: dict[str, Any] = {"ok": False, "available": False, "error": UNAVAILABLE_MESSAGE}
    detail = UNAVAILABLE_DETAIL.get(getattr(args, "cmd_name", ""))
    if detail:
        data["detail"] = detail
    return Result(EXIT_UNAVAILABLE, data, [UNAVAILABLE_MESSAGE])
