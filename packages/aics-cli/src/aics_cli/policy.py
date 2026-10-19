"""The pinned policy (``~/.aics/policy.toml``).

Every proof the CLI checks reduces to what is pinned here:

* from the out-of-band trust bundle (docs/spec/AICS-1.md §6.4): the log
  origin and checkpoint key, the policy key that signs the assurance card,
  the owner key and the bootstrap card hash;
* from the bootstrap card (whose hash the bundle pins) or typed in by hand:
  the witness keys, quorum and ``max_checkpoint_age`` (§6.3), and the tile
  prefixes and API base.

Keys never come from the API host being verified.  The file records the
source of every value; a key whose only source is the API host is refused
when the policy is written and again whenever it is loaded.

``[witness_meta]`` keeps what the card *declares* about each witness
(``declared_trust_domain``, ``declared_independent``: the operator's own
claims) apart from what the user asserted (``independent = true`` with
``independent_source = "manual"``, from ``policy init --independent``).
Only the user's assertion counts as independence (AICS-1 §6.3).
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aics_identity import keys as idkeys
from aics_tlog import VKey, format_vkey, parse_vkey

from . import home as _home
from .encoding import b64d_lenient
from .errors import PolicyError

POLICY_VERSION = 1
TYPE_ED25519 = 0x01
TYPE_COSIGNATURE = 0x04
MIN_CHECKPOINT_AGE = 60  # AICS-1 §13.1: max_checkpoint_age MUST be at least 60 seconds

TRUST_FIELDS = ("origin", "log_vkey", "policy_kid", "owner_kid", "bootstrap_card_hash")
WITNESS_FIELDS = ("witness_vkeys", "quorum", "max_checkpoint_age")
URL_FIELDS = ("checkpoint_url", "tiles_url", "card_url", "consistency_url", "mirrors")
INT_FIELDS = {"quorum", "max_checkpoint_age"}
_HEX64 = re.compile(r"[0-9a-f]{64}")


def is_out_of_band(source: str) -> bool:
    return not source.startswith("api:")


def check_origin_name(name: str) -> str:
    """A signed-note key name / log origin (c2sp.org/signed-note): non-empty,
    at most 255 UTF-8 bytes, no Unicode spaces, no '+', no control characters."""
    if not isinstance(name, str) or not name:
        raise PolicyError("origin must be a non-empty string")
    if len(name.encode("utf-8")) > 255:
        raise PolicyError("origin is longer than 255 bytes")
    if any(ord(c) < 0x20 or c.isspace() or c == "+" for c in name):
        raise PolicyError("origin contains spaces, control characters or '+'")
    return name


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyKey:
    """The policy key (signs the assurance card).  Pinned as a ``did:key``
    (``policy_kid``, AICS-1 §3.1); a signed-note vkey or raw base64 is also
    accepted when typed in by hand."""

    text: str
    public_key: bytes
    kids: frozenset[str]  # identifiers accepted as the JWS ``kid``

    @property
    def did(self) -> str:
        return idkeys.did_key(idkeys.public_key_from_bytes(self.public_key))


def parse_policy_key(text: str) -> PolicyKey:
    t = text.strip()
    names: set[str] = set()
    if t.startswith("did:key:"):
        try:
            pub = idkeys.public_key_bytes(idkeys.parse_did_key(t))
        except ValueError as exc:
            raise PolicyError(f"bad policy key {t!r}: {exc}") from None
        names.add(t)
    else:
        raw_text = t[len("ed25519:"):] if t.startswith("ed25519:") else None
        vk_error: str | None = None
        pub = b""
        if raw_text is None and "+" in t:
            try:
                vk = parse_vkey(t)
            except ValueError as exc:
                vk_error = str(exc)  # maybe raw base64 that contains '+'
            else:
                if vk.key_type != TYPE_ED25519 or len(vk.public_key) != 32:
                    raise PolicyError(f"policy vkey {t!r} is not an Ed25519 (0x01) key")
                pub = vk.public_key
                t = format_vkey(vk)
                names |= {t, vk.name, f"{vk.name}+{vk.key_id.hex()}"}
        if not pub:
            try:
                pub = b64d_lenient(raw_text if raw_text is not None else t)
            except ValueError as exc:
                raise PolicyError(f"bad policy key {t!r}: {vk_error or exc}") from None
            if len(pub) != 32:
                raise PolicyError(f"bad policy key {t!r}: {vk_error or 'not 32 bytes'}")
            names.add(t)
    try:
        pk = idkeys.public_key_from_bytes(pub)
    except ValueError as exc:
        raise PolicyError(f"bad policy key {t!r}: {exc}") from None
    names |= {idkeys.did_key(pk), idkeys.key_id(pk)}
    return PolicyKey(text=t, public_key=pub, kids=frozenset(names))


def parse_log_vkey(text: str) -> VKey:
    try:
        vk = parse_vkey(text.strip())
    except ValueError as exc:
        raise PolicyError(f"bad log vkey {text!r}: {exc}") from None
    if vk.key_type != TYPE_ED25519 or len(vk.public_key) != 32:
        raise PolicyError("the log vkey must be an Ed25519 signed-note key (type 0x01)")
    return vk


def parse_witness_vkey(text: str) -> VKey:
    try:
        vk = parse_vkey(text.strip())
    except ValueError as exc:
        raise PolicyError(f"bad witness vkey {text!r}: {exc}") from None
    if vk.key_type != TYPE_COSIGNATURE or len(vk.public_key) != 32:
        raise PolicyError(
            f"witness vkey {vk.name!r} must be an Ed25519 cosignature key (type 0x04, c2sp.org/tlog-cosignature)"
        )
    return vk


def _norm_value(fieldname: str, value: Any) -> Any:
    """Canonical form for comparing a field across sources."""
    if value is None:
        return None
    if fieldname == "log_vkey":
        return format_vkey(parse_log_vkey(str(value)))
    if fieldname in ("policy_kid", "owner_kid"):
        return parse_policy_key(str(value)).public_key.hex()
    if fieldname == "witness_vkeys":
        return frozenset(format_vkey(parse_witness_vkey(v)) for v in value)
    if fieldname in INT_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyError(f"{fieldname} must be an integer")
        return value
    if fieldname == "bootstrap_card_hash":
        v = str(value).strip()
        if not _HEX64.fullmatch(v):
            raise PolicyError("bootstrap_card_hash must be 64 lowercase hex characters")
        return v
    return str(value).strip()


# ---------------------------------------------------------------------------
# the policy
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    origin: str
    log_vkey: str
    policy_kid: str | None = None
    owner_kid: str | None = None
    bootstrap_card_hash: str | None = None
    trust_bundle_sha256: str | None = None
    witness_vkeys: list[str] = field(default_factory=list)
    quorum: int = 0
    max_checkpoint_age: int | None = None
    witness_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    domain: str | None = None
    checkpoint_url: str = ""
    tiles_url: str = ""
    card_url: str = ""
    consistency_url: str = ""
    mirrors: list[str] = field(default_factory=list)
    sources: dict[str, list[str]] = field(default_factory=dict)
    created_at: str = ""
    path: Path | None = None

    # -- parsed views ----------------------------------------------------

    def log_key(self) -> VKey:
        return parse_log_vkey(self.log_vkey)

    def witness_keys(self) -> list[VKey]:
        return [parse_witness_vkey(w) for w in self.witness_vkeys]

    def policy_keys(self) -> list[PolicyKey]:
        return [parse_policy_key(self.policy_kid)] if self.policy_kid else []

    def validate(self) -> None:
        from .errors import FetchError
        from .net import check_url

        check_origin_name(self.origin)
        log = self.log_key()
        keys = {log.public_key: "log"}
        for name in ("policy_kid", "owner_kid"):
            v = getattr(self, name)
            if v:
                pub = parse_policy_key(v).public_key
                if pub in keys:
                    raise PolicyError("log, policy and owner keys must be distinct (AICS-1 §3.1)")
                keys[pub] = name.split("_")[0]
        if self.bootstrap_card_hash is not None:
            _norm_value("bootstrap_card_hash", self.bootstrap_card_hash)
        witnesses = self.witness_keys()
        if len({w.name for w in witnesses}) != len(witnesses):
            raise PolicyError("a witness name is listed twice")
        if len({w.public_key for w in witnesses}) != len(witnesses):
            raise PolicyError("a witness public key is listed twice (names and keys must be unique)")
        for w in witnesses:
            if w.public_key in keys:
                raise PolicyError(
                    f"witness {w.name!r} uses the {keys[w.public_key]} key: the log, policy and owner keys cannot "
                    "act as witnesses, or the log alone could meet the quorum (AICS-1 §3.1, §6.3)"
                )
        if isinstance(self.quorum, bool) or not isinstance(self.quorum, int) or self.quorum < 0:
            raise PolicyError("quorum must be a non-negative integer")
        if self.quorum > len(witnesses):
            raise PolicyError(f"quorum {self.quorum} exceeds the {len(witnesses)} witnesses")
        if self.max_checkpoint_age is not None and (
            isinstance(self.max_checkpoint_age, bool)
            or not isinstance(self.max_checkpoint_age, int)
            or self.max_checkpoint_age < MIN_CHECKPOINT_AGE
        ):
            raise PolicyError(f"max_checkpoint_age must be at least {MIN_CHECKPOINT_AGE} seconds")
        if self.quorum > 0 and self.max_checkpoint_age is None:
            raise PolicyError("a positive witness quorum needs max_checkpoint_age (AICS-1 §6.3)")
        urls = [self.checkpoint_url, self.tiles_url, self.card_url, *self.mirrors,
                self.consistency_url.replace("{old}", "0").replace("{new}", "1")]
        for u in urls:
            if u:
                try:
                    check_url(u)
                except FetchError as exc:
                    raise PolicyError(f"bad URL in policy: {exc.message}") from None
        for name in ("log_vkey", "origin", "policy_kid", "witness_vkeys"):
            srcs = self.sources.get(name)
            if srcs and not any(is_out_of_band(s) for s in srcs):
                raise PolicyError(
                    f"refusing the pinned {name}: its only source is the API host ({', '.join(srcs)}); "
                    "pin it from DNS, the PyPI package or the README"
                )

    def key_sources(self, name: str) -> list[str]:
        return list(self.sources.get(name) or ["manual"])

    def summary(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else None,
            "domain": self.domain,
            "origin": self.origin,
            "log_vkey": self.log_vkey,
            "policy_kid": self.policy_kid,
            "owner_kid": self.owner_kid,
            "bootstrap_card_hash": self.bootstrap_card_hash,
            "trust_bundle_sha256": self.trust_bundle_sha256,
            "witness_vkeys": list(self.witness_vkeys),
            "quorum": self.quorum,
            "max_checkpoint_age": self.max_checkpoint_age,
            "witness_meta": {k: dict(v) for k, v in self.witness_meta.items()},
            "checkpoint_url": self.checkpoint_url,
            "tiles_url": self.tiles_url,
            "card_url": self.card_url,
            "consistency_url": self.consistency_url,
            "mirrors": list(self.mirrors),
            "sources": {k: list(v) for k, v in self.sources.items()},
            "created_at": self.created_at,
        }

    def trust_values(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in TRUST_FIELDS}

    def witness_name(self, vkey: str) -> str:
        return parse_witness_vkey(vkey).name

    def declared(self, name: str) -> tuple[str | None, bool | None]:
        """(trust_domain, independent) as the operator's card declares them."""
        return declared_meta(self.witness_meta.get(name) or {})

    def assessed_independent(self, name: str) -> bool:
        """Did the user mark this witness independent (policy init --independent)?"""
        return assessed_independent(self.witness_meta.get(name) or {})


def declared_meta(meta: dict[str, Any]) -> tuple[str | None, bool | None]:
    """The card's declarations in a ``[witness_meta]`` entry.  Older policy
    files stored them as ``trust_domain`` / ``independent``."""
    td = meta.get("declared_trust_domain", meta.get("trust_domain"))
    ind = meta.get("declared_independent")
    if ind is None and meta.get("independent_source") is None:
        ind = meta.get("independent")
    return (str(td) if td is not None else None), (ind if isinstance(ind, bool) else None)


def assessed_independent(meta: dict[str, Any]) -> bool:
    return meta.get("independent") is True and meta.get("independent_source") == "manual"


def policy_digest(policy: Policy) -> str:
    """SHA-256 of the policy file text (what each saved checkpoint records)."""
    return hashlib.sha256(dumps(policy).encode("utf-8")).hexdigest()


def archived_log_keys(home: Path) -> dict[str, tuple[str, str]]:
    """``policy_sha256 -> (origin, log_vkey)`` for the current policy file and
    every archived one in ``policy-history/``, keyed both by the digest of the
    file bytes and by the digest of its re-serialised form.  Lets a note saved
    under an earlier policy be re-verified with the log key it was saved
    under."""
    out: dict[str, tuple[str, str]] = {}
    files = [policy_path(home)]
    hist = home / "policy-history"
    if hist.is_dir():
        files += sorted(hist.glob("*.toml"))
    for f in files:
        try:
            raw = f.read_bytes()
            data = tomllib.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            continue
        origin, vkey = data.get("origin"), data.get("log_vkey")
        if not isinstance(origin, str) or not isinstance(vkey, str):
            continue
        out.setdefault(hashlib.sha256(raw).hexdigest(), (origin, vkey.strip()))
        try:
            out.setdefault(policy_digest(loads(raw.decode("utf-8"))), (origin, vkey.strip()))
        except PolicyError:
            pass
    return out


def prefix_urls(prefix: str, api_base: str | None) -> dict[str, Any]:
    """URLs for a C2SP tlog-tiles prefix and the AICS API base (§6.1, §12.1)."""
    p = prefix if prefix.endswith("/") else prefix + "/"
    out: dict[str, Any] = {"checkpoint_url": p + "checkpoint", "tiles_url": p}
    if api_base:
        out["consistency_url"] = api_base.rstrip("/") + "/v2/tlog/consistency?from={old}&to={new}"
    return out


def _origin_host(origin: str | None) -> str | None:
    if not origin or " " in origin:
        return None
    host = origin.split("/", 1)[0]
    return host if "." in host else None


def default_urls(domain: str | None, origin: str | None) -> dict[str, Any]:
    """URLs implied when no card is available: the log's tile prefix is
    ``https://<origin>/`` when the origin looks like ``host/path`` (AICS-1
    §12.2 recommends the origin ``api.<domain>/tiles``); the card is at
    ``https://<domain>/.well-known/aics-card.json``.  Without a domain the
    card host is derived from the origin host (``api.<domain>`` gives
    ``<domain>``, §12.2); the bootstrap card hash authenticates whatever is
    fetched there."""
    out: dict[str, Any] = {"checkpoint_url": "", "tiles_url": "", "card_url": "", "consistency_url": "",
                           "mirrors": []}
    host = _origin_host(origin)
    if host:
        out.update(prefix_urls(f"https://{origin}/", f"https://{host}"))
    elif domain:
        out.update(prefix_urls(f"https://api.{domain}/tiles/", f"https://api.{domain}"))
    if domain:
        out["card_url"] = f"https://{domain}/.well-known/aics-card.json"
    elif host:
        card_host = host[len("api."):] if host.startswith("api.") and host.count(".") >= 2 else host
        out["card_url"] = f"https://{card_host}/.well-known/aics-card.json"
    return out


# ---------------------------------------------------------------------------
# TOML I/O (tomllib reads; the writer handles this schema only)
# ---------------------------------------------------------------------------


def _toml_str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _toml_str(v)
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_toml_str(k)} = {_toml_value(x)}" for k, x in v.items()) + " }"
    if isinstance(v, (list, tuple)):
        if not v:
            return "[]"
        return "[\n" + "".join(f"    {_toml_value(x)},\n" for x in v) + "]"
    raise TypeError(f"cannot write {type(v).__name__} to TOML")


def dumps(policy: Policy) -> str:
    lines = [
        "# aics pinned policy.  Trust anchors come from the out-of-band trust bundle",
        "# (DNS TXT _aics.<domain>, the aics-cli package on PyPI, the public README); the",
        "# witness policy from the bootstrap card the bundle pins, or by hand.  Never",
        "# from the API host alone.  [sources] records where each value came from.",
        f"version = {POLICY_VERSION}",
    ]
    if policy.domain:
        lines.append(f"domain = {_toml_str(policy.domain)}")
    lines += [f"origin = {_toml_str(policy.origin)}", f"log_vkey = {_toml_str(policy.log_vkey)}"]
    for name in ("policy_kid", "owner_kid", "bootstrap_card_hash", "trust_bundle_sha256"):
        v = getattr(policy, name)
        if v:
            lines.append(f"{name} = {_toml_str(v)}")
    lines += [f"witness_vkeys = {_toml_value(policy.witness_vkeys)}", f"quorum = {policy.quorum}"]
    if policy.max_checkpoint_age is not None:
        lines.append(f"max_checkpoint_age = {policy.max_checkpoint_age}")
    lines += [
        f"checkpoint_url = {_toml_str(policy.checkpoint_url)}",
        f"tiles_url = {_toml_str(policy.tiles_url)}",
        f"card_url = {_toml_str(policy.card_url)}",
        f"consistency_url = {_toml_str(policy.consistency_url)}",
        f"mirrors = {_toml_value(policy.mirrors)}",
        f"created_at = {_toml_str(policy.created_at)}",
        "",
        "[witness_meta]",
    ]
    for name in sorted(policy.witness_meta):
        lines.append(f"{_toml_str(name)} = {_toml_value(policy.witness_meta[name])}")
    lines += ["", "[sources]"]
    for k in sorted(policy.sources):
        lines.append(f"{k} = {_toml_value(list(policy.sources[k]))}")
    return "\n".join(lines) + "\n"


def loads(text: str, path: Path | None = None) -> Policy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy file is not valid TOML: {exc}") from None
    version = data.get("version", POLICY_VERSION)
    if version != POLICY_VERSION:
        raise PolicyError(f"unsupported policy version {version!r}")

    def get(name: str, typ: type, default: Any) -> Any:
        v = data.get(name, default)
        if v is None:
            return default
        if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
            raise PolicyError(f"policy field {name!r} has the wrong type")
        return v

    def get_list(name: str) -> list[str]:
        v = data.get(name, [])
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise PolicyError(f"policy field {name!r} must be a list of strings")
        return [x.strip() for x in v if x.strip()]

    if "origin" not in data or "log_vkey" not in data:
        raise PolicyError("policy file needs 'origin' and 'log_vkey'")
    policy_kid = get("policy_kid", str, None)
    if policy_kid is None:  # older spelling
        legacy = get_list("policy_vkeys") or get_list("policy_vkey")
        policy_kid = legacy[0] if legacy else None
    sources_raw = data.get("sources", {})
    if not isinstance(sources_raw, dict):
        raise PolicyError("[sources] must be a table")
    sources: dict[str, list[str]] = {}
    for k, v in sources_raw.items():
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise PolicyError(f"sources.{k} must be a list of strings")
        sources[k] = v
    meta_raw = data.get("witness_meta", {})
    if not isinstance(meta_raw, dict) or not all(isinstance(v, dict) for v in meta_raw.values()):
        raise PolicyError("[witness_meta] must map witness names to tables")
    pol = Policy(
        origin=get("origin", str, ""),
        log_vkey=get("log_vkey", str, "").strip(),
        policy_kid=policy_kid,
        owner_kid=get("owner_kid", str, None),
        bootstrap_card_hash=get("bootstrap_card_hash", str, None),
        trust_bundle_sha256=get("trust_bundle_sha256", str, None),
        witness_vkeys=get_list("witness_vkeys"),
        quorum=get("quorum", int, 0),
        max_checkpoint_age=get("max_checkpoint_age", int, None),
        witness_meta={k: dict(v) for k, v in meta_raw.items()},
        domain=get("domain", str, None),
        checkpoint_url=get("checkpoint_url", str, ""),
        tiles_url=get("tiles_url", str, ""),
        card_url=get("card_url", str, ""),
        consistency_url=get("consistency_url", str, ""),
        mirrors=get_list("mirrors"),
        sources=sources,
        created_at=get("created_at", str, ""),
        path=path,
    )
    pol.validate()
    return pol


def policy_path(home: Path) -> Path:
    return home / _home.POLICY


def load(home: Path) -> Policy:
    path = policy_path(home)
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        raise PolicyError(
            f"no pinned policy at {path}; run: aics policy init --from-dns <domain>"
        ) from None
    return loads(text, path)


def save(policy: Policy, home: Path, *, force: bool = False) -> Path:
    """Write the policy; an existing file is only replaced with ``force``,
    and then archived under ``policy-history/`` first (never lost)."""
    policy.validate()
    text = dumps(policy)
    loads(text)  # round-trip check: what we write is what we will read
    _home.ensure_dir(home)
    path = policy_path(home)
    if path.exists():
        if not force:
            raise PolicyError(f"{path} exists; pass --force to replace it (the old one is archived)")
        hist = _home.ensure_dir(home / "policy-history")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        _home.write_new(hist / f"policy-{stamp}-{os.getpid()}-{time.monotonic_ns()}.toml", path.read_bytes())
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    tmp.write_text(text, "utf-8")
    os.replace(tmp, path)
    policy.path = path
    return path


# ---------------------------------------------------------------------------
# comparing sources
# ---------------------------------------------------------------------------


@dataclass
class SourceValues:
    label: str  # "dns:_aics.example", "pypi:aics-cli==0.1.0", "readme", "manual", "api:https://..."
    values: dict[str, Any]


def compare_sources(sources: list[SourceValues], fields: tuple[str, ...] = TRUST_FIELDS) -> list[dict[str, Any]]:
    """Per field: the value each source gives and whether they agree.
    ``None`` (not published by that source) is not a disagreement; malformed
    values are listed under ``errors``."""
    rows: list[dict[str, Any]] = []
    for f in fields:
        given: dict[str, Any] = {}
        normed: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for src in sources:
            v = src.values.get(f)
            if v is None:
                continue  # not published by this source
            given[src.label] = v
            try:
                normed[src.label] = _norm_value(f, v)
            except PolicyError as exc:
                errors[src.label] = exc.message
        distinct = {repr(sorted(v) if isinstance(v, frozenset) else v) for v in normed.values()}
        rows.append({"field": f, "values": given, "agree": len(distinct) <= 1, "errors": errors})
    return rows


def malformed(rows: list[dict[str, Any]], labels: set[str] | None = None) -> list[str]:
    """Messages for malformed values in ``rows`` (optionally only from ``labels``)."""
    out = []
    for r in rows:
        for label, msg in r["errors"].items():
            if labels is None or label in labels:
                out.append(f"{label}: {r['field']}: {msg}")
    return out
