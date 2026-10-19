"""The out-of-band trust bundle (docs/spec/AICS-1.md §6.4).

The instance publishes the same bundle in three places: DNS TXT
``_aics.<domain>``, the ``AICS_TRUST_BUNDLE`` constant in the ``aics`` package
on PyPI (:mod:`aics_cli.published_keys`), and a labelled block in the public
README.  The bundle is the JCS JSON object::

    {"v": 1, "origin": ..., "log_vkey": ..., "policy_kid": ...,
     "owner_kid": ..., "bootstrap_card_hash": ...}

DNS carries one TXT RR ``aics1=<U64(J(bundle))>`` (character-strings are
concatenated first).  Two different bundles at one name are an error, and so
is any disagreement between sources: bootstrap stops, there is no majority
vote.  The API host and the card's own keys are never a source.

For compatibility with ops/dns-records.md, a TXT record
``aics-log-vkey <vkey>`` is read as a partial source that gives only the log
key.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aics_identity import keys as idkeys
from aics_identity.canonical import canonicalize

from .encoding import b64u_d, b64u_e
from .errors import PolicyError

BUNDLE_FIELDS = ("v", "origin", "log_vkey", "policy_kid", "owner_kid", "bootstrap_card_hash")
TRUST_FIELDS = BUNDLE_FIELDS[1:]  # the values a policy pins
TXT_PREFIX = "aics1="
LEGACY_TXT_PREFIX = "aics-log-vkey"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TXT_VALUE = re.compile(r"aics1=([A-Za-z0-9_-]+)")
#: The README block's digest line, ``sha256: <hexH(J(bundle))>`` (AICS-1 §6.4).
_DIGEST_LINE = re.compile(r"^[ \t]*sha256:(.*)$", re.M)


@dataclass(frozen=True)
class TrustBundle:
    origin: str
    log_vkey: str
    policy_kid: str
    owner_kid: str
    bootstrap_card_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"v": 1, "origin": self.origin, "log_vkey": self.log_vkey, "policy_kid": self.policy_kid,
                "owner_kid": self.owner_kid, "bootstrap_card_hash": self.bootstrap_card_hash}

    @property
    def jcs(self) -> bytes:
        return canonicalize(self.to_dict())

    @property
    def sha256(self) -> str:
        """``hexH(J(bundle))``: the digest README and PyPI carry next to the bytes."""
        return hashlib.sha256(self.jcs).hexdigest()

    @property
    def txt(self) -> str:
        return TXT_PREFIX + b64u_e(self.jcs)

    def values(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in TRUST_FIELDS}


def _check_origin(origin: Any) -> str:
    from .policy import check_origin_name

    if not isinstance(origin, str) or not origin or not origin.isascii():
        raise PolicyError("bundle origin must be non-empty ASCII")
    if "://" in origin or origin.endswith("/"):
        raise PolicyError("bundle origin must have no scheme and no trailing slash")
    return check_origin_name(origin)


def _check_kid(kid: Any, what: str) -> bytes:
    if not isinstance(kid, str) or not kid.startswith("did:key:z"):
        raise PolicyError(f"bundle {what} must be an Ed25519 did:key")
    try:
        return idkeys.public_key_bytes(idkeys.parse_did_key(kid))
    except ValueError as exc:
        raise PolicyError(f"bundle {what}: {exc}") from None


def bundle_from_object(obj: Any) -> TrustBundle:
    from .policy import parse_log_vkey

    if not isinstance(obj, dict):
        raise PolicyError("trust bundle must be a JSON object")
    if set(obj) != set(BUNDLE_FIELDS):
        missing = sorted(set(BUNDLE_FIELDS) - set(obj))
        extra = sorted(set(obj) - set(BUNDLE_FIELDS))
        raise PolicyError(f"trust bundle must have exactly {', '.join(BUNDLE_FIELDS)} "
                          f"(missing {missing}, unknown {extra})")
    if obj["v"] != 1 or isinstance(obj["v"], bool):
        raise PolicyError(f"unsupported trust bundle version {obj['v']!r}")
    origin = _check_origin(obj["origin"])
    if not isinstance(obj["log_vkey"], str):
        raise PolicyError("bundle log_vkey must be a string")
    log_vk = parse_log_vkey(obj["log_vkey"])
    policy_pub = _check_kid(obj["policy_kid"], "policy_kid")
    owner_pub = _check_kid(obj["owner_kid"], "owner_kid")
    if len({log_vk.public_key, policy_pub, owner_pub}) != 3:
        raise PolicyError("log, policy and owner keys must be distinct (AICS-1 §3.1)")
    h = obj["bootstrap_card_hash"]
    if not isinstance(h, str) or not _HEX64.fullmatch(h):
        raise PolicyError("bundle bootstrap_card_hash must be 64 lowercase hex characters")
    return TrustBundle(origin=origin, log_vkey=obj["log_vkey"], policy_kid=obj["policy_kid"],
                       owner_kid=obj["owner_kid"], bootstrap_card_hash=h)


def bundle_from_jcs(raw: bytes) -> TrustBundle:
    """Bundle bytes must be exactly the JCS serialization of the object."""
    from .card import loads_strict

    try:
        obj = loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PolicyError(f"trust bundle is not strict JSON: {exc}") from None
    bundle = bundle_from_object(obj)
    if bundle.jcs != raw:
        raise PolicyError("trust bundle bytes are not the JCS (RFC 8785) serialization of the object")
    return bundle


def bundle_from_text(text: str) -> TrustBundle:
    """``aics1=<U64>``, bare ``U64``, JSON text, or a file holding one of them
    (e.g. the README block saved to a file).

    The README block also carries the digest of the bundle bytes (AICS-1 §6.4:
    "README and PyPI carry the same bytes and their hexH digest"); a stated
    digest is checked exactly like the PyPI constant's
    (:func:`published_bundle`), and a block whose ``sha256:`` line contradicts
    its bytes, or cannot be read, is refused before anything is pinned."""
    t = text.strip()
    if t and "\n" not in t and len(t) < 4096 and not t.startswith(("{", TXT_PREFIX)):
        p = Path(t).expanduser()
        if p.is_file():
            return bundle_from_text(p.read_text("utf-8"))
    values = set(_TXT_VALUE.findall(t))
    if len(values) > 1:
        raise PolicyError(f"the text holds {len(values)} different aics1= trust bundles; give exactly one")
    if values:
        bundle = bundle_from_u64(values.pop())
        check_stated_digest(t, bundle)
        return bundle
    if t.startswith("{"):
        return bundle_from_jcs(t.encode("utf-8"))
    return bundle_from_u64(t)


def check_stated_digest(text: str, bundle: TrustBundle) -> None:
    """Refuse ``text`` (a README block) when its ``sha256:`` line is not
    ``hexH(J(bundle))``.  A bare ``aics1=`` value, the DNS form, states no
    digest and is not refused for that."""
    stated = {value.strip() for value in _DIGEST_LINE.findall(text)}
    if not stated:
        return
    if len(stated) > 1:
        raise PolicyError("the README block states more than one sha256 digest; nothing was pinned")
    digest = stated.pop()
    if not _HEX64.fullmatch(digest):
        raise PolicyError("the README block's sha256 line is not 64 lowercase hex characters; nothing was pinned")
    if digest != bundle.sha256:
        raise PolicyError("the README block's sha256 line does not match its own trust bundle bytes "
                          f"(stated {digest}, computed {bundle.sha256}; AICS-1 §6.4); nothing was pinned")


def bundle_from_u64(value: str) -> TrustBundle:
    try:
        raw = b64u_d(value.strip())
    except ValueError as exc:
        raise PolicyError(f"trust bundle is not base64url: {exc}") from None
    return bundle_from_jcs(raw)


@dataclass
class TxtBundle:
    bundle: TrustBundle | None = None
    legacy_log_vkey: str | None = None
    notes: list[str] = field(default_factory=list)


def parse_txt(records: list[str]) -> TxtBundle:
    """Read the TXT records at ``_aics.<domain>`` (each already concatenated)."""
    from .policy import parse_log_vkey
    from aics_tlog import format_vkey

    out = TxtBundle()
    bundles: dict[bytes, TrustBundle] = {}
    legacy: set[str] = set()
    for rec in records:
        r = rec.strip()
        if r.startswith(TXT_PREFIX):
            b = bundle_from_u64(r[len(TXT_PREFIX):])
            bundles[b.jcs] = b
        elif r.startswith(LEGACY_TXT_PREFIX + " ") or r.startswith(LEGACY_TXT_PREFIX + "="):
            v = r[len(LEGACY_TXT_PREFIX) + 1:].strip()
            legacy.add(format_vkey(parse_log_vkey(v)))
    if len(bundles) > 1:
        raise PolicyError(f"{len(bundles)} different aics1= trust bundles are published at one name")
    if len(legacy) > 1:
        raise PolicyError("different aics-log-vkey records are published at one name")
    if bundles:
        out.bundle = next(iter(bundles.values()))
    if legacy:
        out.legacy_log_vkey = next(iter(legacy))
        out.notes.append("aics-log-vkey record (ops/dns-records.md form): gives the log key only")
        if out.bundle is not None and out.bundle.log_vkey != out.legacy_log_vkey:
            raise PolicyError("the aics1= bundle and the aics-log-vkey record give different log keys")
    if out.bundle is None and out.legacy_log_vkey is None:
        raise PolicyError(f"no {TXT_PREFIX}<bundle> TXT record")
    return out


def published_bundle(domain: str | None, origin: str | None = None) -> tuple[TrustBundle | None, str]:
    """The bundle constant shipped in this package, and a status word.

    It applies, and must then agree, whenever the domain is the one it is
    published for *or* the log origin is its origin - a policy pinned from
    the README alone has no domain, but the same origin."""
    from . import published_keys as pk

    if pk.AICS_TRUST_BUNDLE is None:
        return None, "placeholder"
    raw = pk.AICS_TRUST_BUNDLE
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    bundle = bundle_from_jcs(raw_bytes)
    if pk.AICS_TRUST_BUNDLE_SHA256 and pk.AICS_TRUST_BUNDLE_SHA256 != bundle.sha256:
        raise PolicyError("this package's AICS_TRUST_BUNDLE does not match its own published digest")
    if (domain and domain == pk.AICS_TRUST_BUNDLE_DOMAIN) or (origin and origin == bundle.origin):
        return bundle, "published"
    if not domain and not origin:
        return None, f"not compared (no domain or origin given; it is published for {pk.AICS_TRUST_BUNDLE_DOMAIN})"
    return None, f"published for {pk.AICS_TRUST_BUNDLE_DOMAIN} ({bundle.origin}), not {domain or origin}"
