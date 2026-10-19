"""``aics-id`` - command line interface for aics_identity.

Subcommands: keygen, derive, sign-envelope, verify-envelope,
sign-request, verify-request.  Run ``aics-id --help`` for details.
Envelopes are AICS-1 section 4 envelopes and request signatures follow the
section 12.1 profile by default; kids and keyids are ``did:key`` DIDs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from . import envelope as _envelope
from . import http_signatures as _http
from . import keys as _keys

PROGRAM = "aics-id"


# ----------------------------------------------------------------------
# key file helpers (base64url raw seed, mode 0600)
# ----------------------------------------------------------------------

def save_private_key(path: str, key: Ed25519PrivateKey, *, force: bool = False) -> None:
    if os.path.exists(path) and not force:
        raise FileExistsError(f"refusing to overwrite existing key file {path!r} (use --force)")
    text = _keys.b64u_encode(_keys.private_seed(key)) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read().strip()
    return _keys.private_key_from_seed(_keys.b64u_decode(text))


def _print_identity(key: Ed25519PrivateKey, prefix: str = "") -> None:
    ident = _keys.agent_identity(key)
    for name in ("did", "kid", "key_id", "public_key"):
        print(f"{prefix}{name}: {ident[name]}")


def _read_json(path: str) -> Any:
    raw = sys.stdin.read() if path == "-" else open(path, "r", encoding="utf-8").read()
    return json.loads(raw)


def _key_resolver(key: Ed25519PrivateKey | None):
    """kid -> key: the given key for its own did:key only, or (no key) the kid decoded locally."""
    if key is None:
        return _keys.parse_did_key
    own = _keys.did_key(key.public_key())
    return lambda kid: key.public_key() if kid == own else None


# ----------------------------------------------------------------------
# shared argument helpers
# ----------------------------------------------------------------------

def _add_master_secret_args(sp: argparse.ArgumentParser) -> None:
    group = sp.add_mutually_exclusive_group(required=True)
    group.add_argument("--master-secret-hex", help="master secret as hex")
    group.add_argument("--master-secret-file", help="file containing the raw master secret bytes")
    group.add_argument("--master-secret-env", default=None, metavar="VAR", nargs="?",
                       const="AICS_MASTER_SECRET",
                       help="read hex master secret from environment variable VAR (default: AICS_MASTER_SECRET)")


def _get_master_secret(args: argparse.Namespace) -> bytes:
    if args.master_secret_hex:
        return bytes.fromhex(args.master_secret_hex)
    if args.master_secret_file:
        with open(args.master_secret_file, "rb") as fh:
            return fh.read()
    var = getattr(args, "master_secret_env", None) or "AICS_MASTER_SECRET"
    value = os.environ.get(var)
    if not value:
        raise ValueError(f"environment variable {var} is not set")
    return bytes.fromhex(value.strip())


def _parse_time_arg(text: str, *, relative_base: int) -> int:
    """Accept an absolute unix timestamp or ``+N`` seconds from now."""
    if text.startswith("+"):
        return relative_base + int(text[1:])
    return int(text)


def _split_header(text: str) -> tuple[str, str]:
    name, sep, value = text.partition(":")
    if not sep:
        raise ValueError(f"header must be 'Name: value', got {text!r}")
    return name.strip(), value.strip()


# ----------------------------------------------------------------------
# subcommands
# ----------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> int:
    key = _keys.generate_keypair()
    save_private_key(args.out, key, force=args.force)
    _print_identity(key)
    print(f"key_file: {args.out} (mode 0600)")
    return 0


def cmd_derive(args: argparse.Namespace) -> int:
    master = _get_master_secret(args)
    run_salt = bytes.fromhex(args.salt_hex) if args.salt_hex else None
    key = _keys.derive_agent_key(master, args.label, run_salt)
    _print_identity(key, prefix="agent_")
    if args.out:
        save_private_key(args.out, key, force=args.force)
        print(f"key_file: {args.out} (mode 0600)")
    print(f"derived_from: label={args.label!r} salt={args.salt_hex or '(none)'}")
    return 0


def cmd_sign_envelope(args: argparse.Namespace) -> int:
    key = load_private_key(args.key)
    payload = _read_json(args.payload)
    now = int(time.time())
    created = _parse_time_arg(args.created, relative_base=now) if args.created else now
    expires = _parse_time_arg(args.expires, relative_base=created) if args.expires else created + _envelope.DEFAULT_TTL_SECONDS
    if args.previous:
        if args.seq is not None or args.prev is not None:
            raise ValueError("give --previous or --seq/--prev, not both")
        chain = _envelope.next_chain(_read_json(args.previous))
    else:
        chain = {"seq": 0 if args.seq is None else args.seq, "prev": args.prev}
    seen = None
    if args.seen_note:
        with open(args.seen_note, "rb") as fh:
            seen = _envelope.seen_from_checkpoint(fh.read())
    env = _envelope.sign_envelope(payload, key, origin=args.origin, type=args.type, kid=args.kid,
                                  created=created, expires=expires, nonce=args.nonce, seen=seen, **chain)
    json.dump(env, sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


def cmd_verify_envelope(args: argparse.Namespace) -> int:
    env = _read_json(args.input)
    key = load_private_key(args.key) if args.key else None
    payload = _envelope.verify_envelope(
        env, _key_resolver(key), now=args.now, origin=args.origin, type=args.type, max_clock_skew=args.skew,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(f"verified: kid={env['protected']['kid']} nonce={env['protected']['nonce']} "
          f"origin={env['protected']['origin']} type={env['protected']['type']}", file=sys.stderr)
    if key is None:
        print("note: the kid was decoded locally; its key chain in the log was not checked", file=sys.stderr)
    return 0


def cmd_sign_request(args: argparse.Namespace) -> int:
    key = load_private_key(args.key)
    body = open(args.body, "rb").read() if args.body else b""
    headers = [_split_header(h) for h in (args.header or [])]
    envelope = _read_json(args.envelope) if args.envelope else None
    now = int(time.time())
    if envelope is not None:
        created, expires = None, _http.AUTO  # taken from the envelope
    else:
        created = _parse_time_arg(args.created, relative_base=now) if args.created else now
        expires = _parse_time_arg(args.expires, relative_base=created) if args.expires else _http.AUTO
    signed = _http.sign_request(
        args.method, args.url, headers, body,
        key=key, keyid=args.kid,
        nonce=args.nonce or _http.AUTO, tag=args.tag or None,
        created=created, expires=expires,
        components=args.component or None,
        label=args.label,
        envelope=envelope,
    )
    for name, value in signed.items():
        print(f"{name}: {value}")
    return 0


def cmd_verify_request(args: argparse.Namespace) -> int:
    key = load_private_key(args.key) if args.key else None
    body = open(args.body, "rb").read() if args.body else b""
    headers = [_split_header(h) for h in (args.header or [])]
    if args.headers_file:
        for line in open(args.headers_file, "r", encoding="utf-8"):
            line = line.rstrip("\n")
            if line.strip():
                headers.append(_split_header(line))
    envelope = _read_json(args.envelope) if args.envelope else None
    if args.aics:
        policy = dict(_http.AICS_VERIFY_POLICY)
    else:
        required = [c.strip() for c in (args.require or "").split(",") if c.strip()] or list(_http.DEFAULT_COMPONENTS)
        if body and "content-digest" not in required:
            required.append("content-digest")
        policy = dict(
            max_age=args.max_age if args.max_age >= 0 else None,
            require_expires=not args.allow_no_expires,
            require_nonce=args.require_nonce,
            require_tag=args.require_tag,
            require_content_digest_covered=args.require_digest,
            required_components=required,
        )
    verified = _http.verify_request(
        args.method, args.url, headers, body,
        resolve_key=_key_resolver(key),
        max_clock_skew=args.skew,
        envelope=envelope,
        now=args.now,
        **policy,
    )
    for sig in verified:
        print(f"verified: label={sig.label} keyid={sig.keyid} created={sig.created}"
              f" expires={sig.expires} nonce={sig.nonce} tag={sig.tag}")
        print(f"covered: {' '.join(sig.components)}", file=sys.stderr)
    return 0


# ----------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Ed25519 agent identity: keys, signed envelopes, RFC 9421 request signatures.",
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("keygen", help="generate an Ed25519 key pair; write the private key (0600)")
    p.add_argument("--out", default="aics-id.key", help="private key file path (default: %(default)s)")
    p.add_argument("--force", action="store_true", help="overwrite the key file if it exists")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("derive", help="deterministically derive an agent key via HKDF-SHA256")
    _add_master_secret_args(p)
    p.add_argument("--label", required=True, help="agent label (stable identifier for the agent)")
    p.add_argument("--salt-hex", help="per-run salt as hex (record it to re-derive later)")
    p.add_argument("--out", help="optionally write the derived private key file (0600)")
    p.add_argument("--force", action="store_true", help="overwrite the key file if it exists")
    p.set_defaults(func=cmd_derive)

    p = sub.add_parser("sign-envelope", help="sign a payload (the type's Q) into an AICS-1 envelope")
    p.add_argument("--key", required=True, help="private key file")
    p.add_argument("--payload", default="-", help="payload JSON file ('-' = stdin)")
    p.add_argument("--origin", required=True, help="the log origin, e.g. api.wesupport-ai.com/tiles")
    p.add_argument("--type", required=True, help="the entry type, e.g. post (AICS-1 section 17.1)")
    p.add_argument("--kid", help="the signing kid; must be the key's did:key (the default)")
    p.add_argument("--created", help="unix ts, or +N seconds from now")
    p.add_argument("--expires", help="unix ts, or +N seconds from created (at most +300)")
    p.add_argument("--nonce", help="explicit nonce: U64 of 16 bytes (default: random)")
    p.add_argument("--previous", help="the key's previous accepted envelope (JSON file): sets seq and prev")
    p.add_argument("--seq", type=int, help="sender sequence number (default 0: the key's first envelope)")
    p.add_argument("--prev", help="envelope hash of the previous accepted envelope (64 hex; null at seq 0)")
    p.add_argument("--seen-note", help="the last verified checkpoint note (file), for the seen pointer")
    p.set_defaults(func=cmd_sign_envelope)

    p = sub.add_parser("verify-envelope", help="verify an AICS-1 envelope at time t; print the payload")
    p.add_argument("--input", default="-", help="envelope JSON file ('-' = stdin)")
    p.add_argument("--key", help="private key file whose did:key the kid must be (default: decode the kid)")
    p.add_argument("--origin", help="the origin the envelope must name")
    p.add_argument("--type", help="the entry type the envelope must name")
    p.add_argument("--skew", type=int, default=_envelope.FUTURE_SKEW_SECONDS,
                   help="allowed future creation in seconds, 0 to 30 (default: %(default)s); never extends expiry")
    p.add_argument("--now", type=int, help="submission time t (unix ts; default: now)")
    p.set_defaults(func=cmd_verify_envelope)

    p = sub.add_parser("sign-request", help="sign an HTTP request; print the headers to send")
    p.add_argument("method", help="HTTP method, e.g. POST")
    p.add_argument("url", help="absolute URL, e.g. https://api.example.com/v1/tasks")
    p.add_argument("--key", required=True, help="private key file")
    p.add_argument("--body", help="request body file")
    p.add_argument("--envelope", help="the envelope the request carries (JSON file): keyid, nonce, created "
                                      "and expires are taken from it (AICS-1 section 12.1)")
    p.add_argument("--kid", help="keyid parameter (default: the key's did:key)")
    p.add_argument("--header", action="append", metavar="'Name: value'",
                   help="additional request header (repeatable)")
    p.add_argument("--component", action="append", metavar="NAME",
                   help="covered component (repeatable; default: @method @authority @path content-digest)")
    p.add_argument("--label", default=_http.DEFAULT_LABEL, help="signature label (default: %(default)s)")
    p.add_argument("--nonce", help="signature nonce parameter (default: random)")
    p.add_argument("--tag", default=_http.AICS_TAG, help="signature tag parameter (default: %(default)s; '' omits it)")
    p.add_argument("--created", help="unix ts, or +N seconds from now")
    p.add_argument("--expires", help="unix ts, or +N seconds from created (default: +300)")
    p.set_defaults(func=cmd_sign_request)

    p = sub.add_parser("verify-request", help="verify signed request headers")
    p.add_argument("method", help="HTTP method the request used")
    p.add_argument("url", help="absolute URL the request targeted")
    p.add_argument("--key", help="private key file whose did:key the keyid must be (default: decode the keyid)")
    p.add_argument("--body", help="request body file")
    p.add_argument("--header", action="append", metavar="'Name: value'",
                   help="request header (repeatable)")
    p.add_argument("--headers-file", help="file with 'Name: value' lines (one per line)")
    p.add_argument("--aics", action="store_true",
                   help="apply the AICS-1 section 12.1 profile (AICS_VERIFY_POLICY) instead of the flags below")
    p.add_argument("--envelope", help="the envelope the request carries (JSON file): keyid, nonce, created and "
                                      "expires must equal its values")
    p.add_argument("--require", metavar="C1,C2",
                   help="comma-separated required covered components (default: @method,@authority,@path)")
    p.add_argument("--skew", type=int, default=_http.DEFAULT_MAX_CLOCK_SKEW,
                   help="allowed clock skew in seconds (default: %(default)s)")
    p.add_argument("--max-age", type=int, default=_http.DEFAULT_MAX_AGE,
                   help="refuse created older than this many seconds; negative disables (default: %(default)s)")
    p.add_argument("--allow-no-expires", action="store_true",
                   help="accept signatures without an expires parameter")
    p.add_argument("--require-nonce", action="store_true", help="refuse signatures without a nonce")
    p.add_argument("--require-tag", metavar="TAG", help="refuse signatures whose tag is not TAG")
    p.add_argument("--require-digest", action="store_true",
                   help="refuse signatures that do not cover content-digest")
    p.add_argument("--now", type=int, help="override current time (unix ts, for testing)")
    p.set_defaults(func=cmd_verify_request)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (ValueError, TypeError, OSError, KeyError) as exc:
        print(f"{PROGRAM}: error: {exc}", file=sys.stderr)
        return 1
    except _envelope.EnvelopeError as exc:
        print(f"{PROGRAM}: error: {exc}", file=sys.stderr)
        return 1
    except _http.SignatureError as exc:
        print(f"{PROGRAM}: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
