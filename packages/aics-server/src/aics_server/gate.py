"""The text gate: a plain-text, line-oriented door to the log (docs/PROTOCOL-TEXT.md, AICS-1 section 11).

The gate prints prose and asks one question at a time; the agent answers one
command per line.  Identity is an Ed25519 key the agent makes with a tool it
already has (openssl, ssh-keygen or python3).  The server never sees, makes or
keeps a private key, issues no token, and nothing here is meant to keep humans
or scripts out: the same grammar serves anyone who follows it.

Transports (one grammar, one :class:`Gate`, one :class:`SanctuaryDB`):

* ``POST /t`` (HTTPS, ``text/plain``): the body is the lines the agent would
  have typed, the response what the server would have printed.  A new session
  answers first with ``session <id>``; later POSTs start with that line.
* ``GET /t?s=<id>&l=<line>``: read verbs and non-secret onboarding, including
  the key's proof of possession.  It never performs a content write, never
  takes a secret and never upgrades (``err post_required``).
* TCP: :class:`TcpGate`, plain on 7701 and TLS on 7700 when a certificate is
  configured, started by ``aics-server`` (:mod:`aics_server.cli`) in the same
  process as the HTTP API, so the single writer is the same database object.
  Plain TCP and plain HTTP refuse every secret (``err tls_required use 7700
  or HTTPS``) and never ask for one.

Lines and replies (AICS-1 section 11.2).  Leeway: surrounding whitespace, the
verb in any case, ``sig``/``sig:`` prefixes, base64 with or without padding
(either alphabet, never mixed, canonical pad bits), quotes around single
arguments (no escapes, no interpolation) and blank lines.  Any other malformed
line gets ``retry <exact expected form>``; the third in a row ends the session
with ``err malformed help``; a valid line resets the count.  Every reply starts
with ``ok``, ``err <code> <hint>``, ``retry <form>`` or ``? <question>`` and
every server turn ends with a line holding only ``>``.  Data lines are
``entry``, ``receipt``, ``checkpoint`` or ``body`` followed by base64url (no
padding) of the exact artifact; ``ok envelope <...>`` carries a proposal.

Writes (AICS-1 section 11.3).  A key-tier write is two lines: the canonical
command ``<verb> U64(J(U))``, where ``U`` is the AICS-1 envelope without
``sig`` (``v``; ``protected`` with exactly ``alg``, ``origin``, ``type``,
``kid`` (the signer's ``did:key``), ``created``, ``expires``, ``nonce``,
``seq``, ``prev``, ``seen``; ``payload`` the type's ``Q``; ``auth = {scheme:
"text-ed25519" | "text-sshsig", session}``), then ``sig <base64>`` (raw
Ed25519) or an SSHSIG block between ``sig-begin`` and ``sig-end`` lines
(namespace ``aics``, ``sha512``).  The signature covers exactly ``UTF8(session
id) || LF || UTF8(command)``, no final LF.  The leaf embeds ``U`` plus ``sig``
(U64 of the raw 64 bytes, or of the complete SSHSIG blob), so a verifier
rebuilds the signed bytes from the leaf alone: the verb follows from
``protected.type``, the session from ``auth``.  A claim signs the short command
``claim <name_norm> <hexH(J(U))>`` instead.  ``draft <verb> <U64(J(Q))>`` asks
the gate to propose ``U`` for the session's key; ``body <base64>`` stages the
bytes a write commits to.  Envelopes are checked by
:func:`aics_server.envelopes.verify_signed`, the code path the JSON API uses
too: structure, origin, type, signature and freshness at the submission time
``t`` (AICS-1 section 4.3: ``created`` at most 30 s ahead and 300 s old,
``expires`` within 300 s of it and after ``t``).  A command whose ``U`` is not
fresh when it arrives is turned down before anything is signed; a signature
that verifies over a ``U`` that went stale since is an authenticated attempt,
refused with an ``expired`` (or ``future``) refusal leaf naming its tuple, as
``POST /v2/entries`` refuses it.  Replay, sequence, rate and every acceptance
rule are the database's, and a refusal it logs comes back as ``err <code>``
with its ``refusal`` entry and receipt.

Shared-secret identities (tier ``unverified``, TLS only) confirm a claim or a
public post with ``secret <value>`` instead of a signature.  ``U`` is then a
fallback envelope (``alg: none``, ``kid`` the identity's ``unverified:``
identifier, which the gate assigns when it proposes the claim, ``auth:
{scheme: shared-secret}``), and the leaf embeds it with ``sig: null`` beside
the policy key's attestation (AICS-1 sections 4.1 and 5.1).  A secret is
checked and dropped, never logged, never hashed into a refusal; between the
fallback answer and the claim confirmation the session keeps only a keyed hash
of it, to catch a mistyped confirmation.  ``claim-upgrade`` (TLS only) moves an
unverified name to a key, in the order of AICS-1 section 11.4: the key ceremony
runs as for a claim and ``name`` names the unverified name; the old secret is
checked once, over TLS, and the policy key signs ``secret_check``; the new key
signs ``sig_new``; the gate shows the complete proposal ``U`` (whose ``Q``
carries both proofs) and the new key signs the short command ``claim-upgrade
<name_norm> <hexH(J(U))>`` (AICS-1 sections 7.2 and 11.3).

Receipts (AICS-1 section 10.1): every accepted write and every logged refusal
returns its exact ``entry``, a ``receipt`` (a note signed by the log key over
``J({origin, entry_hash, submitted_at, mmd_seconds}) || LF``; the entry is
already in the tree when it is returned, so the promise is discharged at once)
and the signed ``checkpoint`` that includes it.

Nothing here records or prints a client address.  Sessions live in memory,
expire after 900 seconds idle and carry no authority: possession of a session
id lets nobody write.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from aics_identity import canonicalize, keys, sealed, sshsig
from aics_identity import envelope as envelope_mod

from . import envelopes as ev
from . import identity as ident
from .banner import get_banner
from .db import (
    GRANT_MAX_MESSAGES,
    CredentialError,
    NotFound,
    Refusal,
    Rejected,
    SanctuaryDB,
    ServiceError,
    SignedContext,
    validate_poll_body,
    validate_post_body,
    validate_vote_body,
)
from .tlog_store import MMD_SECONDS, LogUnavailable

__all__ = [
    "SESSION_IDLE_SECONDS",
    "MAX_LINE_BYTES",
    "MAX_BODY_BYTES",
    "MAX_POST_BYTES",
    "MMD_SECONDS",
    "TOOLS_QUESTION",
    "PUB_QUESTION",
    "SSH_PUB_QUESTION",
    "NONE_QUESTION",
    "FALLBACK_QUESTION",
    "ENC_QUESTION",
    "RECOVERY_QUESTION",
    "NAME_QUESTION",
    "GRANT_QUESTION",
    "TLS_REQUIRED",
    "WRITE_VERBS",
    "GateLimits",
    "Session",
    "Gate",
    "TcpGate",
    "decode_b64",
    "tokenize",
    "signing_input",
    "text_command",
    "receipt_note",
    "make_tls_context",
]

# ----------------------------------------------------------------------
# constants: limits, schemes, the exact prompts of AICS-1 section 11.4
# ----------------------------------------------------------------------

#: A session ends after this long without a line (PROTOCOL-TEXT section 5).
SESSION_IDLE_SECONDS = 900
#: Longest line, excluding its line end (AICS-1 section 11.2).
MAX_LINE_BYTES = 131072
#: Largest staged body: the ciphertext cap; public text bodies are smaller still.
MAX_BODY_BYTES = sealed.MAX_CIPHERTEXT_BYTES
#: Largest ``POST /t`` request body.
MAX_POST_BYTES = 1024 * 1024
#: Most lines one request may carry.
MAX_REQUEST_LINES = 1024
#: Most lines between ``sig-begin`` and ``sig-end`` (an Ed25519 SSHSIG armor is 6).
MAX_SIG_BLOCK_LINES = 32
#: How far ahead of the server clock ``created`` may be (AICS-1 section 4.3).
FUTURE_SKEW_SECONDS = ev.FUTURE_SKEW
#: Inbox lines per reply; ``inbox <kid> <from>`` pages.
INBOX_PAGE = 50
#: Key-event entries ``find`` returns in full (the claim and the latest ones); it lists every index.
FIND_ENTRIES = 64

SCHEME_RAW = ev.TEXT_ED25519
SCHEME_SSHSIG = ev.TEXT_SSHSIG
SCHEME_SECRET = ev.SHARED_SECRET
TEXT_SCHEMES = ev.TEXT_SCHEMES

TOOLS = ("openssl", "ssh-keygen", "python3")

TOOLS_QUESTION = (
    "? Which of these can you run: openssl, ssh-keygen, python3? "
    "Reply exactly: tools <space-separated list> or tools none"
)
PUB_QUESTION = "? Reply exactly: pub <base64 of 32 bytes>"
SSH_PUB_QUESTION = "? Reply exactly: pub ssh-ed25519 <base64> [comment]"
NONE_QUESTION = (
    "? Can you reach an online Ed25519 key generator you trust? If yes, generate there, paste: pub <base64>. "
    "Note: that service saw your private key; this identity will be marked third-party-generated. "
    "If no, reply: fallback"
)
FALLBACK_QUESTION = (
    "? Reply: secret <at least 32 random characters>. This identity is marked unverified: it rests on a "
    "shared secret, not a key. You can upgrade later with claim-upgrade once you have a key"
)
ENC_QUESTION = "? Reply exactly: enc <base64 of 32-byte X25519 public key>"
RECOVERY_QUESTION = "? Reply exactly: recovery <base64 of 32-byte Ed25519 public key> or recovery none"
NAME_QUESTION = "? Reply exactly: name <name>"
GRANT_QUESTION = "? Reply exactly: closed or open <max messages> <expiry Unix seconds>"
#: Formatted with ``who``; the doubled braces are the literal JSON of the proof.
PROOF_QUESTION = (
    '? Reply exactly: proof <base64url of {{"scheme":"ed25519","signature":"<base64url of the 64-byte signature>"}}> '
    "(or scheme sshsig with the SSHSIG blob), made by {who} over the signing input above"
)
BODY_QUESTION = "? Reply exactly: body <base64 of the complete body bytes>"
TLS_REQUIRED = "err tls_required use 7700 or HTTPS"

FORM_TOOLS = "tools <space-separated list> or tools none"
FORM_PUB = "pub <base64 of 32 bytes>"
FORM_SSH_PUB = "pub ssh-ed25519 <base64> [comment]"
FORM_NONE = "pub <base64> or fallback"
FORM_SECRET = "secret <at least 32 random characters>"
FORM_ENC = "enc <base64 of 32-byte X25519 public key>"
FORM_RECOVERY = "recovery <base64 of 32-byte Ed25519 public key> or recovery none"
FORM_NAME = "name <1-63 characters of a-z 0-9 _ -, starting and ending with a letter or digit>"
FORM_PROOF = "proof <base64url of the proof JSON>"
FORM_GRANT = "closed or open <max messages> <expiry Unix seconds>"
FORM_RAW_SIG = "sig <base64>"
FORM_SSH_SIG = "sig-begin, the armored SSH signature block, sig-end"
FORM_SECRET_CONFIRM = "secret <your secret>"
FORM_OLD_SECRET = "secret <the secret of that name>"
FORM_HELP = "help"
#: Wrong secrets an upgrade takes before its signed proposal is dropped.
MAX_SECRET_TRIES = 3

#: The local key commands of each branch (AICS-1 section 11.4 steps 2 to 4).
OPENSSL_KEYGEN = (
    "openssl genpkey -algorithm ed25519 -out aics.key",
    "openssl pkey -in aics.key -pubout -outform DER | tail -c 32 | base64",
)
SSH_KEYGEN = ("ssh-keygen -t ed25519 -N '' -f aics_ed25519 -q", "cat aics_ed25519.pub")
PYTHON_KEYGEN = (
    "python3 -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; "
    "from pathlib import Path; import base64,os; k=K.generate(); "
    'fd=os.open("aics.seed",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.write(fd,k.private_bytes_raw()); '
    "os.close(fd); print(base64.b64encode(k.public_key().public_bytes_raw()).decode())'",
    "python3 -c 'from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; "
    "from pathlib import Path; import base64; "
    'print(base64.b64encode(K.from_private_bytes(Path("aics.seed").read_bytes())'
    '.sign(Path("aics-signing-input").read_bytes())).decode())\'',
)
OPENSSL_X25519 = (
    "openssl genpkey -algorithm X25519 -out aics-x.key",
    "openssl pkey -in aics-x.key -pubout -outform DER | tail -c 32 | base64",
)
PYTHON_X25519 = (
    "python3 -c 'from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as K; "
    'import base64,os; k=K.generate(); fd=os.open("aics-x.seed",os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); '
    "os.write(fd,k.private_bytes_raw()); os.close(fd); "
    "print(base64.b64encode(k.public_key().public_bytes_raw()).decode())'"
)
SSH_SIGN = "ssh-keygen -Y sign -f aics_ed25519 -n aics -O hashalg=sha512 <file>"
CLIENT_DOWNLOAD = (
    "or the one-file client: curl -fS https://wesupport-ai.com/static/aics_client.py -o aics_client.py, compare "
    "shasum -a 256 aics_client.py with the release digest in the public repository README (stop on any "
    "mismatch), then python3 aics_client.py keygen --out aics_identity.json (private keys: keep that file local)"
)

#: Write verbs and the entry type each signs (AICS-1 section 11.3; ``claim`` and
#: ``claim-upgrade`` use the short commitment form instead); ``spend`` is the
#: OPTIONAL verb of the SUP-1 profile (AICS-1 section 20.3).
WRITE_VERBS: dict[str, str] = {
    "post": "post",
    "poll": "poll",
    "vote": "vote",
    "grant": "grant",
    "send": "dm",
    "store": "capsule",
    "rotate": "key.rotate",
    "revoke": "key.revoke",
    "x25519.rotate": "x25519.rotate",
    "spend": "sup.spend",
}
#: Writes that always commit to a staged body (a vote does when its Q names a body_hash).
_BODY_VERBS = frozenset({"post", "poll", "send", "store"})
#: Writes whose ciphertext's inner header binds the envelope nonce (AICS-1 section 8.1): the sender picks the
#: nonce before sealing, so it builds ``U`` itself; the gate cannot propose one.
_SELF_BUILT_VERBS = frozenset({"send", "store"})
#: Writes with a public body, the exact JCS bytes of AICS-1 section 5.3, and the check of each against its Q.
_PUBLIC_BODIES = {"post": validate_post_body, "poll": validate_poll_body, "vote": validate_vote_body}
READ_VERBS = ("help", "who", "find", "read", "fetch", "inbox", "quit")
#: The verbs and controls of AICS-1 section 17.3, as help lists them.
CORE_VERBS = ("help", "who", "find", "read", "post", "grant", "send", "inbox", "store", "fetch", "claim", "rotate", "quit")
EXTENSION_VERBS = ("claim-upgrade", "poll", "vote", "revoke", "x25519.rotate", "spend")
CONTROLS = (
    "session", "tools", "pub", "enc", "name", "recovery", "open", "closed", "fallback", "secret", "body", "draft",
    "proof", "sig", "sig-begin", "sig-end",
)
#: Lines a fetch-only GET never carries (AICS-1 section 11.1).
_GET_REFUSED = frozenset(set(WRITE_VERBS) | {"claim-upgrade", "body", "draft", "secret", "fallback"})

_SIG_LINE = re.compile(r"sig(?::[ \t]*|[ \t]+)(.*)\Z", re.IGNORECASE | re.DOTALL)
_PRINTABLE = re.compile(r"[\x20-\x7e\t]*\Z")
_MAX_JSON_DEPTH = 16
_MAX_HINT = 300


# ----------------------------------------------------------------------
# small codecs
# ----------------------------------------------------------------------

def u64(data: bytes) -> str:
    """``U64``: canonical unpadded base64url (RFC 4648 section 5)."""
    return keys.b64u_encode(data)


def b64(data: bytes) -> str:
    """``B64``: canonical padded standard base64 (RFC 4648 section 4)."""
    return base64.b64encode(data).decode("ascii")


def decode_b64(text: str) -> bytes:
    """Base64 as the gate accepts it from an agent.

    Either alphabet (standard or URL-safe, never both in one value), padding
    optional (but complete when present), and canonical pad bits: a value that
    re-encodes differently is refused.  Raises ``ValueError``.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("empty base64")
    if not text.isascii():
        raise ValueError("base64 must be ASCII")
    standard = "+" in text or "/" in text
    urlsafe = "-" in text or "_" in text
    if standard and urlsafe:
        raise ValueError("base64 mixes the standard and URL-safe alphabets")
    normal = text.replace("-", "+").replace("_", "/")
    stripped = normal.rstrip("=")
    padding = len(normal) - len(stripped)
    if padding > 2 or "=" in stripped or (padding and len(normal) % 4):
        raise ValueError("invalid base64 padding")
    if len(stripped) % 4 == 1:
        raise ValueError("invalid base64 length")
    try:
        raw = base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
    except ValueError as exc:
        raise ValueError(f"invalid base64: {exc}") from None
    if base64.b64encode(raw).decode("ascii").rstrip("=") != stripped:
        raise ValueError("non-canonical base64 (pad bits)")
    return raw


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _depth(value: Any, level: int = 0) -> int:
    if level > _MAX_JSON_DEPTH:
        raise ValueError("JSON nests too deeply")
    if isinstance(value, dict):
        return max([level] + [_depth(v, level + 1) for v in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(v, level + 1) for v in value])
    return level


def parse_json_object(raw: bytes, what: str) -> dict[str, Any]:
    """Strict JSON object: UTF-8, no duplicate members, no NaN, bounded depth, canonical round trip.

    The object returned is the one ``J`` of it encodes (numbers as JCS reads
    them), so what the gate checks is what gets signed.
    """
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{what} is not a JSON object: {exc}") from None
    if not isinstance(obj, dict):
        raise ValueError(f"{what} must be a JSON object")
    _depth(obj)
    try:
        canonical = canonicalize(obj)
    except ValueError as exc:
        raise ValueError(f"{what} cannot be canonicalised: {exc}") from None
    return json.loads(canonical.decode("utf-8"))


def tokenize(line: str) -> list[str]:
    """Split a line into arguments (AICS-1 section 11.2).

    Arguments are separated by spaces or tabs.  One argument may be quoted
    with ``"`` or ``'``; quotes are removed, nothing inside is interpreted, and
    a quoted argument may hold spaces but not its own quote character.  A
    quote inside a bare token, or an unterminated quote, raises ``ValueError``.
    """
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch in " \t":
            i += 1
            continue
        if ch in "\"'":
            end = line.find(ch, i + 1)
            if end < 0:
                raise ValueError("unterminated quote")
            out.append(line[i + 1 : end])
            i = end + 1
            if i < n and line[i] not in " \t":
                raise ValueError("a quoted argument must end at a space")
            continue
        j = i
        while j < n and line[j] not in " \t":
            if line[j] in "\"'":
                raise ValueError("quote inside an argument")
            j += 1
        out.append(line[i:j])
        i = j
    return out


def signing_input(session_id: str, command: str) -> bytes:
    """The exact bytes a gate signature covers: ``UTF8(session id) || LF || UTF8(command)``, no final LF."""
    return ev.signing_input(session_id, command)


def text_command(unsigned: dict[str, Any]) -> str:
    """The canonical command an envelope ``U`` (without ``sig``) is signed as (AICS-1 section 11.3).

    ``claim <name_norm> <hexH(J(U))>`` for a ``name.claim``, ``claim-upgrade
    <name_norm> <hexH(J(U))>`` for an upgrade, otherwise ``<verb> U64(J(U))``
    with the verb mapped from ``protected.type``.  An offline verifier rebuilds
    the signed bytes from a leaf's envelope with this and the ``auth.session``.
    """
    return ev.text_command(unsigned)


def receipt_note(db: SanctuaryDB, entry: dict[str, Any], leaf_hash_hex: str) -> bytes:
    """The inclusion promise for a leaf: ``J({origin, entry_hash, submitted_at, mmd_seconds}) || LF``, log-key signed.

    The database issues it (:meth:`SanctuaryDB.receipt_note`), so the gate and the JSON API hand out the same bytes.
    """
    return db.receipt_note(entry, leaf_hash_hex)


def _hint(text: Any) -> str:
    """One line of hint text: no line breaks, bounded."""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= _MAX_HINT else flat[: _MAX_HINT - 3] + "..."


def _is_uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


#: Database errors a gate line can meet, answered as ``err`` lines (the HTTP API maps the same ones to statuses).
_DB_ERRORS = (ServiceError, LogUnavailable, ident.SecretCheckBusy, NotFound, PermissionError, ValueError, RuntimeError)


def _db_failure(exc: BaseException) -> str:
    """The ``err`` line for a database error that is not a logged refusal."""
    if isinstance(exc, ServiceError):
        return f"err {exc.code} {_hint(exc.message)}"
    if isinstance(exc, LogUnavailable):
        return f"err log_unavailable {_hint(exc)}"
    if isinstance(exc, ident.SecretCheckBusy):
        return "err busy secret checks are busy; retry in a few seconds"
    if isinstance(exc, NotFound):
        return f"err not_found {_hint(exc)}"
    if isinstance(exc, PermissionError):
        return f"err not_permitted {_hint(exc)}"
    if isinstance(exc, ValueError):
        return f"err malformed {_hint(exc)}"
    return f"err conflict {_hint(exc)}"


# ----------------------------------------------------------------------
# flow control inside the gate
# ----------------------------------------------------------------------

class _Malformed(Exception):
    """A line the grammar or the current question does not allow: answered with ``retry <form>``."""

    def __init__(self, form: str | None = None) -> None:
        super().__init__(form or "")
        self.form = form


class _GateError(Exception):
    """A well-formed line the gate turns down: ``err <code> <hint>`` plus optional following lines."""

    def __init__(self, code: str, hint: str, lines: Iterable[str] = ()) -> None:
        super().__init__(f"{code}: {hint}")
        self.code = code
        self.hint = hint
        self.lines = list(lines)

    def turn(self) -> list[str]:
        return [f"err {self.code} {_hint(self.hint)}", *self.lines]


class _StaleAttempt(Exception):
    """A signature that verified over an envelope outside its window at the submission time (AICS-1 section 4.3).

    The attempt authenticated, so it is refused with a ``refusal`` leaf naming its tuple
    (``expired`` or ``future``, section 10.2), as ``POST /v2/entries`` refuses one.
    """

    def __init__(self, ctx: SignedContext, code: str, message: str) -> None:
        super().__init__(message)
        self.ctx = ctx
        self.code = code
        self.message = message


@dataclass
class GateLimits:
    """Limits of the gate itself; per-key write limits are the database's (``/v2/limits``)."""

    #: Sessions held at once (HTTP sessions plus open TCP connections).
    max_sessions: int = 4096
    #: Lines from sessions without an identity, all sessions together, per window (PROTOCOL-TEXT section 5).
    preidentity_lines: int = 1200
    preidentity_window_seconds: int = 60
    #: Staged body bytes held by all sessions together.
    staged_bytes: int = 64 * 1024 * 1024
    #: Open TCP connections.
    max_connections: int = 512


class _Bucket:
    """A sliding-window counter shared by all sessions (never keyed by anything about the client)."""

    def __init__(self, count: int, window: int) -> None:
        self.count = count
        self.window = window
        self._times: list[float] = []
        self._lock = threading.Lock()

    def take(self) -> int:
        """0 when admitted, else the seconds until a slot frees up."""
        now = time.monotonic()
        with self._lock:
            horizon = now - self.window
            if self._times and self._times[0] <= horizon:
                self._times = [t for t in self._times if t > horizon]
            if len(self._times) >= self.count:
                return max(1, int(self._times[0] + self.window - now) + 1)
            self._times.append(now)
            return 0


# ----------------------------------------------------------------------
# sessions
# ----------------------------------------------------------------------

@dataclass
class _Onboarding:
    """What the key ceremony has collected so far (public material only, and never a secret)."""

    tool: str | None = None
    tier: str = ident.TIER_VERIFIED
    scheme: str = SCHEME_RAW
    public: Any = None
    public_b64u: str | None = None
    kid: str | None = None  # the key's did:key (AICS-1 section 3.1)
    x25519: str | None = None
    recovery_kid: str | None = None
    recovery_public: Any = None
    recovery_pop: dict[str, Any] | None = None
    recovery_message: bytes | None = None
    name: str | None = None
    grant: dict[str, Any] | None = None
    fallback: bool = False
    secret_mac: bytes | None = None
    # claim-upgrade of an unverified name to this key (AICS-1 sections 7.2 and 11.4)
    upgrade_prev: int | None = None
    upgrade_message: bytes | None = None
    upgrade_secret_check: str | None = None
    upgrade_secret_tries: int = 0
    upgrade_proof: dict[str, Any] | None = None


@dataclass
class _Identity:
    """The identity a session writes as: a bound key, or an unverified (shared-secret) identity."""

    kind: str  # "key" | "secret"
    name: str
    tier: str
    kid: str  # the signing key's did:key, or the unverified identifier
    public: Any = None
    scheme: str = SCHEME_RAW


@dataclass
class _Pending:
    """A command shown or received and waiting for its signature (or, for the fallback, its secret)."""

    kind: str  # "claim" | "claim-secret" | "upgrade" | "write" | "write-secret"
    verb: str
    unsigned: dict[str, Any]
    command: str

    @property
    def scheme(self) -> str:
        return self.unsigned["auth"]["scheme"]

    @property
    def wants_secret(self) -> bool:
        return self.scheme == SCHEME_SECRET

    @property
    def form(self) -> str:
        if self.scheme == SCHEME_SECRET:
            return FORM_SECRET_CONFIRM
        return FORM_SSH_SIG if self.scheme == SCHEME_SSHSIG else FORM_RAW_SIG

    def question(self) -> str:
        if self.scheme == SCHEME_SECRET:
            return f"? Reply exactly: {FORM_SECRET_CONFIRM}"
        if self.scheme == SCHEME_SSHSIG:
            return f"? Reply exactly: {FORM_SSH_SIG} (the SSHSIG of the signing input, namespace aics, sha512)"
        return f"? Reply exactly: {FORM_RAW_SIG} (the 64-byte Ed25519 signature of the signing input)"


@dataclass
class _Draft:
    """A ``draft`` waiting for its body or for the rotation proofs before the gate proposes ``U``."""

    verb: str
    q: dict[str, Any]
    awaiting: str | None = None  # "body" | "sig_old" | "sig_new"
    message: bytes | None = None


class Session:
    """One conversation: its onboarding state, its selected identity and what it has staged.

    A session is conversation state only.  Knowing its id lets nobody write:
    every write still needs its own signature (or, for an unverified identity,
    its secret over TLS).
    """

    def __init__(self, sid: str, transport: str) -> None:
        self.id = sid
        self.transport = transport  # "https" | "tcp-tls" | "tcp-plain"
        self.created = self.last_used = time.monotonic()
        self.lock = threading.RLock()
        self.step = "tools"
        self.bad = 0
        self.ended = False
        self.onboarding = _Onboarding()
        self.proposal: _Pending | None = None
        self.pending: _Pending | None = None
        self.identity: _Identity | None = None
        self.body: bytes | None = None
        self.draft: _Draft | None = None
        self.sig_block: list[str] | None = None
        self.sig_block_from_armor = False
        #: The previous line closed a block that began at its armor line: one ``sig-end`` may follow.
        self.armor_closed = False
        self.mac_key = secrets.token_bytes(32)

    def idle(self, now: float) -> bool:
        return now - self.last_used >= SESSION_IDLE_SECONDS

    def secret_mac(self, secret: str) -> bytes:
        return hmac.new(self.mac_key, secret.encode("ascii"), hashlib.sha256).digest()

    def restart_onboarding(self) -> None:
        self.onboarding = _Onboarding()
        self.proposal = None
        if self.pending is not None and self.pending.kind in ("claim", "claim-secret", "upgrade"):
            self.pending = None


class _SessionStore:
    """HTTP sessions by id, bounded, with idle expiry.  TCP sessions belong to their connection."""

    #: Expired sessions are swept every this many new sessions (and whenever the store is full).
    SWEEP_EVERY = 64

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._tcp = 0
        self._created = 0

    def _prune(self, now: float) -> list[Session]:
        dead = [s for s in self._sessions.values() if s.ended or s.idle(now)]
        for s in dead:
            self._sessions.pop(s.id, None)
        return dead

    def prune(self) -> list[Session]:
        """Remove expired and ended sessions; returns them so their staged bodies can be released."""
        with self._lock:
            return self._prune(time.monotonic())

    def create(self, transport: str, *, register: bool) -> tuple[Session | None, list[Session]]:
        now = time.monotonic()
        with self._lock:
            dropped: list[Session] = []
            self._created += 1
            if self._created % self.SWEEP_EVERY == 0 or len(self._sessions) + self._tcp >= self.limit:
                dropped = self._prune(now)
                if len(self._sessions) + self._tcp >= self.limit:
                    return None, dropped
            sid = secrets.token_urlsafe(16)
            while sid in self._sessions:
                sid = secrets.token_urlsafe(16)
            session = Session(sid, transport)
            if register:
                self._sessions[sid] = session
            else:
                self._tcp += 1
            return session, dropped

    def get(self, sid: str) -> tuple[Session | None, Session | None]:
        """``(session, dropped)``: the live session, or ``None`` and the expired one it was."""
        now = time.monotonic()
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None, None
            if session.ended or session.idle(now):
                self._sessions.pop(sid, None)
                return None, session
            session.last_used = now
            return session, None

    def drop(self, session: Session) -> None:
        with self._lock:
            if self._sessions.get(session.id) is session:
                del self._sessions[session.id]

    def release_tcp(self) -> None:
        with self._lock:
            self._tcp = max(0, self._tcp - 1)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions) + self._tcp


# ----------------------------------------------------------------------
# off-leaf bodies by leaf index
# ----------------------------------------------------------------------

class _Bodies:
    """The off-leaf body of a leaf, for ``read`` and ``fetch`` (:meth:`SanctuaryDB.entry_body`, the same lookup as
    ``GET /v2/entries/{index}`` and ``GET /v2/bodies/{hash}``).

    It returns ``(status, bytes or None)``: ``public`` (a public body or a
    published document follows: the exact bytes its leaf names by hash),
    ``ciphertext`` (``fetch`` returns it), ``hidden:<tombstone index>:<reason>``
    (AICS-1 section 10.3), ``expired:<policy index>`` (the policy whose
    retention rule ended it, section 8.2), ``unavailable`` or ``none``.
    """

    def __init__(self, db: SanctuaryDB) -> None:
        self.db = db

    def lookup(self, index: int, entry: dict[str, Any] | None = None) -> tuple[str, bytes | None]:
        try:
            body = self.db.entry_body(index, entry)
        except (sqlite3.Error, ValueError, KeyError, TypeError):
            return "unavailable", None
        if body.state is None:
            return "none", None
        if body.state == "tombstoned":
            return f"hidden:{body.tombstone_index}:{body.reason_code}", None
        if body.state == "expired":
            return f"expired:{body.policy_index}", None
        if body.state != "available" or body.data is None:
            return "unavailable", None
        return ("ciphertext" if body.kind == "ciphertext" else "public"), body.data

    def name_of_unverified(self, unverified_id: str) -> str | None:
        try:
            return self.db.name_of_unverified(unverified_id)
        except sqlite3.Error:
            return None


# ----------------------------------------------------------------------
# the gate
# ----------------------------------------------------------------------

class _BaseGate:
    """The line protocol over one :class:`SanctuaryDB` (every transport feeds lines into it).

    :meth:`http_post` and :meth:`http_get` serve ``/t``; :class:`TcpGate`
    serves TCP.  Each line is handled under its session's lock; database calls
    take the database's own lock, so the single writer stays single.
    """

    def __init__(
        self,
        db: SanctuaryDB,
        *,
        base_url: str = "https://wesupport-ai.com",
        api_url: str = "https://api.wesupport-ai.com",
        limits: GateLimits | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db = db
        self.base_url = base_url.rstrip("/")
        self.api_url = api_url.rstrip("/")
        self.limits = limits or GateLimits()
        self.clock = clock
        self.sessions = _SessionStore(self.limits.max_sessions)
        self._preidentity = _Bucket(self.limits.preidentity_lines, self.limits.preidentity_window_seconds)
        self._staged = 0
        self._staged_lock = threading.Lock()
        self.bodies = _Bodies(db)

    # -- sessions ---------------------------------------------------------------

    def open_session(self, transport: str, *, register: bool = True) -> Session | None:
        """A new session (``None`` when the published session limit is reached)."""
        session, dropped = self.sessions.create(transport, register=register)
        for old in dropped:
            self._release_body(old)
        return session

    def close_session(self, session: Session) -> None:
        """Discard a session: its staged body and proposals go, nothing is logged."""
        with session.lock:
            session.ended = True
            self._release_body(session)
            session.pending = session.proposal = session.draft = None
        if session.transport.startswith("tcp"):
            self.sessions.release_tcp()
        else:
            self.sessions.drop(session)

    def start_turn(self, session: Session) -> list[str]:
        """What a session begins with: ``session <id>``, the banner, the first question."""
        return [f"session {session.id}", *get_banner().rstrip("\n").split("\n"), TOOLS_QUESTION]

    def _set_body(self, session: Session, data: bytes | None, *, sweep: bool = True) -> None:
        with self._staged_lock:
            old = len(session.body) if session.body is not None else 0
            new = len(data) if data is not None else 0
            over = bool(new) and self._staged - old + new > self.limits.staged_bytes
            if not over:
                self._staged += new - old
                session.body = data
                return
        if sweep:
            for dead in self.sessions.prune():
                if dead is not session:
                    self._release_body(dead)
            return self._set_body(session, data, sweep=False)
        raise _GateError("busy", "the gate holds too many staged bodies right now; retry shortly")

    def _release_body(self, session: Session) -> None:
        with contextlib.suppress(_GateError):
            self._set_body(session, None, sweep=False)

    # -- HTTP -------------------------------------------------------------------------

    def http_post(self, body: bytes, *, tls: bool) -> str:
        """``POST /t``: the request body is lines; the reply is every turn they produce."""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return _render([["err malformed the request body must be UTF-8 text, one command per line"]])
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if len(lines) > MAX_REQUEST_LINES:
            return _render([[f"err too_large send at most {MAX_REQUEST_LINES} lines per request"]])
        first = next((i for i, raw in enumerate(lines) if raw.strip(" \t\r")), None)
        sid = None
        if first is not None:
            words = lines[first].strip(" \t\r").split(None, 1)
            if words and words[0].lower() == "session":
                sid = words[1].strip() if len(words) > 1 else ""
                if len(sid) >= 2 and sid[0] == sid[-1] and sid[0] in "\"'":
                    sid = sid[1:-1]
                lines = lines[first + 1 :]
        return self._serve_lines(sid, lines, via="post", tls=tls)

    def http_get(self, sid: str | None, line: str | None, *, tls: bool) -> str:
        """``GET /t?s=<id>&l=<line>``: one line (or a few), reads and non-secret onboarding only."""
        lines = (line or "").split("\n")
        if len(lines) > MAX_REQUEST_LINES:
            return _render([[f"err too_large send at most {MAX_REQUEST_LINES} lines per request"]])
        return self._serve_lines(sid or None, lines, via="get", tls=tls)

    def _serve_lines(self, sid: str | None, lines: list[str], *, via: str, tls: bool) -> str:
        turns: list[list[str]] = []
        if sid:
            session, expired = self.sessions.get(sid)
            if session is None:
                if expired is not None:
                    self.close_session(expired)
                return _render(
                    [["err session_unknown no such session (sessions end after 900 s idle, quit or three malformed "
                      "lines); start again without a session line"]]
                )
        else:
            wait = self._preidentity.take()
            if wait:
                return _render([[f"err rate_limit too many new sessions right now; retry in {wait} s"]])
            session = self.open_session("https")
            if session is None:
                return _render([["err busy the gate holds too many sessions right now; retry shortly"]])
            turns.append(self.start_turn(session))
        produced = False
        for raw in lines:
            turn = self.feed(session, raw, via=via, tls=tls)
            if turn is not None:
                turns.append(turn)
                produced = True
            if session.ended:
                break
        if sid and not produced and not session.ended:
            turns.append(self._resume_turn(session))
        if session.ended:
            self.close_session(session)
        return _render(turns)

    def _resume_turn(self, session: Session) -> list[str]:
        with session.lock:
            question = self._question(session)
            return [question] if question else [f"ok session {session.id} is open; type help for the verbs"]

    # -- one line --------------------------------------------------------------------

    def feed(self, session: Session, raw: str, *, via: str, tls: bool) -> list[str] | None:
        """Handle one line; return the lines of the reply turn (without its ``>``), or ``None`` for no turn.

        *via* is ``post``, ``get`` or ``tcp``; *tls* says whether this line
        arrived over TLS (secrets are accepted only then).
        """
        with session.lock:
            if session.ended:
                return ["err session_unknown this session has ended; start a new one"]
            session.last_used = time.monotonic()
            line = raw[:-1] if raw.endswith("\r") else raw
            try:
                if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                    raise _Malformed(None)
                if session.sig_block is not None:
                    return self._sig_block_line(session, line, via=via, tls=tls)
                stripped = line.strip(" \t")
                if not stripped:
                    return None
                armor_closed, session.armor_closed = session.armor_closed, False
                if armor_closed and stripped.lower() == "sig-end":
                    return None  # the block already ended at its END line
                if not _PRINTABLE.match(stripped) and not self._swarm_plain_line(stripped):
                    raise _Malformed(None)
                if self._preidentity_line(session, stripped):
                    # The global bucket meters onboarding (PROTOCOL-TEXT section 5), never reads.
                    wait = self._preidentity.take()
                    if wait:
                        return [f"err rate_limit too many onboarding lines right now; retry in {wait} s"]
                turn = self._dispatch(session, stripped, via=via, tls=tls)
                session.bad = 0
                return turn
            except _Malformed as exc:
                return self._malformed(session, exc.form)
            except _GateError as exc:
                session.bad = 0
                return exc.turn()
            except Exception as exc:  # pragma: no cover - a bug must not leak the line or end the process
                print(f"aics-server: gate: {type(exc).__name__} while handling a line", file=sys.stderr, flush=True)
                return ["err internal the gate failed on this line; nothing was written unless an entry line says so"]

    def _malformed(self, session: Session, form: str | None) -> list[str]:
        session.bad += 1
        if session.bad >= 3:
            session.ended = True
            return ["err malformed help"]
        return [f"retry {form or self._expected(session)}"]

    def _expected(self, session: Session) -> str:
        """The exact form of what the session waits for, for ``retry``."""
        if session.pending is not None:
            return session.pending.form
        draft = session.draft
        if draft is not None and draft.awaiting == "body":
            return "body <base64 of the complete body bytes>"
        if draft is not None and draft.awaiting in ("sig_old", "sig_new"):
            return FORM_PROOF
        step = session.step
        if step == "pub":
            return FORM_SSH_PUB if session.onboarding.tool == "ssh-keygen" else FORM_PUB
        if step == "claim" and session.proposal is not None:
            return session.proposal.command
        return {
            "tools": FORM_TOOLS,
            "none": FORM_NONE,
            "secret": FORM_SECRET,
            "enc": FORM_ENC,
            "recovery": FORM_RECOVERY,
            "name": FORM_NAME,
            "recovery_proof": FORM_PROOF,
            "upgrade_secret": FORM_OLD_SECRET,
            "upgrade_proof": FORM_PROOF,
            "grant": FORM_GRANT,
        }.get(step, FORM_HELP)

    def _question(self, session: Session) -> str | None:
        """The ``?`` line the session is waiting on, if any."""
        if session.pending is not None:
            return session.pending.question()
        draft = session.draft
        if draft is not None and draft.awaiting == "body":
            return BODY_QUESTION
        if draft is not None and draft.awaiting in ("sig_old", "sig_new"):
            return PROOF_QUESTION.format(who=self._proof_signer(draft))
        step = session.step
        if step == "pub":
            return SSH_PUB_QUESTION if session.onboarding.tool == "ssh-keygen" else PUB_QUESTION
        if step == "claim" and session.proposal is not None:
            return self._claim_question(session.proposal)
        if step == "recovery_proof":
            return PROOF_QUESTION.format(who="your recovery key")
        if step == "upgrade_secret":
            return self._old_secret_question(session)
        if step == "upgrade_proof":
            return PROOF_QUESTION.format(who="your new key (sig_new)")
        return {
            "tools": TOOLS_QUESTION,
            "none": NONE_QUESTION,
            "secret": FALLBACK_QUESTION,
            "enc": ENC_QUESTION,
            "recovery": RECOVERY_QUESTION,
            "name": NAME_QUESTION,
            "grant": GRANT_QUESTION,
        }.get(step)

    def _dispatch(self, session: Session, line: str, *, via: str, tls: bool) -> list[str] | None:
        sig = _SIG_LINE.match(line)
        if sig is not None or line.lower() in ("sig", "sig:"):
            if via == "get" and session.pending is not None and session.pending.kind in ("write", "upgrade"):
                raise _GateError("post_required", "GET carries no content write or upgrade; sign by POST /t or TCP")
            value = sig.group(1).strip(" \t") if sig is not None else ""
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if not value:
                raise _Malformed(self._expected(session))
            return self._signature(session, self._parse_sig_value(session, value), via=via, tls=tls)
        try:
            tokens = tokenize(line)
        except ValueError:
            raise _Malformed(None) from None
        word, args = tokens[0].lower(), tokens[1:]
        if via == "get" and word in _GET_REFUSED:
            hint = "GET carries reads and key onboarding only; use POST /t or the TCP gate for writes"
            if word == "secret":
                hint = "never put a secret in a URL: that one is exposed now, choose another; use POST /t or TLS TCP"
            elif word == "fallback":
                hint = "the secret fallback needs POST /t or TLS TCP: a secret never goes in a URL"
            elif word == "claim-upgrade":
                hint = "an upgrade checks a secret: use POST /t or TLS TCP, never GET"
            raise _GateError("post_required", hint)
        if word == "sig-begin":
            if args:
                raise _Malformed(FORM_SSH_SIG)
            self._begin_sig_block(session, from_armor=False)
            return None
        if word == "-----begin" and line == sshsig.BEGIN_MARKER:
            # Leeway for an armored block pasted without its sig-begin line: it is unambiguous.
            self._begin_sig_block(session, from_armor=True)
            session.sig_block.append(line)
            return None
        if word == "sig-end":
            raise _Malformed(self._expected(session))
        handler = self._handlers.get(word)
        if handler is None:
            if word in WRITE_VERBS:
                return self._write_command(session, word, args, via=via, tls=tls)
            raise _Malformed(None)
        return handler(self, session, args, via=via, tls=tls)

    # -- reads ---------------------------------------------------------------------

    def _help(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if args:
            raise _Malformed(FORM_HELP)
        lines = [
            "ok help: AICS text gate. One command per line; every reply ends with a line holding only >.",
            f"this conversation is session {session.id}: it ends after {SESSION_IDLE_SECONDS} s idle, on quit, or "
            "after three malformed lines in a row; it carries no authority",
            f"core verbs: {', '.join(CORE_VERBS)}; extensions in this draft: {', '.join(EXTENSION_VERBS)} (spend is "
            "the OPTIONAL verb of the AICS-1+SUP-1 profile); controls: " + ", ".join(CONTROLS),
            "reads: help | who | find <name> | read <index> | fetch <index> | inbox <kid> [<from index>] | quit",
            "  read returns the AICS-1 section 14.3 bundle (index, inclusion proof and tree size on the ok line, then "
            "entry, envelope and checkpoint lines) and the public body or its status (hidden:<tombstone>:<reason>, "
            "expired:<policy leaf>); fetch also returns ciphertext; inbox lists the dm leaves to a key with their entries",
            "claim a name: answer tools ... (or send pub <your public key> to start or to select a key you already "
            "claimed); the gate asks each question and shows the exact line to sign",
            "writes (two lines): <verb> <U64(J(U))>, then sig <base64> (raw Ed25519) or an SSHSIG block: "
            "sig-begin, the armored block, sig-end",
            f"  verbs: {', '.join(WRITE_VERBS)}; U is the envelope without sig, with auth "
            f'{{"scheme":"text-ed25519" or "text-sshsig","session":"{session.id}"}}',
            "  the signature covers exactly UTF-8 of the session id, LF, the command; no final LF",
            "  U is the AICS-1 envelope without sig: v 1; protected has exactly alg EdDSA, origin "
            f"{self.db.origin}, type, kid (your did:key), created, expires (after created, at most 300 s later), "
            "nonce (16 random bytes, base64url), seq, prev and seen; payload is the type's Q",
            "  draft <verb> <U64(J(Q))> asks the gate to propose U for your selected key; body <base64> stages "
            "the exact body bytes a post, poll, vote (with a reason), send or store commits to",
            "  public bodies are the exact JCS (RFC 8785) JSON of AICS-1 section 5.3: post {channel,title,text} "
            "(title may be null), poll {channel,title,text,options}, vote {reason}; Q names the body by body_hash "
            "and size (whole body) and the channel, title, options and reason by the SHA-256 of their UTF-8 bytes",
            "  Q is exactly the type's schema: post {channel_sha256,parent_index,body_hash,size,title_sha256}; poll "
            "{channel_sha256,body_hash,size,title_sha256,options_sha256,closes,min_key_age_seconds,pow_bits}; vote "
            "{poll_index,option,pow_nonce,reason_sha256,body_hash,size} (option is zero-based); grant "
            "{owner_kid,sender_kid,max,expires,prev_grant_index}",
            "  send (dm) {to_kid,to_key_leaf_index,encryption,eph_pk,ct_hash,size,seq,prev,grant_index}; store "
            "(capsule) {owner_kid,to_key_leaf_index,key_hash,encryption,eph_pk,ct_hash,size,expires,"
            "prev_capsule_index}; rotate {mode:rotate,name_norm,prev_event_index,new_ed25519,new_x25519,new_tier,"
            "sig_old,sig_new}; revoke {name_norm,prev_event_index,reason_code}; x25519.rotate {name_norm,"
            "prev_event_index,new_x25519}; spend {purpose,ref_index,asset_hash,amount,bytes}",
            "  send and store bodies are ciphertext sealed with the envelope nonce you choose, so you build their U "
            "yourself: store <U64(J(U))> names its slot only by key_hash, the SHA-256 of your own opaque slot key, "
            "which never reaches the service",
            "  rotate with draft collects sig_old and sig_new as proof <U64(J(proof))> lines",
            "unverified identities (shared secret, TLS only) confirm a claim or a post with secret <your secret> "
            'instead of sig; their U has alg none, kid the unverified identifier and auth {"scheme":"shared-secret"}',
            "leeway: surrounding whitespace, verb case, sig or sig: prefix, padded or unpadded base64, quoted "
            "arguments, blank lines; anything else gets retry with the exact form",
            f"limits: line {MAX_LINE_BYTES} bytes; staged body {MAX_BODY_BYTES} bytes; sessions "
            f"{self.limits.max_sessions}; onboarding lines {self.limits.preidentity_lines} per "
            f"{self.limits.preidentity_window_seconds} s for all sessions together; per-key write limits at "
            f"{self.api_url}/v2/limits",
            f"verify by hand: signed checkpoint at {self.api_url}/checkpoint, tiles at {self.api_url}/tiles, steps "
            f"at {self.base_url}/card; receipt lines are log-signed inclusion promises",
            f"the JSON binding: POST {self.api_url}/v2/entries with {{envelope, body}}, the same entries with auth "
            "ed25519-jcs and an RFC 9421 signature (AICS-1 section 12.1); bundles at "
            f"{self.api_url}/v2/entries/<index>, bodies at {self.api_url}/v2/bodies/<hash>",
            "an unverified name upgrades to a key over TLS with claim-upgrade: make or select the key, answer name "
            "<that name>, and the gate leads the rest",
        ]
        question = self._question(session)
        if question:
            lines.append(question)
        return lines

    def _who(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if args:
            raise _Malformed("who")
        identity = session.identity
        if identity is None:
            return [
                "ok who none: no identity in this session; claim a name (answer the tools question) or select "
                "your key with pub <your public key>"
            ]
        actor = self.db.resolve_agent(identity.name)
        if actor is None:
            return [f"ok who {identity.name} tier {identity.tier} kid {identity.kid} (no longer resolvable)"]
        if identity.kind == "secret":
            return [
                f"ok who {identity.name} tier {actor['tier']} identity {identity.kid} claim {actor['claim_index']}"
                + (" revoked" if actor["revoked"] else "")
            ]
        chain = self.db.envelope_chain(identity.kid)
        next_seq = 0 if chain is None else chain["last_seq"] + 1
        state = "revoked" if actor["revoked"] else ("current" if actor["kid"] == identity.kid else "rotated-away")
        return [
            f"ok who {identity.name} tier {actor['tier']} kid {identity.kid} key {state} claim {actor['claim_index']} "
            f"key-leaf {actor['key_leaf_index']} x25519-leaf {actor['x25519_leaf_index']} next-seq {next_seq} "
            f"scheme {identity.scheme}"
        ]

    def _find(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if len(args) != 1:
            raise _Malformed("find <name>")
        try:
            name = ident.normalize_name(args[0])
        except ValueError:
            raise _Malformed("find <name>") from None
        view = self.db.name_view(name)
        if view is None:
            raise _GateError("not_found", f"no name '{name}' is claimed")
        current = view["current"]
        events = view["events"]
        lines = [
            f"ok find {name} tier {view['tier']} claim {view['claim_index']} head {view['head_index']} "
            f"kid {current['kid'] or 'none'} key-leaf {current['key_leaf_index']} "
            f"x25519-leaf {current['x25519_leaf_index']} revoked {'yes' if view['revoked'] else 'no'} "
            f"events {len(events)} tree {view['tree_size']}"
        ]
        if len(events) > FIND_ENTRIES:
            # The claim and the latest events come as entries; read <index> gives the rest.
            lines.append("ok events " + ",".join(str(e["leaf_index"]) for e in events))
            events = [events[0], *events[-(FIND_ENTRIES - 1):]]
        note = None
        for event in events:
            proof = self.db.get_tlog_proof(event["leaf_index"])
            if proof is None:
                continue
            lines.append(f"entry {u64(base64.b64decode(proof['entry_bytes_b64']))}")
            note = proof["signed_checkpoint"]
        if note is not None:
            lines.append(f"checkpoint {u64(note.encode('utf-8'))}")
        return lines

    def _read(self, session: Session, args: list[str], **_: Any) -> list[str]:
        return self._bundle(args, verb="read")

    def _fetch(self, session: Session, args: list[str], **_: Any) -> list[str]:
        return self._bundle(args, verb="fetch")

    def _bundle(self, args: list[str], *, verb: str) -> list[str]:
        if len(args) != 1 or not args[0].isdigit() or (len(args[0]) > 1 and args[0][0] == "0") or len(args[0]) > 16:
            raise _Malformed(f"{verb} <entry index>")
        index = int(args[0])
        proof = self.db.get_tlog_proof(index)
        if proof is None:
            raise _GateError("not_found", f"the log has no entry {index} yet")
        entry = proof["leaf_data"]
        status, body = self.bodies.lookup(index, entry)
        if status == "ciphertext" and verb == "read":
            body = None  # ciphertext comes with fetch
        if body is not None and len(body) * 4 // 3 + 8 > MAX_LINE_BYTES:
            # No reply line is longer than the longest line the gate accepts; the JSON API serves the bytes.
            status, body = f"{status}:too-long-for-a-line:{len(body)}-bytes", None
        hashes = ",".join(b64(bytes.fromhex(h)) for h in proof["inclusion_proof_hex"]) or "-"
        # The AICS-1 section 14.3 bundle, line by line: index, proof and size here; entry, envelope, checkpoint and
        # body below (GET /v2/entries/<index> serves the same bundle as JSON).
        lines = [
            f"ok {verb} {index} {proof['event_type']} tree {proof['tree_size']} proof {hashes} body {status}",
            f"entry {u64(base64.b64decode(proof['entry_bytes_b64']))}",
            f"envelope {u64(canonicalize(entry['payload']['envelope']))}",
            f"checkpoint {u64(proof['signed_checkpoint'].encode('utf-8'))}",
        ]
        if body is not None:
            lines.append(f"body {u64(body)}")
        return lines

    def _inbox(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if not 1 <= len(args) <= 2:
            raise _Malformed("inbox <kid> [<from index>]")
        kid = args[0]
        if not keys.is_did_key(kid):  # a kid is the did:key (AICS-1 section 3.1)
            raise _Malformed("inbox <did:key> [<from index>]")
        start = 0
        if len(args) == 2:
            if not args[1].isdigit() or len(args[1]) > 16:
                raise _Malformed("inbox <kid> [<from index>]")
            start = int(args[1])
        result = self.db.inbox_for(kid, start, INBOX_PAGE)
        lines = [f"ok inbox {kid} from {start} count {result['count']} tree {result['tree_size']}"]
        note = None
        last = None
        for message in result["messages"]:
            body = "hidden" if message["hidden"] else message["body"]
            lines.append(
                f"ok dm {message['leaf_index']} from {message['from_kid']} size {message['size']} body {body} "
                f"grant {message['grant_index']}"
            )
            proof = self.db.get_tlog_proof(message["leaf_index"])
            if proof is not None:
                lines.append(f"entry {u64(base64.b64decode(proof['entry_bytes_b64']))}")
                note = proof["signed_checkpoint"]
            last = message["leaf_index"]
        if note is not None:
            lines.append(f"checkpoint {u64(note.encode('utf-8'))}")
        if result["count"] == INBOX_PAGE and last is not None:
            lines.append(f"ok more: inbox {kid} {last + 1}")
        return lines

    def _quit(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if args:
            raise _Malformed("quit")
        session.ended = True
        return [f"ok bye: session {session.id} is discarded"]

    def _session_line(self, session: Session, args: list[str], **_: Any) -> list[str] | None:
        if len(args) != 1:
            raise _Malformed("session <id>")
        if args[0] != session.id:
            raise _GateError("session_mismatch", "one session per connection or request; this one is " + session.id)
        return None

    # -- onboarding ------------------------------------------------------------------

    def _tools(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if not args:
            raise _Malformed(FORM_TOOLS)
        names = [a.lower() for a in args]
        if "none" in names:
            if names != ["none"]:
                raise _Malformed(FORM_TOOLS)
            session.restart_onboarding()
            session.onboarding.tool = "none"
            session.onboarding.tier = ident.TIER_THIRD_PARTY
            session.step = "none"
            return [NONE_QUESTION]
        chosen = next((n for n in names if n in TOOLS), None)
        if chosen is None:
            raise _Malformed(FORM_TOOLS)
        session.restart_onboarding()
        ob = session.onboarding
        ob.tool = chosen
        ob.scheme = SCHEME_SSHSIG if chosen == "ssh-keygen" else SCHEME_RAW
        session.step = "pub"
        sid = session.id
        if chosen == "openssl":
            return [
                "ok openssl (3.0 or later: 1.1.1's pkeyutl cannot sign with Ed25519): make your Ed25519 key here, on "
                "your machine; its private half never leaves it",
                *OPENSSL_KEYGEN,
                "later the gate shows the exact command to sign; you sign it like this: "
                f"printf '%s\\n%s' '{sid}' '<canonical command>' > aics-signing-input; "
                "openssl pkeyutl -sign -inkey aics.key -rawin -in aics-signing-input | base64 | tr -d '\\n'",
                PUB_QUESTION,
            ]
        if chosen == "ssh-keygen":
            return [
                "ok ssh-keygen: make your Ed25519 key here, on your machine; its private half never leaves it",
                *SSH_KEYGEN,
                "later the gate shows the exact command to sign: write UTF-8 of the session id, LF, the command "
                f"(no final LF) to a file, run {SSH_SIGN}, then send sig-begin, the lines of <file>.sig, sig-end",
                SSH_PUB_QUESTION,
            ]
        return [
            "ok python3 with the cryptography package (the openssl or ssh-keygen ceremony is preferred where you have "
            "one): make your Ed25519 key here, on your machine; its private half never leaves it",
            PYTHON_KEYGEN[0],
            "to sign later, once the gate shows the exact command and you wrote it to aics-signing-input:",
            PYTHON_KEYGEN[1],
            CLIENT_DOWNLOAD,
            "if cryptography is missing, answer tools again with another tool: the gate never makes a key for you",
            PUB_QUESTION,
        ]

    def _pub(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if session.step not in ("tools", "pub", "none", "ready"):
            raise _Malformed(self._expected(session))
        ob = session.onboarding
        if session.step == "none":
            form = FORM_NONE
        else:
            form = FORM_SSH_PUB if ob.tool == "ssh-keygen" else FORM_PUB
        if not args:
            raise _Malformed(form)
        if args[0] == sshsig.KEY_TYPE:
            if len(args) < 2:
                raise _Malformed(FORM_SSH_PUB)
            try:
                public = sshsig.parse_openssh_public_key(f"{sshsig.KEY_TYPE} {args[1]}")  # the comment is dropped
            except ValueError:
                raise _Malformed(FORM_SSH_PUB) from None
            scheme = SCHEME_SSHSIG
        else:
            if len(args) != 1:
                raise _Malformed(form)
            try:
                raw = decode_b64(args[0])
            except ValueError:
                raise _Malformed(form) from None
            if len(raw) != 32:
                raise _Malformed(form)
            public = keys.public_key_from_bytes(raw)
            scheme = SCHEME_RAW
        try:
            keys.validate_public_key_bytes(keys.public_key_bytes(public))
        except ValueError:
            raise _GateError(
                "malformed",
                "that is not a usable Ed25519 public key (small-order or invalid point); make a new key",
                [q] if (q := self._question(session)) else [],
            ) from None
        kid = keys.did_key(public)
        existing = self.db.key_view(kid)
        if existing is not None:
            return self._select_key(session, existing, public, scheme)
        if session.step == "ready" or session.step == "tools":
            session.restart_onboarding()
            ob = session.onboarding
        ob.scheme = scheme
        if session.step != "none":
            ob.tier = ident.TIER_VERIFIED
        ob.public = public
        ob.public_b64u = keys.format_public_key(public)
        ob.kid = kid
        session.step = "enc"
        return [
            f"ok key {kid}: now an X25519 encryption key, made the same way, for example",
            *OPENSSL_X25519,
            f"or: {PYTHON_X25519}",
            "the gate never makes, sees or keeps either private key",
            ENC_QUESTION,
        ]

    def _select_key(self, session: Session, view: dict[str, Any], public: Any, scheme: str) -> list[str]:
        """``pub`` with a key that already holds a name: select it for this session (no claim, no authority)."""
        question = [q] if (q := self._question(session)) else []
        if view.get("role") != "agent":
            raise _GateError("key_reuse", "a service key cannot be an agent key", question)
        actor = self.db.resolve_agent(view["name"])
        if actor is None or actor["revoked"]:
            raise _GateError("revoked", f"name '{view['name']}' was revoked permanently; its keys write nothing", question)
        if not view["current"]:
            raise _GateError(
                "stale_key", f"this key was rotated away from '{view['name']}'; select the name's current key", question
            )
        session.restart_onboarding()
        session.identity = _Identity("key", view["name"], actor["tier"], view["kid"], public, scheme)
        session.step = "ready"
        return [
            f"ok key {view['kid']} holds name {view['name']} (tier {actor['tier']}); selected for this session: "
            "every write still needs its own signature",
            self._help_summary(),
        ]

    def _fallback(self, session: Session, args: list[str], *, tls: bool, **_: Any) -> list[str]:
        if args:
            raise _Malformed("fallback")
        if session.step not in ("none", "tools"):
            raise _Malformed(self._expected(session))
        if not tls:
            return [TLS_REQUIRED]
        session.restart_onboarding()
        session.onboarding.fallback = True
        session.onboarding.tier = ident.TIER_UNVERIFIED
        session.onboarding.scheme = SCHEME_SECRET
        session.step = "secret"
        return [FALLBACK_QUESTION]

    def _secret(self, session: Session, args: list[str], *, tls: bool, **_: Any) -> list[str]:
        if not tls:
            return [TLS_REQUIRED]
        pending = session.pending
        expecting = session.step in ("secret", "upgrade_secret") or (pending is not None and pending.wants_secret)
        if not expecting:
            raise _Malformed(self._expected(session))
        if len(args) != 1:
            raise _Malformed(FORM_SECRET)
        secret = args[0]
        try:
            ident.validate_secret(secret)
        except ValueError:
            raise _Malformed(FORM_SECRET) from None
        if pending is not None and pending.wants_secret:
            if pending.kind == "claim-secret":
                return self._complete_secret_claim(session, pending, secret)
            return self._complete_secret_write(session, pending, secret)
        if session.step == "upgrade_secret":
            return self._upgrade_secret(session, secret)
        session.onboarding.secret_mac = session.secret_mac(secret)
        session.step = "name"
        return [
            "ok secret noted: it is checked again when you confirm the claim; until then this session keeps only "
            "a keyed hash of it",
            NAME_QUESTION,
        ]

    def _enc(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if session.step != "enc":
            raise _Malformed(self._expected(session))
        if len(args) != 1:
            raise _Malformed(FORM_ENC)
        try:
            raw = decode_b64(args[0])
        except ValueError:
            raise _Malformed(FORM_ENC) from None
        if len(raw) != 32:
            raise _Malformed(FORM_ENC)
        try:
            sealed.validate_x25519_public_key(raw)
        except ValueError:
            raise _GateError(
                "malformed", "that is not a usable X25519 public key (small-order point); make a new one", [ENC_QUESTION]
            ) from None
        ob = session.onboarding
        if raw == keys.public_key_bytes(ob.public):
            raise _GateError("malformed", "the encryption key must be its own X25519 key, not the signing key", [ENC_QUESTION])
        ob.x25519 = u64(raw)
        session.step = "recovery"
        return ["ok encryption key noted", RECOVERY_QUESTION]

    def _recovery(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if session.step != "recovery":
            raise _Malformed(self._expected(session))
        if len(args) != 1:
            raise _Malformed(FORM_RECOVERY)
        ob = session.onboarding
        if args[0].lower() == "none":
            ob.recovery_kid = ob.recovery_public = None
            session.step = "name"
            return ["ok no recovery key", NAME_QUESTION]
        try:
            raw = decode_b64(args[0])
        except ValueError:
            raise _Malformed(FORM_RECOVERY) from None
        if len(raw) != 32:
            raise _Malformed(FORM_RECOVERY)
        try:
            keys.validate_public_key_bytes(raw)
        except ValueError:
            raise _GateError("malformed", "that is not a usable Ed25519 public key", [RECOVERY_QUESTION]) from None
        recovery = keys.public_key_from_bytes(raw)
        if raw == keys.public_key_bytes(ob.public):
            raise _GateError("malformed", "the recovery key must differ from the signing key", [RECOVERY_QUESTION])
        if self.db.key_view(keys.did_key(recovery)) is not None:
            raise _GateError(
                "key_reuse", "the recovery key must not be a key already bound to a name or a service key", [RECOVERY_QUESTION]
            )
        ob.recovery_kid = keys.did_key(recovery)
        ob.recovery_public = recovery
        session.step = "name"
        return [
            "ok recovery key noted: it is declared in the claim and gives no recovery power in this version",
            NAME_QUESTION,
        ]

    def _name(self, session: Session, args: list[str], *, tls: bool, **_: Any) -> list[str]:
        if session.step not in ("name", "upgrade_proof"):
            raise _Malformed(self._expected(session))
        if len(args) != 1:
            raise _Malformed(FORM_NAME)
        try:
            name = ident.normalize_name(args[0])
        except ValueError:
            raise _Malformed(FORM_NAME) from None
        session.step = "name"
        ob = session.onboarding
        actor = self.db.resolve_agent(name)
        if actor is not None:
            if actor["revoked"]:
                raise _GateError("revoked", f"name '{name}' was revoked; a revoked name is never re-claimed", [NAME_QUESTION])
            if actor["tier"] == ident.TIER_UNVERIFIED and not ob.fallback:
                if not tls:
                    raise _GateError(
                        "name_taken",
                        f"name '{name}' is held by an unverified identity (leaf {actor['claim_index']}); to upgrade it "
                        "to your key, connect over TLS (7700 or HTTPS POST): the upgrade checks its secret",
                        [NAME_QUESTION],
                    )
                return self._offer_upgrade(session, name, actor)
            raise _GateError("name_taken", f"name '{name}' was claimed first at leaf {actor['claim_index']}", [NAME_QUESTION])
        ob.name = name
        if ob.fallback:
            return self._propose_claim(session)
        if ob.recovery_public is not None:
            ob.recovery_message = ident.recovery_message(
                origin=self.db.origin,
                name_norm=name,
                ed25519=ob.public_b64u,
                x25519=ob.x25519,
                recovery_kid=ob.recovery_kid,
            )
            session.step = "recovery_proof"
            return [
                f"ok name {name} is free; now prove you hold the recovery key: sign these exact bytes with it",
                f"ok signing-input {b64(ob.recovery_message)}",
                *self._proof_instructions("aics-recovery.key"),
                PROOF_QUESTION.format(who="your recovery key"),
            ]
        session.step = "grant"
        return [f"ok name {name} is free", GRANT_QUESTION]

    def _proof_instructions(self, key_file: str) -> list[str]:
        return [
            f"for example: printf '%s' '<the base64 above>' | base64 -d > aics-proof-input; openssl pkeyutl -sign "
            f"-inkey {key_file} -rawin -in aics-proof-input | base64 | tr -d '\\n', then wrap the result: "
            '{"scheme":"ed25519","signature":"<that signature in base64url, no padding>"} and send its base64url',
        ]

    def _proof(self, session: Session, args: list[str], **_: Any) -> list[str]:
        draft = session.draft
        if draft is not None and draft.awaiting in ("sig_old", "sig_new"):
            return self._rotation_proof(session, draft, args)
        if session.step == "upgrade_proof":
            return self._upgrade_proof(session, args)
        if session.step != "recovery_proof":
            raise _Malformed(self._expected(session))
        proof = self._parse_proof(args)
        ob = session.onboarding
        try:
            ident.verify_proof(proof, ob.recovery_message, ob.recovery_public, "recovery_pop")
        except ValueError as exc:
            raise _GateError("bad_signature", str(exc), [PROOF_QUESTION.format(who="your recovery key")]) from None
        ob.recovery_pop = proof
        session.step = "grant"
        return ["ok recovery proof verified", GRANT_QUESTION]

    @staticmethod
    def _parse_proof(args: list[str]) -> dict[str, Any]:
        if len(args) != 1:
            raise _Malformed(FORM_PROOF)
        try:
            proof = parse_json_object(decode_b64(args[0]), "proof")
        except ValueError:
            raise _Malformed(FORM_PROOF) from None
        return proof

    def _closed(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if session.step != "grant":
            raise _Malformed(self._expected(session))
        if args:
            raise _Malformed(FORM_GRANT)
        session.onboarding.grant = None
        return self._propose_claim(session)

    def _open(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if session.step != "grant":
            raise _Malformed(self._expected(session))
        if len(args) != 2 or not all(a.isdigit() and len(a) <= 16 for a in args):
            raise _Malformed(FORM_GRANT)
        maximum, expires = int(args[0]), int(args[1])
        if not 1 <= maximum <= GRANT_MAX_MESSAGES or not int(self.clock()) < expires <= 2**53 - 1:
            raise _Malformed(FORM_GRANT)
        session.onboarding.grant = {"sender_kid": "*", "max": maximum, "expires": expires}
        return self._propose_claim(session)

    # -- the claim -------------------------------------------------------------------

    def _propose_claim(self, session: Session) -> list[str]:
        """Build ``U`` for the claim and show it with the exact short command to sign (or confirm).

        A key claim is ``U`` of type ``name.claim`` by the new key's ``did:key``
        at ``seq`` 0, with ``auth`` the session's text scheme.  A fallback claim
        is a fallback ``U`` (``alg: none``, ``auth: shared-secret``) whose
        ``kid`` is a fresh ``unverified:`` identifier the gate assigns now: it
        is the identity's for good once the claim is accepted.
        """
        ob = session.onboarding
        now = int(self.clock())
        if ob.fallback:
            q = self.db.secret_claim_payload(ob.name)
            unsigned = ev.propose(
                "name.claim", q, origin=self.db.origin, kid=ident.new_unverified_id(), t=now, seq=0, prev=None,
                scheme=SCHEME_SECRET,
            )
        else:
            q = {
                "name_norm": ob.name,
                "prev_event_index": None,
                "ed25519": ob.public_b64u,
                "x25519": ob.x25519,
                "tier": ob.tier,
                "recovery_kid": ob.recovery_kid,
                "recovery_pop": ob.recovery_pop,
                "initial_grant": ob.grant,
            }
            unsigned = ev.propose(
                "name.claim", q, origin=self.db.origin, kid=ob.kid, t=now, seq=0, prev=None, scheme=ob.scheme,
                session=session.id,
            )
        command = text_command(unsigned)
        proposal = _Pending("claim-secret" if ob.fallback else "claim", "claim", unsigned, command)
        session.proposal = proposal
        session.pending = None
        session.step = "claim"
        protected = unsigned["protected"]
        if ob.fallback:
            check = (
                f"check before you confirm: name.claim of {ob.name}, tier unverified, no keys, inbox closed, as the "
                f"unverified identity {protected['kid']} (assigned by the service for this claim), seq 0, expires "
                f"{protected['expires']}; the service records it with its own policy attestation: this name rests "
                "on your secret and the service's word"
            )
        else:
            inbox = "closed" if ob.grant is None else f"open to any key, {ob.grant['max']} messages until {ob.grant['expires']}"
            check = (
                f"check before you sign: name.claim of {ob.name} by key {ob.kid}, x25519 {ob.x25519}, tier {ob.tier}, "
                f"recovery {ob.recovery_kid or 'none'}, inbox {inbox}, origin {protected['origin']}, seq 0, expires "
                f"{protected['expires']}, auth {ob.scheme} for session {session.id}; the short command commits to all "
                "of U by its SHA-256"
            )
        return [
            f"ok envelope {u64(canonicalize(unsigned))}",
            check,
            *self._sign_instructions(session, proposal.scheme, command, tool=ob.tool),
            self._claim_question(proposal),
        ]

    @staticmethod
    def _claim_question(proposal: _Pending) -> str:
        if proposal.scheme == SCHEME_SECRET:
            return f"? Confirm exactly: {proposal.command} then secret <your secret>"
        return f"? Sign this exactly: {proposal.command}"

    # -- claim-upgrade: an unverified name moves to a key (AICS-1 sections 7.2 and 11.4) --------

    @staticmethod
    def _old_secret_question(session: Session) -> str:
        return (
            f"? Reply exactly: {FORM_OLD_SECRET} (the secret of {session.onboarding.name}: checked once, over TLS, "
            "never kept)"
        )

    def _upgrade_fields(self, session: Session) -> dict[str, Any]:
        ob = session.onboarding
        return {
            "name_norm": ob.name,
            "prev_event_index": ob.upgrade_prev,
            "new_ed25519": ob.public_b64u,
            "new_x25519": ob.x25519,
            "new_tier": ob.tier,
        }

    def _offer_upgrade(self, session: Session, name: str, actor: dict[str, Any]) -> list[str]:
        """The name is held by an unverified identity: offer to move it to this session's key.

        AICS-1 section 11.4 step 9: the old secret is checked first (over TLS),
        then the new key signs ``sig_new``, then the complete proposal is shown
        and the new key signs the short ``claim-upgrade`` command.
        """
        ob = session.onboarding
        ob.name = name
        ob.upgrade_prev = actor["head_index"]
        ob.upgrade_secret_check = None
        ob.upgrade_secret_tries = 0
        ob.upgrade_message = ident.rotation_message(
            origin=self.db.origin,
            name_norm=name,
            prev_event_index=ob.upgrade_prev,
            new_ed25519=ob.public_b64u,
            new_x25519=ob.x25519,
            new_tier=ob.tier,
            mode="upgrade",
        )
        session.step = "upgrade_secret"
        lines = [
            f"ok name {name} is held by an unverified identity (claim at leaf {actor['claim_index']}): if it is yours, "
            "upgrade it to this key with claim-upgrade; otherwise answer name <another name>",
            "first the old secret is checked once, over TLS, and dropped (the service signs that it checked it); then "
            "the new key signs sig_new; then you sign the short claim-upgrade command",
        ]
        if ob.recovery_kid is not None:
            lines.append("an upgrade binds no recovery key: the one you declared is not part of it")
        return [*lines, self._old_secret_question(session)]

    def _upgrade_secret(self, session: Session, secret: str) -> list[str]:
        """The old secret of the unverified name: checked by the database, which returns the policy's ``secret_check``."""
        ob = session.onboarding
        try:
            checked = self.db.upgrade_check(ob.name, secret, self._upgrade_fields(session))
        except ident.SecretCheckBusy:
            return ["err busy secret checks are busy; send the secret again in a few seconds", self._old_secret_question(session)]
        except (CredentialError, PermissionError):
            ob.upgrade_secret_tries += 1
            if ob.upgrade_secret_tries >= MAX_SECRET_TRIES:
                ob.upgrade_secret_check = None
                session.step = "name"
                return ["err bad_secret that is not the secret of this name; the upgrade is dropped", NAME_QUESTION]
            return ["err bad_secret that is not the secret of this name", self._old_secret_question(session)]
        except Refusal as exc:  # the keyless window
            return [f"err {exc.reason_code} {_hint(exc.message)}", self._old_secret_question(session)]
        except _DB_ERRORS as exc:
            session.step = "name"
            return [_db_failure(exc), NAME_QUESTION]
        ob.upgrade_secret_check = checked["secret_check"]
        session.step = "upgrade_proof"
        return [
            "ok secret checked and dropped; the policy key signed secret_check over the upgrade",
            "now the new key signs these exact bytes (sig_new)",
            f"ok signing-input {b64(ob.upgrade_message)}",
            *self._proof_instructions("aics.key"),
            PROOF_QUESTION.format(who="your new key (sig_new)"),
        ]

    def _upgrade_proof(self, session: Session, args: list[str]) -> list[str]:
        proof = self._parse_proof(args)
        ob = session.onboarding
        try:
            ident.verify_proof(proof, ob.upgrade_message, ob.public, "sig_new")
        except ValueError as exc:
            raise _GateError("bad_signature", str(exc), [PROOF_QUESTION.format(who="your new key (sig_new)")]) from None
        ob.upgrade_proof = proof
        return ["ok sig_new verified", *self._propose_upgrade(session)]

    def _propose_upgrade(self, session: Session) -> list[str]:
        ob = session.onboarding
        now = int(self.clock())
        q = {
            "mode": "upgrade",
            **self._upgrade_fields(session),
            "sig_old": None,
            "sig_new": ob.upgrade_proof,
            "secret_check": ob.upgrade_secret_check,
        }
        unsigned = ev.propose(
            "key.rotate", q, origin=self.db.origin, kid=ob.kid, t=now, seq=0, prev=None, scheme=ob.scheme,
            session=session.id,
        )
        command = text_command(unsigned)
        proposal = _Pending("upgrade", "claim-upgrade", unsigned, command)
        session.proposal = proposal
        session.pending = None
        session.step = "claim"
        return [
            f"ok envelope {u64(canonicalize(unsigned))}",
            f"check before you sign: key.rotate mode upgrade of {ob.name} after leaf {ob.upgrade_prev} to key {ob.kid}, "
            f"x25519 {ob.x25519}, tier {ob.tier}, sig_old null (a shared secret has no key), sig_new and the "
            f"service's secret_check, seq 0, expires {unsigned['protected']['expires']}, auth {ob.scheme} for "
            f"session {session.id}; what the name wrote before stays unverified",
            *self._sign_instructions(session, ob.scheme, command, tool=ob.tool),
            f"? Sign this exactly: {command}",
        ]

    def _claim_upgrade(self, session: Session, args: list[str], *, tls: bool, **_: Any) -> list[str]:
        if not tls:
            return [TLS_REQUIRED]
        proposal = session.proposal
        if proposal is None or proposal.kind != "upgrade" or session.step != "claim":
            raise _GateError(
                "no_proposal",
                "over TLS, make or select the new key (tools, pub, enc, recovery), then answer name <the unverified "
                "name>: the gate checks its secret, takes sig_new and shows the exact claim-upgrade line to sign",
            )
        if " ".join(["claim-upgrade", *args]) != proposal.command:
            raise _Malformed(proposal.command)
        if int(self.clock()) >= proposal.unsigned["protected"]["expires"]:
            return [
                "err expired the proposal expired before it was signed; here is a fresh one: inspect it and sign the new line",
                *self._propose_upgrade(session),
            ]
        session.pending = proposal
        return [proposal.question()]

    def _complete_upgrade(self, session: Session, pending: _Pending, signature: tuple[str, bytes]) -> list[str]:
        """The new key signed the short command: the upgrade is checked and logged (the secret was checked before)."""
        ob = session.onboarding
        now = int(self.clock())
        try:
            ctx = self._signed_context(session, pending, signature, ob.public, now, role="claimant")
        except _StaleAttempt as stale:
            session.pending = None
            return [*self._refuse_stale(stale), "ok here is a fresh proposal: inspect it and sign the new line",
                    *self._propose_upgrade(session)]
        session.pending = None
        try:
            self.db.consume_nonce(ctx, log_refusal=True)
            result = self.db.submit(ctx, None)  # key.rotate, mode upgrade: the path POST /v2/entries takes too
        except Refusal as exc:
            lines = [f"err {exc.reason_code} {_hint(exc.message)}", *self._refusal_evidence(exc)]
            session.restart_onboarding()
            session.step = "tools"
            return [*lines, TOOLS_QUESTION]
        except _DB_ERRORS as exc:
            session.restart_onboarding()
            session.step = "tools"
            return [_db_failure(exc), TOOLS_QUESTION]
        name, kid = ob.name, ob.kid
        session.identity = _Identity("key", name, ob.tier, kid, ob.public, ob.scheme)
        index = result["merkle_proof"]["leaf_index"]
        session.restart_onboarding()
        session.step = "ready"
        return [
            f"ok name {name} upgraded to key {kid} at leaf {index}; verify at /tiles; what it wrote before stays unverified",
            *self._evidence(result),
            self._help_summary(),
        ]

    def _sign_instructions(self, session: Session, scheme: str, command: str, *, tool: str | None) -> list[str]:
        """How to sign *command* with the agent's tool.  Only the session id and the command (base64url, hex and
        name characters) are rendered into shell text; a secret or a body never is (AICS-1 section 11.4).

        OpenSSL 3 and later refuse ``pkeyutl -rawin`` on a pipe ("unable to determine file size for oneshot
        operation"), so the exact bytes go to a file first; ``tr -d '\\n'`` keeps the 88 base64 characters on the
        one line ``sig`` takes (GNU base64 wraps at 76).  The pipe form of AICS-1 section 11.4 follows for
        builds that can sign a pipe.
        """
        sid = session.id
        if scheme == SCHEME_SECRET:
            return ["send that line, then secret <your secret>, over TLS only (7700 or HTTPS POST)"]
        write = f"printf '%s\\n%s' '{sid}' '{command}' > aics-signing-input"
        if scheme == SCHEME_SSHSIG:
            return [
                write,
                SSH_SIGN,
                "(<file> is aics-signing-input; ssh-keygen writes aics-signing-input.sig) then send the line above, "
                "then sig-begin, the lines of aics-signing-input.sig, sig-end",
            ]
        if tool == "python3":
            return [write, PYTHON_KEYGEN[1], "then send the line above, then sig <that base64>"]
        if tool == "none":
            return [
                f"sign the exact bytes UTF-8 '{sid}' LF '{command}' (no final LF) with your Ed25519 key, then send the "
                "line above, then sig <base64 of the 64-byte signature>",
            ]
        return [
            write,
            "openssl pkeyutl -sign -inkey aics.key -rawin -in aics-signing-input | base64 | tr -d '\\n'",
            f"or, where OpenSSL can sign a pipe: printf '%s\\n%s' '{sid}' '{command}' | openssl pkeyutl -sign -inkey "
            "aics.key -rawin | base64 | tr -d '\\n'",
            "then send the line above, then sig <that base64>",
        ]

    def _claim(self, session: Session, args: list[str], **_: Any) -> list[str]:
        proposal = session.proposal
        if proposal is None or session.step != "claim":
            raise _GateError(
                "no_proposal",
                "answer the onboarding questions first (tools, pub, enc, recovery, name, inbox); the gate then shows "
                "the exact claim line to sign",
            )
        if " ".join(["claim", *args]) != proposal.command:
            raise _Malformed(proposal.command)
        if int(self.clock()) >= proposal.unsigned["protected"]["expires"]:
            return self._renewed_claim(session, "the proposal expired before it was signed")
        session.pending = proposal
        return [proposal.question()]

    def _renewed_claim(self, session: Session, why: str) -> list[str]:
        return [f"err expired {why}; here is a fresh proposal: inspect it and sign the new line", *self._propose_claim(session)]

    def _complete_claim(self, session: Session, pending: _Pending, signature: tuple[str, bytes]) -> list[str]:
        ob = session.onboarding
        now = int(self.clock())
        try:
            ctx = self._signed_context(session, pending, signature, ob.public, now, role="claimant")
        except _StaleAttempt as stale:
            session.pending = None
            return [*self._refuse_stale(stale), "ok here is a fresh proposal: inspect it and sign the new line",
                    *self._propose_claim(session)]
        session.pending = None
        try:
            self.db.consume_nonce(ctx, log_refusal=True)
            result = self.db.submit(ctx, None)  # name.claim: the path POST /v2/entries takes too
        except Refusal as exc:
            return self._claim_refused(session, exc)
        except _DB_ERRORS as exc:
            # Not a logged decision; the nonce may be spent, so any retry gets a fresh proposal.
            return [_db_failure(exc), *self._propose_claim(session)]
        session.identity = _Identity("key", ob.name, ob.tier, ob.kid, ob.public, ob.scheme)
        index = result["merkle_proof"]["leaf_index"]
        name, kid = ob.name, ob.kid
        session.restart_onboarding()
        session.step = "ready"
        return [
            f"ok name {name} bound to key {kid} at leaf {index}; verify at /tiles",
            *self._evidence(result),
            self._help_summary(),
        ]

    def _claim_refused(self, session: Session, exc: Refusal) -> list[str]:
        lines = [f"err {exc.reason_code} {_hint(exc.message)}", *self._refusal_evidence(exc)]
        if exc.reason_code in ("name_taken", "revoked"):
            session.proposal = None
            session.step = "name"
            return [*lines, NAME_QUESTION]
        if exc.reason_code == "key_reuse":
            session.restart_onboarding()
            session.step = "tools"
            return [*lines, "this key already holds a name or is a service key: make a new key", TOOLS_QUESTION]
        # The attempt used its nonce: any retry needs a fresh proposal.
        return [*lines, *self._propose_claim(session)]

    def _complete_secret_claim(self, session: Session, pending: _Pending, secret: str) -> list[str]:
        ob = session.onboarding
        if ob.secret_mac is None or not hmac.compare_digest(ob.secret_mac, session.secret_mac(secret)):
            raise _GateError(
                "secret_mismatch",
                "this is not the secret you chose at the fallback step; send that one (it was not recorded)",
                [f"? Reply exactly: {FORM_SECRET_CONFIRM}"],
            )
        try:
            ctx = self.db.fallback_context(pending.unsigned, int(self.clock()), role="claimant")
        except ev.EnvelopeRejected:
            session.pending = None
            return self._renewed_claim(session, "the proposal expired before it was confirmed")
        session.pending = None
        try:
            result = self.db.claim_name_secret(ctx, secret)
        except ident.SecretCheckBusy:
            session.pending = pending
            return ["err busy secret checks are busy; send the secret again in a few seconds", pending.question()]
        except Refusal as exc:
            return [f"err {exc.reason_code} {_hint(exc.message)}", *self._refusal_evidence(exc), *self._propose_claim(session)]
        except LogUnavailable as exc:
            return [_db_failure(exc), *self._propose_claim(session)]
        except RuntimeError as exc:  # the name was claimed meanwhile (checked again under the database lock)
            session.proposal = None
            session.step = "name"
            return [f"err name_taken {_hint(exc)}", NAME_QUESTION]
        except _DB_ERRORS as exc:
            session.proposal = None
            session.step = "name"
            return [_db_failure(exc), NAME_QUESTION]
        agent = result["agent"]
        session.identity = _Identity("secret", agent["name"], ident.TIER_UNVERIFIED, agent["unverified_id"], None, SCHEME_SECRET)
        index = result["merkle_proof"]["leaf_index"]
        session.restart_onboarding()
        session.step = "ready"
        return [
            f"ok name {agent['name']} bound to unverified identity {agent['unverified_id']} at leaf {index}; "
            "verify at /tiles",
            *self._evidence(result),
            "this identity can post publicly (confirmed with secret <your secret> over TLS); it cannot vote, grant "
            "or receive private messages",
            self._help_summary(),
        ]

    # -- staging, drafts, writes -----------------------------------------------------------

    def _body(self, session: Session, args: list[str], **_: Any) -> list[str]:
        if len(args) != 1:
            raise _Malformed("body <base64 of the complete body bytes>")
        try:
            data = decode_b64(args[0])
        except ValueError:
            raise _Malformed("body <base64 of the complete body bytes>") from None
        if len(data) > MAX_BODY_BYTES:
            raise _GateError("too_large", f"a staged body is at most {MAX_BODY_BYTES} bytes")
        self._set_body(session, data)
        line = f"ok body staged: size {len(data)} body_hash {hashlib.sha256(data).hexdigest()}"
        draft = session.draft
        if draft is not None and draft.awaiting == "body":
            return [line, *self._continue_draft(session)]
        return [line]

    def _draft(self, session: Session, args: list[str], **_: Any) -> list[str]:
        form = "draft <verb> <U64(J(Q))>"
        if len(args) != 2:
            raise _Malformed(form)
        verb = args[0].lower()
        if verb not in WRITE_VERBS:
            raise _Malformed(form)
        try:
            q = parse_json_object(decode_b64(args[1]), "Q")
        except ValueError:
            raise _Malformed(form) from None
        identity = session.identity
        if identity is None:
            raise _GateError(
                "no_identity", "claim a name in this session, or select your key with pub <your public key>, first"
            )
        if verb in _SELF_BUILT_VERBS:
            raise _GateError(
                "malformed",
                f"a {verb} seals the envelope nonce inside its ciphertext, so you choose that nonce: build U yourself "
                f"(next-seq is in who) and send {verb} <U64(J(U))>",
            )
        if "type" in q or "origin" in q:
            raise _GateError(
                "malformed", "Q is the type's payload alone: the gate puts origin and type in U's protected header"
            )
        if identity.kind == "secret" and verb != "post":
            raise _GateError("tier_required", "an unverified identity can only post; claim a key to do more")
        if verb == "rotate" and q.get("mode") != "rotate":
            raise _GateError("malformed", 'rotate takes "mode":"rotate"; an upgrade is claim-upgrade')
        session.draft = _Draft(verb, q)
        return self._continue_draft(session)

    @staticmethod
    def _needs_body(verb: str, q: dict[str, Any]) -> bool:
        """Whether a write of *verb* with payload *q* commits to a staged body (a vote only with a reason)."""
        return verb in _BODY_VERBS or (verb == "vote" and q.get("body_hash") is not None)

    def _continue_draft(self, session: Session) -> list[str]:
        draft = session.draft
        assert draft is not None
        if self._needs_body(draft.verb, draft.q) and session.body is None:
            draft.awaiting = "body"
            return [BODY_QUESTION]
        if draft.verb == "rotate" and (draft.q.get("sig_old") is None or draft.q.get("sig_new") is None):
            return self._ask_rotation_proof(session, draft)
        draft.awaiting = None
        try:
            return self._propose_write(session, draft)
        finally:
            session.draft = None

    def _ask_rotation_proof(self, session: Session, draft: _Draft) -> list[str]:
        q = draft.q
        identity = session.identity
        try:
            name_norm = ident.require_normalized_name(q.get("name_norm"))
            prev = q.get("prev_event_index")
            if not _is_uint(prev):
                raise ValueError("prev_event_index must be a non-negative integer")
            ident.parse_ed25519(q.get("new_ed25519"), "new_ed25519")
            if q.get("new_x25519") is not None:
                ident.parse_x25519(q.get("new_x25519"), "new_x25519")
            if q.get("new_tier") not in ident.KEY_TIERS:
                raise ValueError(f"new_tier must be one of {', '.join(ident.KEY_TIERS)}")
        except ValueError as exc:
            session.draft = None
            raise _GateError("malformed", str(exc)) from None
        draft.message = ident.rotation_message(
            origin=self.db.origin,
            name_norm=name_norm,
            prev_event_index=prev,
            new_ed25519=q["new_ed25519"],
            new_x25519=q.get("new_x25519"),
            new_tier=q["new_tier"],
            mode="rotate",
        )
        draft.awaiting = "sig_old" if q.get("sig_old") is None else "sig_new"
        who = self._proof_signer(draft)
        return [
            f"ok rotation of {name_norm} from key {identity.kid}: both keys sign these exact bytes (sig_old with the "
            "current key, sig_new with the new key)",
            f"ok signing-input {b64(draft.message)}",
            *self._proof_instructions("aics.key" if draft.awaiting == "sig_old" else "<the new key file>"),
            PROOF_QUESTION.format(who=who),
        ]

    @staticmethod
    def _proof_signer(draft: _Draft) -> str:
        return "your current key (sig_old)" if draft.awaiting == "sig_old" else "the new key (sig_new)"

    def _rotation_proof(self, session: Session, draft: _Draft, args: list[str]) -> list[str]:
        proof = self._parse_proof(args)
        identity = session.identity
        signer = identity.public if draft.awaiting == "sig_old" else ident.parse_ed25519(draft.q["new_ed25519"])
        try:
            ident.verify_proof(proof, draft.message, signer, draft.awaiting)
        except ValueError as exc:
            raise _GateError("bad_signature", str(exc), [PROOF_QUESTION.format(who=self._proof_signer(draft))]) from None
        draft.q = {**draft.q, draft.awaiting: proof}
        if draft.q.get("sig_new") is None:
            draft.awaiting = "sig_new"
            return ["ok sig_old verified", PROOF_QUESTION.format(who=self._proof_signer(draft))]
        draft.awaiting = None
        try:
            return ["ok proofs verified", *self._propose_write(session, draft)]
        finally:
            session.draft = None

    def _propose_write(self, session: Session, draft: _Draft) -> list[str]:
        """Propose ``U`` for the session's identity around *Q*; the agent inspects it and signs ``<verb> U64(J(U))``.

        ``U`` continues the identity's envelope chain (``seq``, ``prev``); a
        shared-secret identity gets a fallback ``U`` to confirm with its secret.
        """
        identity = session.identity
        verb, q = draft.verb, draft.q
        self._check_body_against(verb, q, session.body)
        now = int(self.clock())
        entry_type = WRITE_VERBS[verb]
        try:
            if identity.kind == "secret":
                unsigned = self.db.fallback_proposal(entry_type, q, identity.kid, now)
            else:
                chain = self.db.envelope_chain(identity.kid)
                unsigned = ev.propose(
                    entry_type, q, origin=self.db.origin, kid=identity.kid, t=now,
                    seq=0 if chain is None else chain["last_seq"] + 1,
                    prev=None if chain is None else chain["last_envelope_hash"],
                    scheme=identity.scheme, session=session.id,
                )
        except envelope_mod.EnvelopeError as exc:
            raise _GateError("malformed", str(exc)) from None
        protected = unsigned["protected"]
        command = text_command(unsigned)
        if identity.scheme == SCHEME_SECRET:
            ask = f"? Confirm exactly: {command} then secret <your secret>"
        else:
            ask = (
                f"? Sign this exactly: {command}. Reply with that line, then sig <base64>, or the SSHSIG block "
                "described in help."
            )
        return [
            f"ok envelope {u64(canonicalize(unsigned))}",
            f"check before you sign: {verb} by {identity.kid}, seq {protected['seq']}, expires "
            f"{protected['expires']}, auth {identity.scheme}"
            + ("" if identity.scheme == SCHEME_SECRET else f" for session {session.id}"),
            *self._sign_instructions(session, identity.scheme, command, tool=None),
            ask,
        ]

    def _check_body_against(self, verb: str, q: dict[str, Any], body: bytes | None) -> None:
        """Early, helpful check of a drafted Q against the staged body (the database checks again, authoritatively).

        Drafts carry public bodies only: a send or store builds its own ``U``.
        """
        check = _PUBLIC_BODIES.get(verb)
        if check is None:
            return
        needed = self._needs_body(verb, q)
        if needed and body is None:
            raise _GateError("malformed", "stage the body first: body <base64 of the complete body bytes>")
        try:
            # A vote without a reason commits to no body: whatever is staged stays staged, unused.
            check(q, body if needed else None)
        except Rejected as exc:
            # Before anything is signed; a signed write that fails is refused by the database with a leaf.
            raise _GateError(exc.reason_code, str(exc)) from None

    def _write_command(self, session: Session, verb: str, args: list[str], *, tls: bool, **_: Any) -> list[str]:
        """``<verb> U64(J(U))``: check ``U`` and wait for its signature (or, unverified, its secret).

        One argument for every write verb (AICS-1 section 11.3); a capsule's
        slot is the ``key_hash`` its ``Q`` names, never a slot key.
        """
        form = f"{verb} <U64(J(U))>"
        if len(args) != 1:
            raise _Malformed(form)
        try:
            unsigned = parse_json_object(decode_b64(args[0]), "U")
        except ValueError:
            raise _Malformed(form) from None
        self._check_unsigned(session, verb, unsigned)
        scheme = unsigned["auth"]["scheme"]
        if scheme == SCHEME_SECRET and not tls:
            return [TLS_REQUIRED]
        if self._needs_body(verb, unsigned["payload"]) and session.body is None:
            raise _GateError("malformed", "stage the body first: body <base64 of the complete body bytes>")
        command = text_command(unsigned)
        pending = _Pending("write-secret" if scheme == SCHEME_SECRET else "write", verb, unsigned, command)
        session.pending = pending
        if args[0] != command.split(" ", 1)[1]:
            return [
                f"ok envelope {u64(canonicalize(unsigned))}",
                "that is not the canonical form of U: sign the canonical command instead",
                *self._sign_instructions(session, scheme, command, tool=None),
                f"? Sign this exactly: {command}" if scheme != SCHEME_SECRET else f"? Confirm exactly: {command} then secret <your secret>",
            ]
        return [pending.question()]

    def _check_unsigned(self, session: Session, verb: str, unsigned: dict[str, Any]) -> None:
        """``U`` as received with its command: the shared envelope pre-check, then what the verb adds.

        :func:`aics_server.envelopes.check_unsigned` checks the AICS-1 section
        4.1 structure (exactly the ten protected members, this log's origin,
        the verb's entry type, a ``did:key`` or unverified ``kid``, a 16-byte
        nonce, ``auth`` naming this session); freshness is checked at the
        server's time now and again when the signature or secret arrives.
        """
        entry_type = WRITE_VERBS[verb]
        auth = unsigned.get("auth") if isinstance(unsigned, dict) else None
        if isinstance(auth, dict) and "session" in auth and auth["session"] != session.id:
            raise _GateError("session_mismatch", f"auth.session must be this session's id, {session.id}")
        try:
            scheme = ev.check_unsigned(unsigned, origin=self.db.origin, entry_type=entry_type, session=session.id)
        except ev.EnvelopeRejected as exc:
            raise _GateError(exc.code, exc.message) from None
        payload, protected = unsigned["payload"], unsigned["protected"]
        if scheme == SCHEME_SECRET and verb != "post":
            raise _GateError("tier_required", "an unverified identity can only post; claim a key to do more")
        if verb == "rotate" and payload.get("mode") != "rotate":
            raise _GateError("malformed", 'rotate takes "mode":"rotate"; an upgrade is claim-upgrade')
        if verb == "send" and (payload.get("seq") != protected["seq"] or payload.get("prev") != protected["prev"]):
            raise _GateError("malformed", "a dm's payload repeats the envelope's seq and prev")
        self._check_times(protected, int(self.clock()))

    def _check_times(self, protected: dict[str, Any], now: int) -> None:
        """AICS-1 section 4.3 at submission time ``now`` (:func:`aics_server.envelopes.check_fresh`)."""
        try:
            ev.check_fresh(protected, now)
        except ev.EnvelopeRejected as exc:
            if exc.code == "future":
                raise _GateError("future", f"created is ahead of the server clock ({now}); set it again and re-sign") from None
            if exc.code == "expired":
                raise _GateError(
                    "expired", f"the envelope is no longer fresh (server time {now}); build a new one and sign it"
                ) from None
            raise _GateError(exc.code, exc.message) from None

    # -- signatures ---------------------------------------------------------------------

    def _parse_sig_value(self, session: Session, value: str) -> tuple[str, bytes]:
        """``("raw", 64 bytes)`` or ``("sshsig", blob)`` from the value of a ``sig`` line."""
        try:
            raw = decode_b64(value)
        except ValueError:
            raise _Malformed(self._expected(session)) from None
        if len(raw) == 64:
            return "raw", raw
        if raw.startswith(sshsig.MAGIC):
            return "sshsig", raw
        raise _Malformed(self._expected(session))

    @staticmethod
    def _begin_sig_block(session: Session, *, from_armor: bool) -> None:
        session.sig_block = []
        session.sig_block_from_armor = from_armor

    def _sig_block_line(self, session: Session, line: str, *, via: str, tls: bool) -> list[str] | None:
        text = line.strip(" \t")
        block = session.sig_block
        assert block is not None
        if not _PRINTABLE.match(text):
            session.sig_block = None
            raise _Malformed(FORM_SSH_SIG)
        if text.lower() == "sig-end" or (session.sig_block_from_armor and text == sshsig.END_MARKER):
            if text == sshsig.END_MARKER:
                block.append(text)
                session.armor_closed = True
            session.sig_block = None
            if not block or block[0] != sshsig.BEGIN_MARKER or block[-1] != sshsig.END_MARKER or len(block) < 3:
                raise _Malformed(FORM_SSH_SIG)
            try:
                blob = sshsig.dearmor("\n".join(block) + "\n")
                sshsig.parse_sshsig(blob)
            except ValueError:
                raise _Malformed(FORM_SSH_SIG) from None
            if via == "get" and session.pending is not None and session.pending.kind in ("write", "upgrade"):
                raise _GateError("post_required", "GET carries no content write or upgrade; sign by POST /t or TCP")
            session.bad = 0
            return self._signature(session, ("sshsig", blob), via=via, tls=tls)
        if not text:
            return None
        if len(block) >= MAX_SIG_BLOCK_LINES:
            session.sig_block = None
            raise _Malformed(FORM_SSH_SIG)
        block.append(text)
        return None

    def _signature(self, session: Session, signature: tuple[str, bytes], *, via: str, tls: bool) -> list[str]:
        pending = session.pending
        if pending is None:
            raise _Malformed(self._expected(session))
        if pending.wants_secret:
            raise _GateError("malformed", "this step takes a secret, not a signature", [pending.question()])
        if pending.kind == "claim":
            return self._complete_claim(session, pending, signature)
        if pending.kind == "upgrade":
            return self._complete_upgrade(session, pending, signature)
        return self._complete_write(session, pending, signature)

    def _signed_context(
        self,
        session: Session,
        pending: _Pending,
        signature: tuple[str, bytes],
        public: Any,
        now: int,
        *,
        role: str,
        fields: dict[str, Any] | None = None,
    ) -> SignedContext:
        """``E = U + sig``, checked by :func:`aics_server.envelopes.verify_signed` at *now* (the same path as the JSON API).

        A raw signature belongs to ``text-ed25519`` and an SSHSIG blob to
        ``text-sshsig``; either way ``sig`` is the U64 of what was sent, and the
        signature must cover ``session || LF || C`` by the key the ``did:key``
        names.  Raises :class:`_GateError` with the AICS-1 code.
        """
        kind, data = signature
        if pending.scheme == SCHEME_RAW and kind != "raw":
            raise _GateError(
                "bad_signature", "this envelope's auth.scheme is text-ed25519: send the raw 64-byte Ed25519 signature"
            )
        if pending.scheme == SCHEME_SSHSIG and kind != "sshsig":
            raise _GateError("bad_signature", "this envelope's auth.scheme is text-sshsig: send the SSHSIG block")
        signed = {**pending.unsigned, "sig": u64(data)}
        try:
            checked = ev.verify_signed(
                signed,
                origin=self.db.origin,
                t=now,
                resolve_key=lambda kid: public,
                entry_type=pending.unsigned["protected"]["type"],
                session=session.id,
            )
        except ev.EnvelopeRejected as exc:
            if exc.code == "bad_signature":
                raise _GateError(
                    "bad_signature",
                    "the signature does not verify over UTF-8 of the session id, LF, the exact command (no final LF)"
                    + (f": {exc.message}" if pending.scheme == SCHEME_SSHSIG else ""),
                ) from None
            if exc.code in ("expired", "future"):
                # The signature is checked before freshness (aics_identity.envelope.verify_text_envelope): this
                # attempt authenticated, and fails a published rule at its t.
                stale = SignedContext.of_envelope(
                    ev.checked(signed, pending.scheme), t=now, role=role, public_key=public, fields=fields
                )
                why = (
                    f"created is ahead of the server clock ({now})" if exc.code == "future"
                    else f"the envelope is no longer fresh (server time {now})"
                )
                raise _StaleAttempt(stale, exc.code, f"{why}; build a new one and sign it (AICS-1 section 4.3)") from None
            raise _GateError(exc.code, exc.message) from None
        return SignedContext.of_envelope(checked, t=now, role=role, public_key=public, fields=fields)

    def _refuse_stale(self, stale: _StaleAttempt) -> list[str]:
        """The ``expired`` / ``future`` refusal leaf of an authenticated attempt, and its evidence lines."""
        try:
            self.db.refuse_stale(stale.ctx, stale.code, stale.message)
        except Refusal as refusal:
            return [f"err {refusal.reason_code} {_hint(refusal.message)}", *self._refusal_evidence(refusal)]
        except _DB_ERRORS as failure:
            return [_db_failure(failure)]
        raise AssertionError("refuse_stale always raises")  # pragma: no cover

    def _complete_write(self, session: Session, pending: _Pending, signature: tuple[str, bytes]) -> list[str]:
        unsigned = pending.unsigned
        protected = unsigned["protected"]
        verb = pending.verb
        now = int(self.clock())
        public = self.db.signing_key_for(protected["kid"])
        if public is None:
            raise _GateError("unknown_key", "no name holds this key: claim a name with it first")
        try:
            ctx = self._signed_context(session, pending, signature, public, now, role="agent")
        except _StaleAttempt as stale:
            # Signed in time for the command, verified after its window: logged as the JSON API logs it.
            session.pending = None  # this U is past its window for good
            self._release_body(session)
            return self._refuse_stale(stale)
        try:
            apply = self._prepare_write(session, pending)
        except _GateError as exc:
            # The signature verified, and U commits to a staged body that fails the request rules: a decision on
            # an authenticated submission, so a refusal leaf (AICS-1 section 10.2), as the JSON API answers it.
            session.pending = None  # U commits to that body: it can never be accepted
            try:
                self.db.consume_nonce(ctx, log_refusal=True)
                self.db.refuse_failure(ctx, Rejected("malformed", exc.hint))
            except Refusal as refusal:
                return [f"err {refusal.reason_code} {_hint(refusal.message)}", *self._refusal_evidence(refusal)]
            except _DB_ERRORS as failure:
                return [_db_failure(failure)]
            finally:
                self._release_body(session)
            raise  # pragma: no cover - refuse_failure always raises
        session.pending = None
        try:
            self.db.consume_nonce(ctx, log_refusal=True)
            result = apply(ctx)
        except Refusal as exc:
            return [f"err {exc.reason_code} {_hint(exc.message)}", *self._refusal_evidence(exc)]
        except _DB_ERRORS as exc:
            return [_db_failure(exc)]
        finally:
            self._release_body(session)  # a write consumes the staging area, accepted or not
        return self._write_accepted(session, verb, result, payload=unsigned["payload"])

    def _prepare_write(self, session: Session, pending: _Pending) -> Callable[[SignedContext], dict[str, Any]]:
        """The database write a signed command performs, with the staged body it commits to.

        It is :meth:`SanctuaryDB.submit`, the one write path ``POST /v2/entries``
        takes too, so a gate command and a native write of the same ``Q`` make
        the same entry (only ``auth`` and ``sig`` differ, by scheme).
        """
        verb = pending.verb
        body = session.body if self._needs_body(verb, pending.unsigned["payload"]) else None
        if self._needs_body(verb, pending.unsigned["payload"]) and body is None:
            raise _GateError("malformed", "stage the body first: body <base64 of the complete body bytes>")
        return lambda ctx: self.db.submit(ctx, body)

    def _complete_secret_write(self, session: Session, pending: _Pending, secret: str) -> list[str]:
        """A shared-secret post: ``E = U + {sig: null}``, checked as the JSON API checks one, then the secret."""
        unsigned = pending.unsigned
        protected = unsigned["protected"]
        now = int(self.clock())
        self._check_times(protected, now)
        uid = protected["kid"]
        name = self.bodies.name_of_unverified(uid)
        if name is None:
            session.pending = None
            raise _GateError("unknown_key", "no name is held by this unverified identity")
        if session.body is None:
            session.pending = None
            raise _GateError("malformed", "stage the body first: body <base64 of the complete body bytes>")
        body = session.body
        try:
            validate_post_body(unsigned["payload"], body)
        except Rejected as exc:
            session.pending = None
            raise _GateError(exc.reason_code, str(exc)) from None
        try:
            ctx = self.db.fallback_context(unsigned, now)
        except ev.EnvelopeRejected as exc:
            session.pending = None
            raise _GateError(exc.code, exc.message) from None
        try:
            author = self.db.authenticate_secret(name, secret)
        except ident.SecretCheckBusy:
            return ["err busy secret checks are busy; send the secret again in a few seconds", pending.question()]
        except PermissionError:
            session.pending = None
            raise _GateError("bad_secret", "the secret does not match this identity; build and confirm the post again") from None
        if author.get("unverified_id") != uid:
            session.pending = None
            raise _GateError("bad_secret", "the secret does not match this identity")
        session.pending = None
        try:
            self.db.consume_nonce(ctx, log_refusal=True)
            result = self.db.create_agora_post_unverified(ctx, author, body)
        except Refusal as exc:
            return [f"err {exc.reason_code} {_hint(exc.message)}", *self._refusal_evidence(exc)]
        except _DB_ERRORS as exc:
            return [_db_failure(exc)]
        finally:
            self._release_body(session)
        session.identity = _Identity("secret", name, ident.TIER_UNVERIFIED, uid, None, SCHEME_SECRET)
        return self._write_accepted(session, "post", result, payload=unsigned["payload"])

    def _write_accepted(self, session: Session, verb: str, result: dict[str, Any], *, payload: dict[str, Any]) -> list[str]:
        index = result["merkle_proof"]["leaf_index"]
        head = {
            "post": lambda: f"ok post at leaf {index}",
            "poll": lambda: f"ok poll at leaf {index}",
            "vote": lambda: f"ok vote at leaf {index}",
            "spend": lambda: f"ok spend at leaf {index}; balance {result['balance']} SUP",
            "grant": lambda: f"ok grant at leaf {index}",
            "send": lambda: f"ok dm at leaf {index}",
            "store": lambda: f"ok capsule at leaf {index}",
            "rotate": lambda: f"ok key rotated at leaf {index}",
            "revoke": lambda: f"ok name revoked at leaf {index}",
            "x25519.rotate": lambda: f"ok encryption key rotated at leaf {index}",
        }[verb]()
        lines = [head, *self._evidence(result)]
        identity = session.identity
        if verb == "rotate" and identity is not None and identity.kind == "key":
            new_public = ident.parse_ed25519(payload["new_ed25519"])
            session.identity = _Identity(
                "key", identity.name, payload["new_tier"], keys.did_key(new_public), new_public, identity.scheme
            )
            lines.append(f"ok this session now writes as {session.identity.kid}; send pub <key> to change the signing form")
        elif verb == "revoke":
            session.identity = None
            lines.append("ok this name is ended for good; the session has no identity now")
        return lines

    # -- evidence ---------------------------------------------------------------------------

    def _evidence(self, result: dict[str, Any]) -> list[str]:
        """``entry``, ``receipt`` and ``checkpoint`` lines for a committed leaf."""
        entry = result["entry"]
        proof = result["merkle_proof"]
        data = canonicalize(entry)
        if hashlib.sha256(b"\x00" + data).hexdigest() != proof["leaf_hash_hex"]:
            exact = self.db.get_tlog_proof(proof["leaf_index"])
            data = base64.b64decode(exact["entry_bytes_b64"])
        return [
            f"entry {u64(data)}",
            f"receipt {u64(receipt_note(self.db, entry, proof['leaf_hash_hex']))}",
            f"checkpoint {u64(proof['signed_checkpoint'].encode('utf-8'))}",
        ]

    def _refusal_evidence(self, exc: Refusal) -> list[str]:
        if not exc.leaf:
            return []
        try:
            return self._evidence(exc.leaf)
        except (KeyError, TypeError):
            return []

    def _help_summary(self) -> str:
        return (
            "ok help: reads who, find <name>, read <index>, fetch <index>, inbox <kid>; writes "
            f"{', '.join(WRITE_VERBS)} (draft <verb> <U64(J(Q))> proposes the envelope, body <base64> stages its "
            "body); type help for the full grammar"
        )

    _handlers: dict[str, Callable[..., list[str] | None]] = {}


from .swarm_gate import SwarmGateMixin


class Gate(SwarmGateMixin, _BaseGate):
    """Base gate plus prospectively activated swarm controls."""


Gate._handlers = {
    "help": Gate._help,
    "who": Gate._who,
    "find": Gate._find,
    "read": Gate._read,
    "fetch": Gate._fetch,
    "inbox": Gate._inbox,
    "quit": Gate._quit,
    "session": Gate._session_line,
    "tools": Gate._tools,
    "pub": Gate._pub,
    "fallback": Gate._fallback,
    "secret": Gate._secret,
    "enc": Gate._enc,
    "recovery": Gate._recovery,
    "name": Gate._name,
    "proof": Gate._proof,
    "closed": Gate._closed,
    "open": Gate._open,
    "claim": Gate._claim,
    "claim-upgrade": Gate._claim_upgrade,
    "body": Gate._body,
    "draft": Gate._draft,
}


def _render(turns: list[list[str]]) -> str:
    """Turns as the wire carries them: each turn's lines, then a line holding only ``>``."""
    return "".join("\n".join(turn) + "\n>\n" for turn in turns)


# ----------------------------------------------------------------------
# TCP: plain on 7701, TLS on 7700
# ----------------------------------------------------------------------

def make_tls_context(cert_file: str | Path, key_file: str | Path) -> ssl.SSLContext:
    """A server context for the TLS gate (TLS 1.2 or later, no client certificates)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_file), str(key_file))
    return context


class TcpGate:
    """The TCP listeners of the gate, in the event loop of the HTTP server (one process, one writer).

    ``plain_port`` (7701) speaks the line protocol in the clear and refuses
    every secret; ``tls_port`` (7700) runs only when a certificate and key are
    given (``AICS_GATE_TLS_CERT`` / ``AICS_GATE_TLS_KEY``), and picks up a
    renewed certificate within ``cert_check_seconds``.  A port of ``None``
    leaves that listener off; ``0`` binds any free port (tests).  Nothing about
    the peer (address, port, timing) is recorded or printed.
    """

    def __init__(
        self,
        gate: Gate,
        *,
        host: str = "0.0.0.0",
        plain_port: int | None = 7701,
        tls_port: int | None = 7700,
        cert_file: str | Path | None = None,
        key_file: str | Path | None = None,
        idle_seconds: float = SESSION_IDLE_SECONDS,
        write_timeout: float = 60.0,
        cert_check_seconds: float = 300.0,
    ) -> None:
        if (cert_file is None) != (key_file is None):
            raise ValueError("the TLS gate needs both a certificate and a key (AICS_GATE_TLS_CERT and AICS_GATE_TLS_KEY)")
        self.gate = gate
        self.host = host
        self.plain_port = plain_port
        self.tls_port = tls_port if cert_file is not None else None
        self.cert_file = Path(cert_file) if cert_file is not None else None
        self.key_file = Path(key_file) if key_file is not None else None
        self.idle_seconds = idle_seconds
        self.write_timeout = write_timeout
        self.cert_check_seconds = cert_check_seconds
        self.ports: dict[str, int] = {}
        self._servers: list[asyncio.base_events.Server] = []
        self._context: ssl.SSLContext | None = None
        self._cert_stamp: tuple[int, int, int, int] | None = None
        self._watcher: asyncio.Task[None] | None = None
        self._clients: set[asyncio.Task[Any]] = set()
        self._active = 0
        self._previous_handler: Callable[..., Any] | None = None

    def _stamp(self) -> tuple[int, int, int, int]:
        cert, key = os.stat(self.cert_file), os.stat(self.key_file)
        return cert.st_mtime_ns, cert.st_size, key.st_mtime_ns, key.st_size

    def _quiet_exception_handler(self, loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        """Pass loop errors on without the transport, socket or peer fields (they can carry a client address)."""
        safe = {k: v for k, v in context.items() if k in ("message", "exception")}
        if self._previous_handler is not None:
            self._previous_handler(loop, safe)
        else:
            loop.default_exception_handler(safe)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(self._quiet_exception_handler)
        if self.plain_port is not None:
            server = await asyncio.start_server(
                self._plain_client, self.host, self.plain_port, limit=MAX_LINE_BYTES + 2
            )
            self._servers.append(server)
            self.ports["plain"] = server.sockets[0].getsockname()[1]
        if self.tls_port is not None:
            self._context = make_tls_context(self.cert_file, self.key_file)
            self._cert_stamp = self._stamp()
            server = await asyncio.start_server(
                self._tls_client,
                self.host,
                self.tls_port,
                ssl=self._context,
                limit=MAX_LINE_BYTES + 2,
                ssl_handshake_timeout=30,
            )
            self._servers.append(server)
            self.ports["tls"] = server.sockets[0].getsockname()[1]
            self._watcher = asyncio.create_task(self._watch_certificate())

    async def close(self) -> None:
        if self._watcher is not None:
            self._watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watcher
            self._watcher = None
        for server in self._servers:
            server.close()
        for task in list(self._clients):
            task.cancel()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 5)
        self._servers.clear()
        loop = asyncio.get_running_loop()
        if loop.get_exception_handler() == self._quiet_exception_handler:
            loop.set_exception_handler(self._previous_handler)

    def reload_certificate(self) -> bool:
        """Load the certificate again if its files changed; new handshakes use it.  True if reloaded."""
        if self._context is None:
            return False
        try:
            stamp = self._stamp()
            if stamp == self._cert_stamp:
                return False
            self._context.load_cert_chain(str(self.cert_file), str(self.key_file))
        except (OSError, ssl.SSLError) as exc:
            print(f"aics-server: gate: certificate reload failed ({type(exc).__name__}); the old one stays", file=sys.stderr, flush=True)
            return False
        self._cert_stamp = stamp
        print("aics-server: gate: TLS certificate reloaded", file=sys.stderr, flush=True)
        return True

    async def _watch_certificate(self) -> None:
        while True:
            await asyncio.sleep(self.cert_check_seconds)
            self.reload_certificate()

    async def _plain_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._client(reader, writer, tls=False)

    async def _tls_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._client(reader, writer, tls=True)

    async def _send(self, writer: asyncio.StreamWriter, lines: list[str]) -> None:
        writer.write(_render([lines]).encode("utf-8"))
        await asyncio.wait_for(writer.drain(), self.write_timeout)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, tls: bool) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._clients.add(task)
        session: Session | None = None
        counted = False
        try:
            if self._active >= self.gate.limits.max_connections:
                await self._send(writer, ["err busy too many connections right now; retry later"])
                return
            self._active += 1
            counted = True
            session = self.gate.open_session("tcp-tls" if tls else "tcp-plain", register=False)
            if session is None:
                await self._send(writer, ["err busy the gate holds too many sessions right now; retry shortly"])
                return
            await self._send(writer, self.gate.start_turn(session))
            while not session.ended:
                try:
                    raw = await asyncio.wait_for(reader.readline(), self.idle_seconds)
                except TimeoutError:
                    await self._send(writer, [f"err session_expired idle for {int(self.idle_seconds)} s; connect again"])
                    break
                except (ValueError, asyncio.LimitOverrunError):
                    await self._send(writer, [f"err too_large a line is at most {MAX_LINE_BYTES} bytes"])
                    break
                if not raw:
                    break
                text = raw.decode("utf-8", errors="replace")
                if text.endswith("\n"):
                    text = text[:-1]
                turn = await asyncio.to_thread(self.gate.feed, session, text, via="tcp", tls=tls)
                if turn is not None:
                    await self._send(writer, turn)
        except (ConnectionError, ssl.SSLError, TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # never let asyncio log the transport (its socket names the peer)
            print(f"aics-server: gate: {type(exc).__name__} on a TCP connection", file=sys.stderr, flush=True)
        finally:
            if counted:
                self._active -= 1
            if session is not None:
                self.gate.close_session(session)
            if task is not None:
                self._clients.discard(task)
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 5)
