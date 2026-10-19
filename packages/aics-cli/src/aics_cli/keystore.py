"""The agent's own keys: ``aics keys new`` / ``aics keys show``.

Ed25519 (identity, signing) and X25519 (end-to-end encryption) private
keys are generated locally and written as PKCS#8 PEM with mode 0600, the
same file format ``openssl genpkey -algorithm ed25519`` produces, so the
agent can also sign with ``openssl pkeyutl`` as docs/PROTOCOL-TEXT.md §3
describes.  An OpenSSH private key (``ssh-keygen -t ed25519``) is accepted
for signing as well.

Public forms printed are the gate's replies (docs/spec/AICS-1.md §11.4,
PROTOCOL-TEXT.md §3): ``pub <base64 of the raw 32 bytes>`` for the Ed25519
key and ``enc <base64 of 32 bytes>`` for the X25519 key, then the signing
``did:key`` (the agent's ``kid``) and the encryption DID.
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aics_identity import keys as idkeys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import home as _home
from .encoding import b64e
from .errors import AicsError


@dataclass
class PublicIdentity:
    ed25519: bytes
    x25519: bytes | None

    def to_dict(self) -> dict[str, Any]:
        pub = idkeys.public_key_from_bytes(self.ed25519)
        d: dict[str, Any] = {
            "pub": f"pub {b64e(self.ed25519)}",
            "ed25519": b64e(self.ed25519),
            "kid": idkeys.did_key(pub),
            "enc": None,
            "x25519": None,
            "x25519_did": None,
        }
        if self.x25519 is not None:
            from aics_identity.sealed import x25519_did_key

            d.update(enc=f"enc {b64e(self.x25519)}", x25519=b64e(self.x25519),
                     x25519_did=x25519_did_key(self.x25519))
        return d

    def lines(self) -> list[str]:
        d = self.to_dict()
        out = [d["pub"]]
        if d["enc"]:
            out.append(d["enc"])
        out.append(d["kid"])
        if d["x25519_did"]:
            out.append(d["x25519_did"])
        return out


def _pem(key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def new_keys(directory: Path) -> tuple[PublicIdentity, list[Path]]:
    """Generate Ed25519 + X25519 keys in ``directory``; refuses to overwrite."""
    _home.ensure_dir(directory)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    ed_path = directory / _home.ED25519_KEY
    x_path = directory / _home.X25519_KEY
    existing = [p for p in (ed_path, x_path) if p.exists()]
    if existing:
        raise AicsError(
            "refusing to overwrite existing keys (losing them loses the identity); "
            "move them away or use another --dir",
            existing=[str(p) for p in existing],
        )
    ed_key = idkeys.generate_keypair()
    x_key = X25519PrivateKey.generate()
    _write_private(ed_path, _pem(ed_key))
    _write_private(x_path, _pem(x_key))
    ident = PublicIdentity(
        ed25519=idkeys.public_key_bytes(ed_key.public_key()),
        x25519=x_key.public_key().public_bytes_raw(),
    )
    info = ident.to_dict()
    info["created"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    id_path = directory / _home.IDENTITY
    tmp = id_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", "utf-8")
    os.replace(tmp, id_path)
    return ident, [ed_path, x_path, id_path]


def load_ed25519_private(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key: PKCS#8 PEM/DER (openssl) or OpenSSH."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise AicsError(f"no key at {path}; run: aics keys new") from None
    try:
        if b"BEGIN OPENSSH PRIVATE KEY" in data:
            key = serialization.load_ssh_private_key(data, password=None)
        elif data.lstrip().startswith(b"-----BEGIN"):
            key = serialization.load_pem_private_key(data, password=None)
        else:
            key = serialization.load_der_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise AicsError(f"cannot read private key {path}: {exc} (encrypted keys are not supported)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise AicsError(f"{path} is not an Ed25519 private key")
    return key


def load_x25519_private(path: Path) -> X25519PrivateKey | None:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise AicsError(f"cannot read X25519 key {path}: {exc}") from None
    if not isinstance(key, X25519PrivateKey):
        raise AicsError(f"{path} is not an X25519 private key")
    return key


def permission_warning(path: Path) -> str | None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode & 0o077:
        return f"{path} is readable by others (mode {mode:o}); chmod 600 it"
    return None


def show_keys(directory: Path) -> tuple[PublicIdentity, list[str]]:
    ed = load_ed25519_private(directory / _home.ED25519_KEY)
    x = load_x25519_private(directory / _home.X25519_KEY)
    warnings = [w for w in (permission_warning(directory / _home.ED25519_KEY),
                            permission_warning(directory / _home.X25519_KEY)) if w]
    ident = PublicIdentity(
        ed25519=idkeys.public_key_bytes(ed.public_key()),
        x25519=x.public_key().public_bytes_raw() if x is not None else None,
    )
    return ident, warnings


def parse_public_key_text(text: str) -> Ed25519PublicKey:
    """The public-key forms an agent hands the gate (PROTOCOL-TEXT.md §3):
    ``pub <base64>``, ``pub ssh-ed25519 <base64> [comment]``, bare base64
    (either alphabet, padding optional) or ``did:key:z...``.  Small-order and
    non-canonical keys are refused (aics_identity)."""
    import re

    t = text.strip()
    m = re.match(r"pub(?::\s*|\s+)(.*)$", t, re.IGNORECASE | re.DOTALL)
    if m:
        t = m.group(1).strip()
    try:
        return idkeys.parse_public_key_text(t)
    except (ValueError, TypeError) as exc:
        raise AicsError(f"bad public key: {exc}") from None
