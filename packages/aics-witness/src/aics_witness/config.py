"""Witness configuration file (JSON).

::

    {
      "witness": {
        "name": "witness.example.org/aics-w1",
        "listen": "0.0.0.0:7380",
        "prefix": "",
        "db": "witness.db",
        "key_file": "witness.key",
        "max_body_bytes": 262144
      },
      "logs": [
        {"origin": "wesupport-ai.com/log/v2",
         "vkeys": ["wesupport-ai.com/log/v2+1a2b3c4d+AU..."],
         "extension_lines": false,
         "initial": {"size": 1234, "root": "<base64 root hash>"}}
      ]
    }

``name`` is the cosigner name (it is part of the witness vkey).  ``db`` and
``key_file`` are resolved relative to the directory holding the config
file.  Each log is identified by its origin line; ``vkeys`` lists the log
public keys the witness trusts for that origin as C2SP verifier keys of type
0x01 (Ed25519 log signature, the normal case) or 0x04 (Ed25519 cosignature
used by the log itself).  Keys that are not canonical Ed25519 encodings, or
are points of small order (under which signatures can be forged), are
refused.

``extension_lines`` (default false) allows checkpoint extension lines for
the log; AICS-1 checkpoints have none, so by default a checkpoint carrying
them is refused instead of cosigned.  ``initial`` (optional) pins a known
good checkpoint (size >= 1 and root) for a log the witness has never
cosigned: the witness then starts from it instead of trusting whatever
checkpoint arrives first with ``old 0``.  Once the witness holds state for
the log, ``initial`` is ignored.

Unknown fields are errors, so a typo cannot silently drop a setting.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aics_tlog import EMPTY_HASH, VKey, format_vkey, parse_vkey

from .protocol import (
    MAX_TREE_SIZE,
    ProtocolError,
    b64_decode_strict,
    b64_encode,
    ed25519_public_key_problem,
    validate_name,
)

__all__ = [
    "CONFIG_ENV",
    "DEFAULT_LISTEN",
    "DEFAULT_MAX_BODY_BYTES",
    "SUPPORTED_LOG_KEY_TYPES",
    "ConfigError",
    "LogConfig",
    "WitnessConfig",
    "add_log_to_config",
    "load_config",
    "new_config",
    "normalize_prefix",
    "parse_initial",
    "parse_listen",
    "parse_log_vkey",
    "write_config",
]

CONFIG_ENV = "AICS_WITNESS_CONFIG"
DEFAULT_LISTEN = "0.0.0.0:7380"
DEFAULT_MAX_BODY_BYTES = 256 * 1024
TYPE_ED25519 = 0x01
TYPE_COSIGNATURE = 0x04
SUPPORTED_LOG_KEY_TYPES = (TYPE_ED25519, TYPE_COSIGNATURE)

_WITNESS_FIELDS = {"name", "listen", "prefix", "db", "key_file", "max_body_bytes"}
_LOG_FIELDS = {"origin", "vkeys", "vkey", "extension_lines", "initial"}


class ConfigError(ValueError):
    """The configuration file is missing, malformed or inconsistent."""


def parse_log_vkey(text: str) -> VKey:
    """Parse and check a log verifier key."""
    if not isinstance(text, str):
        raise ConfigError("a vkey must be a string")
    try:
        key = parse_vkey(text.strip())
    except ValueError as e:
        raise ConfigError(f"invalid vkey {text.strip()[:60]!r}: {e}") from None
    if key.key_type not in SUPPORTED_LOG_KEY_TYPES:
        raise ConfigError(
            f"vkey {key.name} has signature type 0x{key.key_type:02x}; supported: "
            "0x01 (Ed25519 log signature) and 0x04 (Ed25519 cosignature)"
        )
    if len(key.public_key) != 32:
        raise ConfigError(f"vkey {key.name} does not hold a 32-byte Ed25519 key")
    problem = ed25519_public_key_problem(key.public_key)
    if problem is not None:
        raise ConfigError(f"vkey {key.name}: the public key {problem}")
    return key


def parse_initial(raw: Any, origin: str = "") -> tuple[int, bytes]:
    """A log's ``initial`` pin: ``{"size": N, "root": "<base64>"}`` with N >= 1."""
    where = f"log {origin!r}: " if origin else ""
    if not isinstance(raw, dict) or set(raw) != {"size", "root"}:
        raise ConfigError(f"{where}'initial' must be an object with exactly 'size' and 'root'")
    size, root_text = raw["size"], raw["root"]
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_TREE_SIZE:
        raise ConfigError(f"{where}'initial.size' must be an integer of at least 1 (size 0 pins nothing)")
    if not isinstance(root_text, str):
        raise ConfigError(f"{where}'initial.root' must be a base64 string")
    try:
        root = b64_decode_strict(root_text)
    except ProtocolError as e:
        raise ConfigError(f"{where}'initial.root': {e}") from None
    if len(root) != 32:
        raise ConfigError(f"{where}'initial.root' must decode to a 32-byte hash")
    return size, root


@dataclass(frozen=True)
class LogConfig:
    """A log the witness accepts checkpoints from.

    ``extension_lines``: whether its checkpoints may carry extension lines
    (AICS-1 checkpoints have none).  ``initial``: an optional ``(size,
    root)`` the witness treats as its state for the log until it cosigns
    one, instead of trusting the first checkpoint it is sent.
    """

    origin: str
    vkeys: tuple[VKey, ...]
    extension_lines: bool = False
    initial: tuple[int, bytes] | None = None

    def __post_init__(self) -> None:
        try:
            validate_name(self.origin, "origin")
        except ValueError as e:
            raise ConfigError(str(e)) from None
        vkeys = tuple(self.vkeys)
        object.__setattr__(self, "vkeys", vkeys)
        if not vkeys:
            raise ConfigError(f"log {self.origin!r} has no vkeys")
        seen: set[tuple[str, bytes]] = set()
        for key in vkeys:
            if not isinstance(key, VKey):
                raise ConfigError(f"log {self.origin!r}: vkeys must be VKey objects")
            if key.key_type not in SUPPORTED_LOG_KEY_TYPES or len(key.public_key) != 32:
                raise ConfigError(f"log {self.origin!r}: unsupported vkey {key.name}")
            problem = ed25519_public_key_problem(key.public_key)
            if problem is not None:
                raise ConfigError(f"log {self.origin!r}: vkey {key.name}: the public key {problem}")
            pair = (key.name, key.key_id)
            if pair in seen:
                raise ConfigError(f"log {self.origin!r}: vkey {format_vkey(key)} listed twice")
            seen.add(pair)
        if not isinstance(self.extension_lines, bool):
            raise ConfigError(f"log {self.origin!r}: 'extension_lines' must be true or false")
        if self.initial is not None:
            size, root = self.initial
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_TREE_SIZE:
                raise ConfigError(f"log {self.origin!r}: the initial size must be at least 1")
            if not isinstance(root, bytes) or len(root) != 32:
                raise ConfigError(f"log {self.origin!r}: the initial root must be 32 bytes")
            if root == EMPTY_HASH:
                raise ConfigError(f"log {self.origin!r}: the initial root is the empty-tree hash")
            object.__setattr__(self, "initial", (size, bytes(root)))

    @classmethod
    def from_strings(
        cls,
        origin: str,
        vkeys: list[str] | tuple[str, ...],
        *,
        extension_lines: bool = False,
        initial: tuple[int, bytes] | None = None,
    ) -> LogConfig:
        return cls(
            origin=origin,
            vkeys=tuple(parse_log_vkey(v) for v in vkeys),
            extension_lines=extension_lines,
            initial=initial,
        )

    def initial_document(self) -> dict[str, Any] | None:
        """The ``initial`` pin as it appears in the config file."""
        if self.initial is None:
            return None
        return {"size": self.initial[0], "root": b64_encode(self.initial[1])}


@dataclass(frozen=True)
class WitnessConfig:
    path: Path
    name: str
    host: str
    port: int
    prefix: str
    db_path: Path
    key_path: Path
    max_body_bytes: int
    logs: tuple[LogConfig, ...]

    @property
    def listen(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


def parse_listen(text: str) -> tuple[str, int]:
    """``host:port`` or ``[ipv6]:port``; port 0 asks the OS for a free port."""
    if not isinstance(text, str) or ":" not in text:
        raise ConfigError(f"listen address must be host:port, got {text!r}")
    host, _, port_text = text.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ConfigError(f"listen address {text!r} has no host")
    if not port_text.isascii() or not port_text.isdigit() or int(port_text) > 65535:
        raise ConfigError(f"listen address {text!r} has an invalid port")
    return host, int(port_text)


def normalize_prefix(prefix: str) -> str:
    """The URL path prefix: empty, or '/a/b' without a trailing slash."""
    if not isinstance(prefix, str):
        raise ConfigError("prefix must be a string")
    p = prefix.strip()
    if p in ("", "/"):
        return ""
    if not p.startswith("/"):
        raise ConfigError(f"prefix {prefix!r} must start with '/'")
    if any(c in p for c in "?#%") or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in p):
        raise ConfigError(f"prefix {prefix!r} contains characters not allowed in a path prefix")
    return p.rstrip("/")


def new_config(
    name: str,
    *,
    listen: str = DEFAULT_LISTEN,
    prefix: str = "",
    db: str = "witness.db",
    key_file: str = "witness.key",
) -> dict[str, Any]:
    """A fresh configuration document with no logs."""
    try:
        validate_name(name, "witness name")
    except ValueError as e:
        raise ConfigError(str(e)) from None
    parse_listen(listen)
    return {
        "witness": {
            "name": name,
            "listen": listen,
            "prefix": normalize_prefix(prefix),
            "db": db,
            "key_file": key_file,
        },
        "logs": [],
    }


def _read_document(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        raise ConfigError(f"config file {path} does not exist (run 'aics-witness init')") from None
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"cannot read config file {path}: {e}") from None
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise ConfigError(f"config file {path} is not valid JSON: {e}") from None
    if not isinstance(doc, dict):
        raise ConfigError(f"config file {path} must hold a JSON object")
    return doc


def _parse_logs(raw: Any) -> tuple[LogConfig, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("'logs' must be a list")
    logs: list[LogConfig] = []
    origins: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ConfigError("each entry of 'logs' must be an object")
        unknown = set(entry) - _LOG_FIELDS
        if unknown:
            raise ConfigError(f"unknown field(s) in a log entry: {', '.join(sorted(unknown))}")
        origin = entry.get("origin")
        if not isinstance(origin, str):
            raise ConfigError("each log needs an 'origin' string")
        vkeys = entry.get("vkeys", [])
        if "vkey" in entry:
            vkeys = list(vkeys) + [entry["vkey"]]
        if not isinstance(vkeys, list) or not vkeys:
            raise ConfigError(f"log {origin!r} needs 'vkeys': a non-empty list of vkey strings")
        if origin in origins:
            raise ConfigError(f"log origin {origin!r} is configured twice")
        origins.add(origin)
        extension_lines = entry.get("extension_lines", False)
        if not isinstance(extension_lines, bool):
            raise ConfigError(f"log {origin!r}: 'extension_lines' must be true or false")
        initial = None
        if entry.get("initial") is not None:
            initial = parse_initial(entry["initial"], origin)
        logs.append(
            LogConfig.from_strings(origin, vkeys, extension_lines=extension_lines, initial=initial)
        )
    return tuple(logs)


def load_config(path: str | os.PathLike[str]) -> WitnessConfig:
    p = Path(path)
    doc = _read_document(p)
    unknown = set(doc) - {"witness", "logs"}
    if unknown:
        raise ConfigError(f"unknown top-level field(s): {', '.join(sorted(unknown))}")
    w = doc.get("witness")
    if not isinstance(w, dict):
        raise ConfigError("config needs a 'witness' object")
    unknown = set(w) - _WITNESS_FIELDS
    if unknown:
        raise ConfigError(f"unknown field(s) in 'witness': {', '.join(sorted(unknown))}")
    name = w.get("name")
    try:
        validate_name(name, "witness name")
    except ValueError as e:
        raise ConfigError(str(e)) from None
    host, port = parse_listen(w.get("listen", DEFAULT_LISTEN))
    prefix = normalize_prefix(w.get("prefix", ""))
    base = p.resolve().parent
    db = w.get("db", "witness.db")
    key_file = w.get("key_file", "witness.key")
    if not isinstance(db, str) or not db or not isinstance(key_file, str) or not key_file:
        raise ConfigError("'db' and 'key_file' must be non-empty paths")
    max_body = w.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)
    if isinstance(max_body, bool) or not isinstance(max_body, int) or max_body < 4096:
        raise ConfigError("'max_body_bytes' must be an integer of at least 4096")
    return WitnessConfig(
        path=p,
        name=name,
        host=host,
        port=port,
        prefix=prefix,
        db_path=base / db,
        key_path=base / key_file,
        max_body_bytes=max_body,
        logs=_parse_logs(doc.get("logs")),
    )


def write_config(path: str | os.PathLike[str], doc: dict[str, Any]) -> None:
    """Write the config atomically (temp file in the same directory, fsync,
    rename), keeping the mode of an existing file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        mode = os.stat(p).st_mode & 0o777
    except FileNotFoundError:
        mode = 0o644
    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def add_log_to_config(path: str | os.PathLike[str], origin: str, vkey_text: str) -> str:
    """Add a log, or another vkey to a configured log (key rotation).

    Returns ``"added log"``, ``"added vkey"`` or ``"unchanged"``.  The whole
    resulting file is validated before it replaces the old one.
    """
    p = Path(path)
    try:
        validate_name(origin, "origin")
    except ValueError as e:
        raise ConfigError(str(e)) from None
    key = parse_log_vkey(vkey_text)
    canonical = format_vkey(key)
    doc = _read_document(p)
    load_config(p)  # refuse to edit a file that does not load today
    logs = doc.setdefault("logs", [])
    outcome = "added log"
    for entry in logs:
        if entry.get("origin") != origin:
            continue
        vkeys = list(entry.get("vkeys", []))
        if "vkey" in entry:
            vkeys.append(entry.pop("vkey"))
        existing = {format_vkey(parse_log_vkey(v)) for v in vkeys}
        if canonical in existing:
            return "unchanged"
        entry["vkeys"] = vkeys + [canonical]
        outcome = "added vkey"
        break
    else:
        logs.append({"origin": origin, "vkeys": [canonical]})
    tmp_check = json.loads(json.dumps(doc))
    _parse_logs(tmp_check.get("logs"))  # validate before writing
    write_config(p, doc)
    return outcome
