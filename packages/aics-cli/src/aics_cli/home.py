"""Layout of the agent's local state directory (default ``~/.aics``).

::

    ~/.aics/                    0700
      aics.key                  Ed25519 private key, PKCS#8 PEM (what
                                ``openssl genpkey -algorithm ed25519`` writes), 0600
      aics-x.key                X25519 private key, PKCS#8 PEM (what
                                ``openssl genpkey -algorithm X25519`` writes), 0600
      identity.json             public keys only
      policy.toml               pinned keys and URLs (``aics policy init``)
      policy-history/           policies replaced with ``--force``
      checkpoints/              append-only: verified checkpoint notes
        index.jsonl             one line per save, with its role (head/evidence/observed)
                                and log key; ``reset`` lines (--reset-history)
        <origin>/<size>-<sha256>.note
      cards/                    append-only: verified assurance cards
        index.jsonl
        <policy key>/<card hash>.json
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

ED25519_KEY = "aics.key"
X25519_KEY = "aics-x.key"
IDENTITY = "identity.json"
POLICY = "policy.toml"


def default_home() -> Path:
    env = os.environ.get("AICS_HOME")
    if env:
        return Path(env).expanduser()
    return Path("~/.aics").expanduser()


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    return path


def slug(text: str) -> str:
    """A filesystem-safe, collision-resistant directory name for an origin or host."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._") or "_"
    if safe != text:
        import hashlib

        safe = f"{safe[:80]}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:8]}"
    return safe


def write_new(path: Path, data: bytes, mode: int = 0o644) -> bool:
    """Create ``path`` with ``data``; never replace an existing file.

    Returns True if created, False if the file already holds exactly
    ``data``.  Raises FileExistsError if it holds something else.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        if path.read_bytes() == data:
            return False
        raise
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return True


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON line (O_APPEND; never rewrites earlier lines)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue  # a torn final line from a crash; earlier lines stay valid
        if isinstance(obj, dict):
            out.append(obj)
    return out
