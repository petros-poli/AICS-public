"""The submitter's state file: what was submitted, what is pending or failed.

Default ``/var/lib/aics-dsa/state.json`` (the systemd unit's StateDirectory),
overridable with ``--state`` or ``DSA_STATE_PATH``. The file holds the walked-
up-to log index (``entries_scanned``) and one record per restriction leaf:
the ``puid`` and the database's returned identifier once submitted, or the
last error once a 4xx blocked it (with the fingerprint of the decisions
record that produced the failed payload — a changed record un-blocks it).
It never holds the token.
"""

from __future__ import annotations

import json
import os
import tempfile

STATE_VERSION = 1


def default_state():
    return {"version": STATE_VERSION, "entries_scanned": 0, "leaves": {}}


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            state = json.load(handle)
    except FileNotFoundError:
        return default_state()
    except json.JSONDecodeError as exc:
        raise ValueError(f"state file {path} is not valid JSON: {exc.msg}") from None
    if not isinstance(state, dict) or "leaves" not in state or "entries_scanned" not in state:
        raise ValueError(f"state file {path} does not look like submitter state")
    if state.get("version") != STATE_VERSION:
        raise ValueError(f"state file {path} has version {state.get('version')!r}; "
                         f"expected {STATE_VERSION}")
    return state


def save(path, state):
    """Atomically (same-directory temp file, then rename), mode 0600."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def submitted_indexes(state):
    return {int(index) for index, record in state["leaves"].items()
            if record.get("status") == "submitted"}
