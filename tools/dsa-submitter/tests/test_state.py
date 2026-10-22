"""Group N: the state file."""

import json
import os

import pytest

from dsa_submitter import state


def test_save_load_round_trip(tmp_path):
    path = str(tmp_path / "state.json")
    original = {
        "version": 1,
        "entries_scanned": 15,
        "leaves": {
            "2": {"status": "submitted", "uuid": "uuid-1", "puid": "aics-leaf-2"},
            "10": {"status": "pending", "reason": "needs operator input"},
        },
    }
    state.save(path, original)
    assert state.load(path) == original


def test_saved_file_is_mode_0600(tmp_path):
    path = str(tmp_path / "state.json")
    state.save(path, state.default_state())
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_missing_file_returns_the_default(tmp_path):
    path = str(tmp_path / "absent.json")
    assert state.load(path) == {"version": 1, "entries_scanned": 0, "leaves": {}}


def test_corrupt_file_raises_value_error(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("not json at all")
    with pytest.raises(ValueError, match="not valid JSON"):
        state.load(str(path))


def test_non_state_json_raises_value_error(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"entries_scanned": 3}))
    with pytest.raises(ValueError, match="does not look like submitter state"):
        state.load(str(path))


def test_submitted_indexes():
    state_now = {"leaves": {
        "2": {"status": "submitted"},
        "4": {"status": "failed"},
        "10": {"status": "pending"},
        "11": {"status": "submitted"},
    }}
    assert state.submitted_indexes(state_now) == {2, 11}
