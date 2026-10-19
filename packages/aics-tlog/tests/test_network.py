"""Optional network test against the live Go checksum database."""

import pytest

from conftest import GO_SUMDB_VKEY


def test_sum_golang_org_latest_verifies(go_sumdb_vkey):
    try:
        import urllib.request
    except ImportError:  # pragma: no cover
        pytest.skip("urllib unavailable")
    try:
        data = urllib.request.urlopen(
            "https://sum.golang.org/latest", timeout=15
        ).read()
    except OSError:
        pytest.skip("offline: cannot reach sum.golang.org")
    from aics_tlog.note import parse_note, verify_note

    note = parse_note(data)
    assert note.text.startswith("go.sum database tree\n")
    size_line = note.text.split("\n")[1]
    assert size_line.isdigit() and int(size_line) > 0
    assert verify_note(note, [go_sumdb_vkey]), "signature over /latest failed"
