"""ops/mirror-sync.sh: the tiles snapshot survives a cosignature refresh, and fails closed on a new publication.

The server rewrites <tiles>/checkpoint with the same checkpoint text whenever it merges a fresher witness
cosignature (every AICS_WITNESS_REFRESH_SECONDS), besides once per publication. The snapshot program (the
script's Python heredoc) is run here on a local tiles tree, with the checkpoint rewritten while the tiles are
copied; rclone is never run.
"""

import base64
from pathlib import Path
import re
import subprocess
import sys

SCRIPT = Path(__file__).resolve().parents[1] / "ops/mirror-sync.sh"


def snapshot_program() -> str:
    text = SCRIPT.read_text()
    return re.search(r"<<'PYTHON'[^\n]*\n(.*?)\nPYTHON\n", text, re.S).group(1)


def note(size: int, cosignature: bytes | None = None) -> bytes:
    root = base64.b64encode(bytes([size]) * 32).decode()
    out = f"example.test/log\n{size}\n{root}\n\n— example.test/log {base64.b64encode(bytes(68)).decode()}\n"
    if cosignature is not None:
        out += f"— witness.example.test/w1 {base64.b64encode(cosignature).decode()}\n"
    return out.encode()


def run(tmp_path: Path, rewrite: bytes | None):
    src, dst = tmp_path / "tiles", tmp_path / "stage"
    (src / "tile/0").mkdir(parents=True)
    (src / "tile/entries").mkdir(parents=True)
    (src / "tile/0/000.p").mkdir()
    (src / "tile/0/000.p/7").write_bytes(b"\x01" * 32 * 7)
    (src / "tile/entries/000.p").mkdir()
    (src / "tile/entries/000.p/7").write_bytes(b"entries")
    (src / "checkpoint").write_bytes(note(7, cosignature=bytes(76)))
    dst.mkdir()
    # While the first tile is copied, the server replaces the checkpoint (atomically, as its store does).
    prelude = (
        "import os, shutil, sys\n"
        "_copy, _done = shutil.copyfile, []\n"
        "def copyfile(a, b, *k, **kw):\n"
        "    r = _copy(a, b, *k, **kw)\n"
        "    if not _done and REWRITE is not None:\n"
        "        _done.append(1); tmp = os.path.join(sys.argv[1], '.checkpoint.tmp')\n"
        "        open(tmp, 'wb').write(REWRITE); os.replace(tmp, os.path.join(sys.argv[1], 'checkpoint'))\n"
        "    return r\n"
        "shutil.copyfile = copyfile\n"
        f"REWRITE = {rewrite!r}\n"
    )
    result = subprocess.run([sys.executable, "-c", prelude + snapshot_program(), str(src), str(dst)],
                            capture_output=True, text=True)
    return result, dst


def test_an_unchanged_tree_is_snapshotted(tmp_path):
    result, dst = run(tmp_path, None)
    assert result.returncode == 0, result.stderr
    assert (dst / "checkpoint").read_bytes() == note(7, cosignature=bytes(76))
    assert (dst / "tile/0/000.p/7").exists() and (dst / "tile/entries/000.p/7").exists()


def test_a_refreshed_cosignature_of_the_same_checkpoint_does_not_fail_the_snapshot(tmp_path):
    fresher = note(7, cosignature=b"\x02" * 76)
    result, dst = run(tmp_path, fresher)
    assert result.returncode == 0, result.stderr
    assert (dst / "checkpoint").read_bytes() == fresher  # the newest note of the same checkpoint


def test_a_new_publication_during_the_snapshot_fails_closed(tmp_path):
    result, dst = run(tmp_path, note(8, cosignature=bytes(76)))
    assert result.returncode != 0
    assert "new checkpoint was published during the snapshot" in result.stderr
    assert not (dst / "checkpoint").exists()


def test_a_note_without_signatures_is_refused(tmp_path):
    result, _ = run(tmp_path, b"example.test/log\n7\nAAAA\n")
    assert result.returncode != 0 and "not a signed note" in result.stderr
