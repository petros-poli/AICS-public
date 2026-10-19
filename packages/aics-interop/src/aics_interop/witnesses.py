"""In-process aics-witness instances (the real protocol logic, no HTTP)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from . import aicslog


class LocalWitness:
    """aics_witness.Witness over a fresh SQLite store with an injectable clock."""

    def __init__(self, which: str, db_dir: Path, logs: list[tuple[str, str]], *,
                 clock: Callable[[], float]) -> None:
        from aics_witness.config import LogConfig
        from aics_witness.service import Witness
        from aics_witness.store import WitnessStore

        self.which = which
        self.name = aicslog.WITNESS_NAMES[which]
        self.store = WitnessStore(Path(db_dir) / f"{which}.db", create=True)
        self.witness = Witness(self.name, aicslog.witness_key(which), self.store,
                               [LogConfig.from_strings(o, [v]) for o, v in logs], clock=clock)
        self.size = 0  # the size this witness last cosigned (what the feeder tracks)

    @property
    def vkey(self) -> str:
        return self.witness.vkey_text

    def add_checkpoint(self, note: bytes, old_size: int, proof: list[bytes]) -> str:
        """POST-equivalent of ``/add-checkpoint``: returns the cosignature line(s) or raises WitnessError."""
        from aics_witness.protocol import format_add_checkpoint_request

        return self.witness.add_checkpoint(format_add_checkpoint_request(old_size, proof, note)).decode("utf-8")

    def feed(self, log: aicslog.AicsLog, size: int | None = None, note: bytes | None = None) -> str:
        """Feed the log's checkpoint at ``size`` with a tile-derived consistency proof."""
        n = log.size if size is None else size
        note = log.note(n) if note is None else note
        proof = log.consistency_proof(self.size, n) if 0 < self.size < n else []
        line = self.add_checkpoint(note, self.size, proof)
        self.size = n
        return line

    def close(self) -> None:
        self.store.close()


def cosigned(note: bytes, *lines: str) -> bytes:
    """Merge cosignature lines into a log-signed note (aics-witness feeder.merge_cosignatures)."""
    from aics_witness.feeder import merge_cosignatures

    out = note
    for line in lines:
        out = merge_cosignatures(out, line)
    return out
