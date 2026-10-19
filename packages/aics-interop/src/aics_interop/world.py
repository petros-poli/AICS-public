"""Deterministic interop scenarios shared by the tests and the fixture generator.

Everything here is built from public test seeds and fixed clocks, so two runs
produce the same bytes: entries and tiles come from aics-tlog, checkpoint
notes from aics-tlog ``sign_checkpoint``, cosignatures from in-process
aics-witness instances (:mod:`aics_interop.witnesses`) whose clock is pinned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import aicslog, spec
from .witnesses import LocalWitness, cosigned

T_COSIGN = aicslog.T0 + 3600  # witnesses cosign one hour after the Appendix A epoch
NOW = T_COSIGN + 10           # the verifiers' clock in most tests
WITNESSES = ("witness_a", "witness_b")


class Clock:
    """A settable clock for aics-witness (``clock=`` takes a callable)."""

    def __init__(self, t: int) -> None:
        self.t = t

    def __call__(self) -> float:
        return float(self.t)


def witness_vkeys(which: tuple[str, ...] = WITNESSES) -> list[str]:
    return [aicslog.witness_vkey(w) for w in which]


def witness_pool(db_dir: Path, clock: Clock, *, origin: str = aicslog.ORIGIN,
                 keys: aicslog.Keys | None = None) -> dict[str, LocalWitness]:
    """Both interop witnesses, each trusting the interop log key for ``origin``."""
    k = keys or aicslog.Keys()
    db_dir.mkdir(parents=True, exist_ok=True)
    return {w: LocalWitness(w, db_dir, [(origin, k.log_vkey(origin))], clock=clock) for w in WITNESSES}


def cosign(log: aicslog.AicsLog, size: int, witnesses: list[LocalWitness], clock: Clock, at: int) -> bytes:
    """Feed ``log`` at ``size`` to each witness at time ``at`` and merge the returned lines."""
    clock.t = at
    lines = [w.feed(log, size) for w in witnesses]
    return cosigned(log.note(size), *lines)


# ---------------------------------------------------------------------------
# the main scenario: a 300-entry log with a bootstrap card, two witnesses
# ---------------------------------------------------------------------------


def interop_card(*, version: str = "0.2-draft", spec_versions: dict[str, str] | None = None,
                 refusal: list[str] | None = None, quorum: int = 2) -> dict[str, Any]:
    """The signed bootstrap card of the interop log (AICS-1 §13.1-13.2), signed with the spec reference."""
    k = aicslog.Keys()
    witnesses = [{"name": aicslog.WITNESS_NAMES[w], "vkey": aicslog.witness_vkey(w), "trust_domain": "founder",
                  "independent": False} for w in WITNESSES]
    card = spec.card_template(
        origin=aicslog.ORIGIN, log_vkey=k.log_vkey(), policy_kid=spec.kid(k.policy), owner_kid=spec.kid(k.owner),
        issued_at=aicslog.T0, expires=aicslog.T0 + 30 * 86400, policy_parent_index=0,
        tile_prefixes=[aicslog.PREFIX.rstrip("/"), aicslog.MIRROR.rstrip("/")], api_base=aicslog.API_BASE,
        witnesses=witnesses, quorum=quorum, charter_hash=spec.hexH(aicslog.AicsLog.CHARTER_BODY),
        version=version, spec_versions=spec_versions or spec.SPEC_VERSIONS, refusal=refusal,
        secret_patterns=[{"id": "github_pat", "pattern_hash": spec.hexH(b"ghp_[A-Za-z0-9]{36}")}])
    return spec.sign_card(card, k.policy, spec.kid(k.policy))


@dataclass
class MainScenario:
    log: aicslog.AicsLog
    card: dict[str, Any]
    trust: dict[str, Any]
    notes: dict[int, bytes]          # size -> note cosigned by both witnesses
    cosigned_at: dict[int, int]      # size -> cosignature timestamp
    witnesses: dict[str, LocalWitness]
    clock: Clock

    @property
    def trust_bytes(self) -> bytes:
        return spec.J(self.trust)

    def close(self) -> None:
        for w in self.witnesses.values():
            w.close()


MAIN_SIZES = (3, 256, 300)


def main_scenario(db_dir: Path, *, card: dict[str, Any] | None = None) -> MainScenario:
    card = card or interop_card()
    log = aicslog.standard_log(max(MAIN_SIZES), card=card)
    clock = Clock(T_COSIGN)
    pool = witness_pool(db_dir, clock)
    notes, at = {}, {}
    for i, size in enumerate(MAIN_SIZES):
        at[size] = T_COSIGN + 60 * i
        notes[size] = cosign(log, size, list(pool.values()), clock, at[size])
    trust = aicslog.trust_bundle(card_hash=spec.card_hash(card))
    return MainScenario(log, card, trust, notes, at, pool, clock)


# ---------------------------------------------------------------------------
# split-view fixtures (AICS-1 §14.6)
# ---------------------------------------------------------------------------


@dataclass
class SplitFixture:
    name: str
    description: str
    a: bytes                                 # note 1, served by the log origin
    b: bytes                                 # note 2, served by the mirror
    a_tiles: dict[str, bytes]
    b_tiles: dict[str, bytes] | None         # None: the mirror's tiles are unavailable
    quorum: int
    witnesses: list[str] = field(default_factory=witness_vkeys)
    larger_entries: list[bytes] | None = None  # the larger tree's entries, for the spec classifier
    expected: dict[str, Any] = field(default_factory=dict)  # spec.classify_gossip(a, b, ...)
    now: int = NOW
    trees: tuple[str, str] = ("", "")        # labels of the served trees ("main@12", "fork@12", "none")

    def classify(self) -> dict[str, Any]:
        return spec.classify_gossip(self.a, self.b, log_vkey=aicslog.Keys().log_vkey(),
                                    witness_vkeys=self.witnesses, quorum=self.quorum,
                                    larger_entries=self.larger_entries, expected_origin=aicslog.ORIGIN)


def split_fixtures(db_dir: Path) -> list[SplitFixture]:
    """Nine pairs of notes covering every §14.6 outcome, with what each source serves."""
    main = aicslog.standard_log(12)
    fork = aicslog.standard_log(12, fork_after=6)
    assert main.leaves(6) == fork.leaves(6) and main.leaves(7) != fork.leaves(7)
    out: list[SplitFixture] = []

    def pool(name: str) -> tuple[dict[str, LocalWitness], Clock]:
        clock = Clock(T_COSIGN)
        return witness_pool(db_dir / name, clock), clock

    # 1. consistent: a smaller head is a prefix of a larger one
    p, c = pool("consistent-prefix")
    a = cosign(main, 8, [p["witness_a"]], c, T_COSIGN)
    b = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    out.append(SplitFixture("consistent-prefix", "size 8 is a prefix of size 12 (one log)", a, b,
                            main.tiles(8), main.tiles(12), 1, larger_entries=main.leaves(12),
                            trees=("main@8", "main@12")))
    # 2. consistent: same tree, different signature sets (different note hashes, not a split view, §4.1)
    p, c = pool("same-tree-different-signatures")
    a = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    b = cosigned(a, p["witness_b"].feed(main, 12))
    out.append(SplitFixture("same-tree-different-signatures",
                            "one tree under two different cosignature sets: note hashes differ, no split", a, b,
                            main.tiles(12), main.tiles(12), 1, trees=("main@12", "main@12")))
    # 3. split: equal sizes, different roots, each cosigned by a different witness
    p, c = pool("equal-size-split")
    a = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    b = cosign(fork, 12, [p["witness_b"]], c, T_COSIGN)
    out.append(SplitFixture("equal-size-split", "two cosigned heads of size 12 with different roots", a, b,
                            main.tiles(12), fork.tiles(12), 1, trees=("main@12", "fork@12")))
    # 4. split: the smaller head is not a prefix of the larger one
    p, c = pool("not-a-prefix")
    a = cosign(main, 10, [p["witness_a"]], c, T_COSIGN)
    b = cosign(fork, 12, [p["witness_b"]], c, T_COSIGN)
    out.append(SplitFixture("not-a-prefix", "cosigned size 10 is not a prefix of cosigned size 12 (fork at 6)",
                            a, b, main.tiles(10), fork.tiles(12), 1, larger_entries=fork.leaves(12),
                            trees=("main@10", "fork@12")))
    # 5. equivocation: the conflicting head is log-signed only (the witness refused it)
    p, c = pool("unwitnessed-equivocation")
    a = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    b = fork.note(12)
    out.append(SplitFixture("unwitnessed-equivocation",
                            "a cosigned head and a log-signed, uncosigned head of size 12 with another root "
                            "(the witness refused it with 422)", a, b, main.tiles(12), fork.tiles(12), 1,
                            trees=("main@12", "fork@12")))
    # 5b. equivocation: the conflicting head carries a junk line under the pinned witness's key
    p, c = pool("equivocation-invalid-cosignature")
    a = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    junk = [ln for ln in a.decode().split("\n") if ln.startswith(f"{spec.EM_DASH} {aicslog.WITNESS_NAMES['witness_a']} ")]
    b = fork.note(12) + (junk[0] + "\n").encode()
    out.append(SplitFixture("equivocation-invalid-cosignature",
                            "a cosigned head and a log-signed head of size 12 with another root whose witness line "
                            "(copied from the first) does not verify", a, b, main.tiles(12), fork.tiles(12), 1,
                            trees=("main@12", "fork@12")))
    # 6. unproven: unequal sizes and no tiles or proof for the larger head
    p, c = pool("consistency-unproven")
    a = cosign(main, 10, [p["witness_a"]], c, T_COSIGN)
    b = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    out.append(SplitFixture("consistency-unproven",
                            "sizes 10 and 12 of one log, but the mirror serves no tiles and there is no proof",
                            a, b, main.tiles(10), None, 1, trees=("main@10", "none")))
    # 7. split: a log-signed size-0 head whose root is not SHA-256("") (quorum 0 policy)
    p, c = pool("bad-empty-root")
    a = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    b = main.note(0, root=spec.H(b"not the empty tree"))
    out.append(SplitFixture("bad-empty-root", "a log-signed size-0 checkpoint with a root that is not SHA-256('')",
                            a, b, main.tiles(12), {}, 0, larger_entries=main.leaves(12),
                            trees=("main@12", "empty")))
    # 8. not evidence: note 2 is not signed by the pinned log key
    p, c = pool("not-log-signed")
    a = cosign(main, 12, [p["witness_a"]], c, T_COSIGN)
    b = main.note(12, key=spec.test_key(0x2F))
    out.append(SplitFixture("not-log-signed", "note 2 carries a signature line under another key only", a, b,
                            main.tiles(12), main.tiles(12), 1, trees=("main@12", "main@12")))
    for fx in out:
        fx.expected = fx.classify()
    return out
