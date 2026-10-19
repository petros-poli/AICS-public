"""ops/backup.sh and ops/restore.sh against a docker-less fake layout.

A fake `docker` shim stands in for the aics-server container: its /data and
/tmp live under a temporary FAKE_ROOT, `compose exec ... python3 -c <online
backup>` copies the fake database bytes (so a corrupt database stays corrupt),
`compose cp` copies files, `compose run` runs python3 for real with the -v
mounts mapped, and aics-tlog answers success. A fake `rclone` copies into
directories, a fake `flock` always gets the lock. Run with:
    uv run --with pytest pytest -q tools/test_backup_local.py
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile

import pytest


REPO = Path(__file__).resolve().parents[1]
BACKUP = REPO / "ops/backup.sh"
RESTORE = REPO / "ops/restore.sh"
STAMP_RE = re.compile(r"^\d{8}-\d{6}$")
SEED_BYTES = b"SEED-NEVER-IN-A-BACKUP-0123456789abcdef"

DOCKER_SHIM = r'''
import json, os, shutil, subprocess, sys
root = os.environ["FAKE_ROOT"]
args = sys.argv[1:]
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps(["docker", *args]) + "\n")
if not args or args[0] != "compose":
    sys.exit(2)
i = 1
while i < len(args) and args[i] in ("--project-directory", "-f"):
    i += 2
sub, rest = args[i], args[i + 1:]

def cpath(p, mounts=()):
    for src, dst in mounts:
        if p == dst or p.startswith(dst + "/"):
            return src + p[len(dst):]
    for prefix in ("/data", "/tmp"):
        if p == prefix or p.startswith(prefix + "/"):
            return root + p
    return p

def side(p):
    return cpath(p.split(":", 1)[1]) if p.startswith("aics-server:") else p

if sub == "exec":
    j = 0
    while rest[j].startswith("-"):
        j += 2 if rest[j] in ("-u", "--user") else 1
    cmd = rest[j + 1:]
    if cmd[:2] == ["python3", "-c"] and "src.backup(dst)" in cmd[2]:
        if os.environ.get("FAKE_EXEC_FAIL") == "1":
            sys.exit(1)
        shutil.copyfile(root + "/data/aics.db", root + "/tmp/aics-backup.db")
        sys.exit(0)
    if cmd[:2] == ["python3", "-c"]:
        sys.exit(subprocess.call([sys.executable, "-I", "-c", cmd[2], *[cpath(a) for a in cmd[3:]]]))
    if cmd[:2] == ["rm", "-f"]:
        for p in cmd[2:]:
            try:
                os.remove(cpath(p))
            except FileNotFoundError:
                pass
        sys.exit(0)
    sys.exit(3)
if sub == "cp":
    src, dst = side(rest[-2]), side(rest[-1])
    if os.path.isdir(src):
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copyfile(src, dst)
    sys.exit(0)
if sub == "run":
    mounts, entry, j = [], None, 0
    while rest[j] != "aics-server":
        if rest[j] in ("--user", "--name", "--entrypoint", "-v"):
            if rest[j] == "-v":
                parts = rest[j + 1].split(":")
                mounts.append((parts[0], parts[1]))
            if rest[j] == "--entrypoint":
                entry = rest[j + 1]
            j += 2
        else:
            j += 1
    argv = rest[j + 1:]
    if entry == "python3":
        sys.exit(subprocess.call([sys.executable, "-I", *[cpath(a, mounts) for a in argv]]))
    if entry == "aics-tlog":
        print(json.dumps({"ok": True}))
        sys.exit(int(os.environ.get("FAKE_TLOG_RC", "0")))
    sys.exit(0)
if sub == "stop":
    sys.exit(0)
sys.exit(4)
'''

RCLONE_SHIM = r'''
import json, os, shutil, sys
args = sys.argv[1:]
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps(["rclone", *args]) + "\n")
if args[:1] == ["--config"]:
    args = args[2:]
store = os.environ["FAKE_REMOTES"]
failing = os.environ.get("FAKE_RCLONE_FAIL", "").split()
def where(spec):
    remote, path = spec.split(":", 1)
    return remote, os.path.join(store, remote, path)
if args[0] == "copyto":
    remote, dst = where(args[2])
    if remote in failing:
        sys.exit(1)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(args[1], dst)
    sys.exit(0)
if args[0] in ("delete", "rmdirs"):
    sys.exit(0)
if args[0] == "copy":
    remote, src = where(args[1])
    shutil.copytree(src, args[2], dirs_exist_ok=True)
    sys.exit(0)
sys.exit(5)
'''


def make_db(path: Path, rows: int = 400) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE leaves (idx INTEGER PRIMARY KEY, body BLOB NOT NULL)")
    conn.execute("CREATE INDEX leaves_body ON leaves(body)")
    conn.executemany("INSERT INTO leaves(idx, body) VALUES (?, ?)",
                     [(i, hashlib.sha256(str(i).encode()).digest() * 8) for i in range(rows)])
    conn.commit()
    conn.close()


def integrity(path: Path) -> str:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        conn.close()
        return "\n".join(str(r[0]) for r in rows)
    except sqlite3.DatabaseError as exc:
        return f"error: {exc}"


def stamp(days_ago: float) -> str:
    when = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)
    return when.strftime("%Y%m%d-%H%M%S")


class Layout:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.root = tmp / "container"
        (self.root / "data/tiles/tile/0").mkdir(parents=True)
        (self.root / "tmp").mkdir()
        make_db(self.root / "data/aics.db")
        (self.root / "data/tiles/checkpoint").write_text("wesupport-ai.com/log\n4\nroot\n\n— sig\n")
        (self.root / "data/tiles/tile/0/000.p").mkdir()
        (self.root / "data/tiles/tile/0/000.p/4").write_bytes(os.urandom(128))
        # The seed sits in /data next to the database and must never be read.
        (self.root / "data/server_master.seed").write_bytes(SEED_BYTES)
        self.compose_dir = tmp / "deploy"
        self.compose_dir.mkdir()
        (self.compose_dir / "docker-compose.yml").write_text("services: {}\n")
        (self.compose_dir / ".env").write_text("AICS_OWNER_PUBKEY=x\nSECRET=" + SEED_BYTES.decode() + "\n")
        self.local = tmp / "backups"
        self.remotes = tmp / "remotes"
        self.calls = tmp / "calls.jsonl"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name, body in (("docker", DOCKER_SHIM), ("rclone", RCLONE_SHIM)):
            shim = self.bin / name
            shim.write_text(f"#!{sys.executable}\n{body}")
            shim.chmod(0o755)
        flock = self.bin / "flock"
        flock.write_text("#!/bin/sh\nexit 0\n")
        flock.chmod(0o755)
        self.run_dir = tmp / "run"
        self.rclone_conf = tmp / "rclone.conf"  # absent unless a test creates it

    def env(self, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("AICS_", "RCLONE_"))}
        env.update(
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
            FAKE_ROOT=str(self.root), FAKE_CALLS=str(self.calls), FAKE_REMOTES=str(self.remotes),
            AICS_COMPOSE_DIR=str(self.compose_dir), RCLONE_CONFIG=str(self.rclone_conf),
            AICS_BACKUP_LOCAL_DIR=str(self.local), RUNTIME_DIRECTORY=str(self.run_dir),
            AICS_BACKUP_MIN_FREE_MB="0",
        )
        env.update(extra)
        return env

    def backup(self, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(BACKUP)], text=True, capture_output=True, env=self.env(**extra))

    def restore(self, *args: str, stdin: str = "no\n", **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(RESTORE), *args], input=stdin, text=True,
                              capture_output=True, env=self.env(**extra))

    def calls_list(self) -> list[list[str]]:
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def stamps(self) -> list[str]:
        if not self.local.exists():
            return []
        return sorted(p.name for p in self.local.iterdir() if p.is_dir() and STAMP_RE.match(p.name))

    def all_bytes_under(self, path: Path) -> bytes:
        """Every file under path, with .gz members decompressed, concatenated."""
        out = b""
        for f in path.rglob("*"):
            if f.is_file():
                data = f.read_bytes()
                out += data
                if f.name.endswith(".gz"):
                    out += gzip.decompress(data)
        return out


@pytest.fixture
def lay(tmp_path: Path) -> Layout:
    return Layout(tmp_path)


def test_local_mode_writes_verified_archives(lay: Layout) -> None:
    result = lay.backup(AICS_BACKUP_REMOTES="")
    assert result.returncode == 0, result.stderr
    assert "LOCAL MODE" in result.stderr and "not off-box" in result.stderr
    [s] = lay.stamps()
    d = lay.local / s
    assert sorted(p.name for p in d.iterdir()) == sorted([f"aics-{s}.db.gz", f"tiles-{s}.tar.gz", "SHA256SUMS"])
    # Private: directory 0700, files 0600 (the database holds notices and hidden bodies).
    assert stat.S_IMODE(lay.local.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in d.iterdir())
    # SHA256SUMS is right; the database round-trips and passes integrity_check.
    sums = dict(reversed(line.split("  ")) for line in (d / "SHA256SUMS").read_text().splitlines())
    for name, digest in sums.items():
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest
    restored = lay.tmp / "restored.db"
    restored.write_bytes(gzip.decompress((d / f"aics-{s}.db.gz").read_bytes()))
    assert integrity(restored) == "ok"
    assert sqlite3.connect(restored).execute("SELECT count(*) FROM leaves").fetchone()[0] == 400
    with tarfile.open(d / f"tiles-{s}.tar.gz") as tar:
        names = tar.getnames()
    assert "tiles/checkpoint" in names and all(n == "tiles" or n.startswith("tiles/") for n in names)
    assert "verified" in result.stdout and "integrity_check ok" in result.stdout
    # No rclone at all in local mode; the seed and deploy/.env are nowhere in the backup.
    assert not any(c[0] == "rclone" for c in lay.calls_list())
    assert SEED_BYTES not in lay.all_bytes_under(lay.local)
    assert not list(lay.local.glob(".incoming-*"))


def test_missing_rclone_config_means_local_mode(lay: Layout) -> None:
    result = lay.backup()  # default remotes "r2 b2", but no rclone config
    assert result.returncode == 0, result.stderr
    assert "rclone config not found" in result.stderr and "LOCAL MODE" in result.stderr
    assert len(lay.stamps()) == 1
    assert not any(c[0] == "rclone" for c in lay.calls_list())


def test_require_remotes_turns_local_mode_into_failure(lay: Layout) -> None:
    result = lay.backup(AICS_BACKUP_REQUIRE_REMOTES="1")
    assert result.returncode != 0
    assert lay.stamps() == []


def test_local_mode_needs_a_local_dir(lay: Layout) -> None:
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_LOCAL_DIR="")
    assert result.returncode != 0 and "AICS_BACKUP_LOCAL_DIR" in result.stderr


def test_retention_keeps_the_newest_days_by_stamp_date(lay: Layout) -> None:
    lay.local.mkdir(mode=0o700)
    old = [stamp(400), stamp(45), stamp(31)]
    kept = [stamp(29), stamp(1), stamp(0.01)]
    for s in old + kept:
        (lay.local / s).mkdir()
        (lay.local / s / f"aics-{s}.db.gz").write_bytes(b"x")
    (lay.local / "not-a-backup").mkdir()                 # never touched: not a stamp
    (lay.local / "20200101-000000.txt").write_text("x")  # a file, not a stamp dir
    (lay.local / ".incoming-20200101-000000").mkdir()    # stale partial of a crashed run
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_KEEP_DAYS="30")
    assert result.returncode == 0, result.stderr
    stamps = lay.stamps()
    assert not set(old) & set(stamps)
    assert set(kept) <= set(stamps) and len(stamps) == len(kept) + 1
    assert (lay.local / "not-a-backup").is_dir() and (lay.local / "20200101-000000.txt").is_file()
    assert not (lay.local / ".incoming-20200101-000000").exists()
    assert result.stdout.count("pruned local backup") == 3


def test_retention_with_one_day(lay: Layout) -> None:
    lay.local.mkdir(mode=0o700)
    two_days, half_day = stamp(2), stamp(0.5)
    for s in (two_days, half_day):
        (lay.local / s).mkdir()
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_KEEP_DAYS="1")
    assert result.returncode == 0, result.stderr
    assert two_days not in lay.stamps() and half_day in lay.stamps() and len(lay.stamps()) == 2


@pytest.mark.parametrize("value", ["0", "-3", "thirty", "1.5"])
def test_bad_keep_days_fails(lay: Layout, value: str) -> None:
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_KEEP_DAYS=value)
    assert result.returncode != 0 and lay.stamps() == []


def test_low_disk_space_prunes_oldest_but_never_the_newest_then_fails(lay: Layout) -> None:
    lay.local.mkdir(mode=0o700)
    existing = [stamp(5), stamp(3), stamp(1)]
    for s in existing:
        (lay.local / s).mkdir()
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_MIN_FREE_MB=str(10**12))
    assert result.returncode != 0
    assert "not enough disk space" in result.stderr
    assert lay.stamps() == [existing[-1]]      # only the newest existing backup is left
    assert not list(lay.local.glob(".incoming-*"))


def corrupt_pages(path: Path) -> None:
    data = bytearray(path.read_bytes())
    page = int.from_bytes(data[16:18], "big") or 65536
    for n in range(2, len(data) // page - 1):
        start = n * page + 8
        data[start:start + 64] = b"\xff" * 64
    path.write_bytes(bytes(data))


@pytest.mark.parametrize("tool", ["python3", "sqlite3", "container"])
@pytest.mark.parametrize("damage", ["not_a_database", "corrupt_pages"])
def test_integrity_failure_exits_nonzero_and_keeps_nothing(lay: Layout, tool: str, damage: str) -> None:
    if tool == "sqlite3" and shutil.which("sqlite3") is None:
        pytest.skip("no sqlite3 CLI on this machine")
    db = lay.root / "data/aics.db"
    if damage == "not_a_database":
        db.write_bytes(b"this is not an sqlite database" * 200)
    else:
        corrupt_pages(db)
    assert integrity(db) != "ok"  # precondition: the fake database really is damaged
    lay.local.mkdir(mode=0o700)
    earlier = stamp(2)
    (lay.local / earlier).mkdir()  # an earlier good backup must survive
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_INTEGRITY_TOOL=tool)
    assert result.returncode != 0
    assert "integrity_check failed" in result.stderr
    assert lay.stamps() == [earlier]
    assert not list(lay.local.glob(".incoming-*"))
    if tool == "container":
        assert any("/tmp/aics-verify.db" in " ".join(c) for c in lay.calls_list())
        assert not (lay.root / "tmp/aics-verify.db").exists()


@pytest.mark.parametrize("tool", ["python3", "sqlite3", "container"])
def test_each_integrity_tool_accepts_a_good_database(lay: Layout, tool: str) -> None:
    if tool == "sqlite3" and shutil.which("sqlite3") is None:
        pytest.skip("no sqlite3 CLI on this machine")
    result = lay.backup(AICS_BACKUP_REMOTES="", AICS_BACKUP_INTEGRITY_TOOL=tool)
    assert result.returncode == 0, result.stderr
    assert len(lay.stamps()) == 1


@pytest.mark.parametrize("planted", ["server_master.seed", "sub/dir/log.seed", ".env", ".env.production"])
def test_seed_guard_refuses_a_seed_or_env_in_the_tiles(lay: Layout, planted: str) -> None:
    target = lay.root / "data/tiles" / planted
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(SEED_BYTES)
    lay.rclone_conf.write_text("[r2]\ntype = s3\n")  # remote mode: the guard must stop the upload too
    result = lay.backup()
    assert result.returncode != 0
    assert "seed" in result.stderr and "never kept or uploaded" in result.stderr
    assert lay.stamps() == []
    assert not any(c[0] == "rclone" for c in lay.calls_list())
    if lay.local.exists():
        assert SEED_BYTES not in lay.all_bytes_under(lay.local)
    assert not lay.remotes.exists()


def test_failed_database_dump_exits_nonzero(lay: Layout) -> None:
    result = lay.backup(AICS_BACKUP_REMOTES="", FAKE_EXEC_FAIL="1")
    assert result.returncode != 0 and "online backup" in result.stderr
    assert lay.stamps() == []


def test_remote_mode_uploads_to_every_remote_and_keeps_local(lay: Layout) -> None:
    lay.rclone_conf.write_text("[r2]\ntype = s3\n[b2]\ntype = b2\n")
    result = lay.backup(AICS_BACKUP_KEEP_DAYS="30")
    assert result.returncode == 0, result.stderr
    assert "LOCAL MODE" not in result.stderr
    [s] = lay.stamps()
    local = sorted(p.name for p in (lay.local / s).iterdir())
    for remote in ("r2", "b2"):
        up = lay.remotes / remote / "aics-backup" / s
        assert sorted(p.name for p in up.iterdir()) == local
        for name in local:
            assert (up / name).read_bytes() == (lay.local / s / name).read_bytes()
    deletes = [c for c in lay.calls_list() if c[:1] == ["rclone"] and "delete" in c]
    assert len(deletes) == 2 and all(c[-2:] == ["--min-age", "30d"] for c in deletes)


def test_remote_mode_without_local_copy(lay: Layout) -> None:
    lay.rclone_conf.write_text("[r2]\ntype = s3\n")
    result = lay.backup(AICS_BACKUP_REMOTES="r2", AICS_BACKUP_LOCAL_DIR="")
    assert result.returncode == 0, result.stderr
    [s] = [p.name for p in (lay.remotes / "r2/aics-backup").iterdir()]
    assert len(list((lay.remotes / "r2/aics-backup" / s).iterdir())) == 3
    assert not lay.local.exists()


def test_one_failing_remote_fails_the_run_but_the_others_still_get_it(lay: Layout) -> None:
    lay.rclone_conf.write_text("[r2]\ntype = s3\n[b2]\ntype = b2\n")
    result = lay.backup(FAKE_RCLONE_FAIL="r2")
    assert result.returncode != 0 and "remote step failed for: r2" in result.stderr
    [s] = lay.stamps()  # the verified local copy is kept
    assert len(list((lay.remotes / "b2/aics-backup" / s).iterdir())) == 3


def test_remote_mode_without_rclone_binary_fails(lay: Layout, tmp_path: Path) -> None:
    lay.rclone_conf.write_text("[r2]\ntype = s3\n")
    (lay.bin / "rclone").unlink()
    env_path = str(lay.bin) + os.pathsep + "/usr/bin:/bin:/usr/sbin:/sbin"
    if shutil.which("rclone", path="/usr/bin:/bin:/usr/sbin:/sbin"):
        pytest.skip("a real rclone is installed in the system path")
    result = lay.backup(PATH=env_path)
    assert result.returncode != 0 and "rclone is not installed" in result.stderr


# --- restore.sh accepts a local backup directory ----------------------------------

def made_backup(lay: Layout) -> Path:
    result = lay.backup(AICS_BACKUP_REMOTES="")
    assert result.returncode == 0, result.stderr
    [s] = lay.stamps()
    return lay.local / s


def vkey(lay: Layout) -> Path:
    path = lay.tmp / "log.vkey"
    path.write_text("wesupport-ai.com/log+01234567+AAAA\n")
    return path


@pytest.mark.parametrize("how", ["archive", "stamp_local"])
def test_restore_from_a_local_backup_verifies_then_stops_at_the_prompt(lay: Layout, how: str) -> None:
    d = made_backup(lay)
    lay.calls.unlink()
    args = ["--archive", str(d)] if how == "archive" else ["--stamp", d.name, "--remote", "local"]
    result = lay.restore(*args, "--vkey-file", str(vkey(lay)))
    assert result.returncode != 0
    assert "aborted; nothing was changed" in result.stderr
    assert "SHA256SUMS match" in result.stdout
    assert "integrity_check: ok" in result.stdout
    calls = lay.calls_list()
    assert any("aics-tlog" in c for c in calls)
    assert not any(c[0] == "rclone" for c in calls)
    assert not any("stop" in c for c in calls)


def test_restore_refuses_an_archive_that_does_not_match_its_sums(lay: Layout) -> None:
    d = made_backup(lay)
    tiles = next(d.glob("tiles-*.tar.gz"))
    with tarfile.open(tiles, "w:gz") as tar:  # a different but well-formed tiles archive
        tar.add(lay.root / "data/tiles", arcname="tiles")
        info = tarfile.TarInfo("tiles/extra")
        tar.addfile(info)
    lay.calls.unlink()
    result = lay.restore("--archive", str(d), "--vkey-file", str(vkey(lay)), "--yes")
    assert result.returncode != 0 and "SHA256 mismatch" in result.stderr
    assert lay.calls_list() == []  # nothing ran in any container


def test_restore_refuses_a_seed_inside_a_local_archive(lay: Layout, tmp_path: Path) -> None:
    d = tmp_path / "copied"
    d.mkdir()
    shutil.copy(next(made_backup(lay).glob("aics-*.db.gz")), d / "aics-x.db.gz")
    with tarfile.open(d / "tiles-x.tar.gz", "w:gz") as tar:
        tar.add(lay.root / "data/tiles", arcname="tiles")
        tar.add(lay.root / "data/server_master.seed", arcname="tiles/server_master.seed")
    lay.calls.unlink()
    result = lay.restore("--archive", str(d), "--vkey-file", str(vkey(lay)), "--yes")
    assert result.returncode != 0 and "seed" in result.stderr
    assert not any("stop" in c for c in lay.calls_list())


def test_restore_archive_errors(lay: Layout, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = lay.restore("--archive", str(empty), "--vkey-file", str(vkey(lay)))
    assert result.returncode != 0 and "does not hold" in result.stderr
    result = lay.restore("--archive", str(tmp_path / "missing"), "--vkey-file", str(vkey(lay)))
    assert result.returncode != 0 and "not found" in result.stderr


def test_units_run_as_root_with_the_local_dir() -> None:
    unit = (REPO / "ops/systemd/aics-backup.service").read_text()
    assert "User=root" in unit and "RuntimeDirectory=aics-backup" in unit
    assert "Environment=AICS_BACKUP_LOCAL_DIR=/var/backups/aics" in unit
    assert "ReadWritePaths=/var/backups/aics" in unit and "ProtectSystem=strict" in unit
    assert "install -d -m 0700 -o root -g root /var/backups/aics" in unit
    timer = (REPO / "ops/systemd/aics-backup.timer").read_text()
    assert "Unit=aics-backup.service" in timer and "Persistent=true" in timer
