"""Run trial agents: per-provider machine-wide slots, a separate user, sandbox, credential proxy,
wall-clock limit, transcripts.  In container mode (a throwaway Linux VM) each agent runs in its own
Docker container instead of the sandbox, separate user and proxy (``container.py``)."""

from __future__ import annotations

import fcntl
import grp
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import container, render, sandbox
from . import providers as prov
from .proxy import CredentialProxy
from .scenarios import TrialSpec
from .transcript import Redactor, final_event, host_of, redact_stream, redact_value

REPO = Path(__file__).resolve().parents[3]
DEFAULT_RUNS = Path(__file__).resolve().parents[1] / "runs"
TRIALS_TMP_ROOT = Path("/private/tmp")


#: Machine-wide slot locks (one file per provider slot) and the single-runner lock.  Outside every
#: sandbox's reach: agents can neither read nor write /private/tmp (on Linux, /tmp of the host, which no
#: agent container sees).
DEFAULT_SLOTS_DIR = Path("/private/tmp/agent-trials-slots" if sys.platform == "darwin" else "/tmp/agent-trials-slots")


class SlotBusy(RuntimeError):
    pass


def _try_lock(path: Path):
    """An open file holding an exclusive flock on ``path``, or None when another process holds it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle


def acquire_machine_slot(provider: str, limit: int, slots_dir: Path, *, poll_s: float = 1.0,
                         stop: threading.Event | None = None):
    """Block until one of ``provider``'s ``limit`` machine-wide slots is free; return its lock handle.

    Every process that uses a provider's account (this runner, a second runner, the orchestrator's GLM
    workers through ``tools/agent-trials/slot.py``) takes the same ``<provider>.<i>.lock`` files, so the
    per-account limits hold across processes, not only within one runner."""
    while True:
        for i in range(limit):
            handle = _try_lock(slots_dir / f"{provider}.{i}.lock")
            if handle is not None:
                return handle
        if stop is not None and stop.is_set():
            raise SlotBusy(provider)
        time.sleep(poll_s)


class ProviderPool:
    """One bounded semaphore per provider, plus a machine-wide slot lock per running agent (fcntl.flock
    on ``slots_dir/<provider>.<i>.lock``); records the peak concurrency it allowed."""

    def __init__(self, limits: dict[str, int], slots_dir: Path | None = None, poll_s: float = 1.0):
        self.limits = dict(limits)
        self.slots_dir = slots_dir
        self.poll_s = poll_s
        self._sems = {name: threading.BoundedSemaphore(n) for name, n in limits.items() if n > 0}
        self._lock = threading.Lock()
        self.active: dict[str, int] = {name: 0 for name in limits}
        self.peak: dict[str, int] = {name: 0 for name in limits}

    def slot(self, provider: str):
        pool = self

        class _Slot:
            handle = None

            def __enter__(self_inner):
                sem = pool._sems.get(provider)
                if sem is None:
                    raise prov.ProviderUnavailable(f"provider {provider} has no concurrency slots")
                sem.acquire()
                try:
                    if pool.slots_dir is not None:
                        # The ceiling, not this run's (possibly lower) limit: the account's limit is machine-wide.
                        ceiling = prov.MAX_CONCURRENCY.get(provider, pool.limits[provider])
                        self_inner.handle = acquire_machine_slot(provider, ceiling, pool.slots_dir,
                                                                 poll_s=pool.poll_s)
                except BaseException:
                    sem.release()
                    raise
                with pool._lock:
                    pool.active[provider] += 1
                    pool.peak[provider] = max(pool.peak[provider], pool.active[provider])
                return self_inner

            def __exit__(self_inner, *exc):
                with pool._lock:
                    pool.active[provider] -= 1
                if self_inner.handle is not None:
                    self_inner.handle.close()  # closing the file releases the flock
                pool._sems[provider].release()
                return False

        return _Slot()


@dataclass
class Execution:
    returncode: int | None
    timed_out: bool


Executor = Callable[[list[str], dict[str, str], str | None, Path, Path, Path, float], Execution]


def execute_subprocess(argv: list[str], env: dict[str, str], stdin: str | None, cwd: Path,
                       stdout_path: Path, stderr_path: Path, timeout: float,
                       on_timeout: Callable[[int], None] | None = None) -> Execution:
    """Start ``argv`` in its own process group, kill the whole group at the time limit.

    ``on_timeout(pgid)`` runs first at the limit: for an agent running as another user, signals from
    the runner reach only ``sudo``, so the runner kills that user's process group through sudo."""
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = subprocess.Popen(argv, env=env, cwd=cwd, stdout=out, stderr=err,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                start_new_session=True)
        if stdin is not None:
            try:
                proc.stdin.write(stdin.encode())
                proc.stdin.close()
            except BrokenPipeError:
                pass
        try:
            return Execution(proc.wait(timeout=timeout), False)
        except subprocess.TimeoutExpired:
            if on_timeout is not None:
                try:
                    on_timeout(proc.pid)
                except Exception:  # noqa: BLE001 - the plain kill below still runs
                    pass
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except (ProcessLookupError, PermissionError):
                    break
                try:
                    proc.wait(timeout=10)
                    break
                except subprocess.TimeoutExpired:
                    continue
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            return Execution(proc.returncode, True)


@dataclass
class RunConfig:
    scenario: str
    base_url: str
    timeout_s: float = 15 * 60
    runs_dir: Path = DEFAULT_RUNS
    stamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    #: None: the defaults of the isolation mode (prov.resolve_limits).
    limits: dict[str, int] | None = None
    zshenv: Path = field(default_factory=lambda: Path.home() / ".zshenv")
    owner_home: Path = field(default_factory=Path.home)
    repo: Path = REPO
    gemini_auth_home: Path | None = None
    gemini_disposable: bool = False
    keep_workdirs: bool = False
    use_sandbox: bool = True
    #: The unprivileged macOS user the agents run as (sudo -n -u).  Required with the sandbox: as the
    #: owner's own user an agent can read every owner process's environment (KERN_PROCARGS2).
    run_as_user: str | None = None
    claude_bin: str | None = None
    gemini_bin: str | None = None
    runner_env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    #: Machine-wide slot and runner locks; None disables them (tests of the in-process pool only).
    slots_dir: Path | None = DEFAULT_SLOTS_DIR
    #: Production hostnames whose addresses are resolved at start and recorded for the report.
    production_hosts: tuple[str, ...] = ("wesupport-ai.com", "api.wesupport-ai.com", "gate.wesupport-ai.com")
    #: ``macos`` (sandbox-exec, separate user, credential proxy) or ``container`` (one Docker container per
    #: agent, on a throwaway Linux VM).
    isolation: str = prov.MACOS
    image: str = container.IMAGE
    container_limits: container.Limits = field(default_factory=container.Limits)
    env_file: Path = container.DEFAULT_ENV_FILE
    codex_auth: Path | None = field(default_factory=lambda: Path.home() / ".codex" / "auth.json")
    docker_bin: str = "docker"
    #: transcript.md cuts each tool result to this many characters (0: no limit).
    transcript_max_chars: int = render.DEFAULT_MAX_CHARS

    def __post_init__(self):
        if self.limits is None:
            self.limits = prov.resolve_limits(isolation=self.isolation)


def refuse_disabled(provider_names: list[str], isolation: str = prov.MACOS) -> None:
    for name in provider_names:
        adapter = prov.ADAPTERS.get(name)
        if adapter is None:
            raise prov.ProviderUnavailable(f"unknown provider {name!r}; known: {', '.join(prov.ADAPTERS)}")
        reason = adapter.unavailable_reason(isolation)
        if reason:
            raise prov.ProviderUnavailable(reason)


def check_run_as_user(user: str, owner_uid: int | None = None) -> None:
    """The agents' user must exist, be unprivileged, not be the owner, and be usable through ``sudo -n``."""
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        raise RuntimeError(f"run-as user {user!r} does not exist; create it first (README, 'Separate user')") from None
    owner_uid = os.getuid() if owner_uid is None else owner_uid
    if entry.pw_uid in (0, owner_uid):
        raise RuntimeError(f"run-as user {user!r} must be a separate unprivileged user, not root or the owner")
    try:
        admin = grp.getgrnam("admin")
        if user in admin.gr_mem or entry.pw_gid == admin.gr_gid:
            raise RuntimeError(f"run-as user {user!r} is an administrator; use a standard user")
    except KeyError:
        pass
    probe = subprocess.run(sandbox.as_user(["/usr/bin/true"], user), capture_output=True, text=True, timeout=30)
    if probe.returncode != 0:
        raise RuntimeError(f"`sudo -n -u {user} /usr/bin/true` failed ({probe.stderr.strip()[:200]}); add the "
                           "sudoers rule from the README ('Separate user')")


def resolve_addresses(hosts: tuple[str, ...]) -> list[str]:
    """The IPv4/IPv6 addresses the production hostnames resolve to now (best effort, for the report)."""
    found: set[str] = set()
    for host in hosts:
        try:
            for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
                found.add(info[4][0])
        except OSError:
            continue
    return sorted(found)


class Runner:
    def __init__(self, config: RunConfig, executor: Executor = execute_subprocess, log=print,
                 proxy_factory: Callable[[], object] | None = None, docker: container.DockerControl | None = None):
        if config.isolation not in prov.ISOLATIONS:
            raise ValueError(f"unknown isolation {config.isolation!r}; choose from {', '.join(prov.ISOLATIONS)}")
        self.config = config
        self.executor = executor
        self.docker = docker or container.DockerControl(config.docker_bin, _docker_client_env(config.runner_env))
        self.image_id: str | None = None
        self.pool = ProviderPool(config.limits, config.slots_dir)
        self.log = log
        self.run_dir = config.runs_dir / config.stamp
        self._base: Path | None = None
        self._base_lock = threading.Lock()
        self._proxy_factory = proxy_factory or (lambda: CredentialProxy(timeout_s=config.timeout_s + 60))
        self.proxy = None
        self.production_ips: list[str] = []

    @property
    def in_container(self) -> bool:
        return self.config.isolation == prov.CONTAINER

    @property
    def run_as(self) -> str | None:
        return self.config.run_as_user if self.config.use_sandbox and not self.in_container else None

    # -- isolation ---------------------------------------------------------

    def trials_base(self) -> Path:
        with self._base_lock:
            if self._base is None:
                # Container mode: only the runner's own capture files and sign-in copies live here (0700).
                root = tempfile.gettempdir() if self.in_container else TRIALS_TMP_ROOT
                self._base = Path(os.path.realpath(tempfile.mkdtemp(prefix="aics-trials-", dir=root)))
                if self.run_as:
                    self._base.chmod(0o711)  # the agents' user may traverse, not list
            return self._base

    def _container_dir(self, slot: str) -> Path:
        """The host side of one container trial: the raw capture and the read-only mount copies (owner only)."""
        root = self.trials_base() / slot
        (root / "capture").mkdir(parents=True, exist_ok=True)
        (root / "mounts").mkdir(exist_ok=True)
        for p in (root, root / "capture", root / "mounts"):
            p.chmod(0o700)
        return root

    def _stage_mounts(self, root: Path, launch: prov.Launch) -> list[tuple[Path, str]]:
        """A per-trial copy of each file to mount read-only.  World-readable inside the owner-only directory, so
        the container's own user can read it whatever its uid on the host; deleted when the trial ends."""
        staged: list[tuple[Path, str]] = []
        for i, (source, target) in enumerate(launch.mount_files):
            copy = root / "mounts" / f"{i}-{Path(target).name}"
            fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(Path(source).read_bytes())
            copy.chmod(0o644)
            staged.append((copy, target))
        return staged

    def _paths(self, slot: str, cli_read: list[Path]) -> sandbox.SandboxPaths:
        base = self.trials_base()
        root = base / slot
        paths = sandbox.SandboxPaths(
            owner_home=Path(os.path.realpath(self.config.owner_home)),
            repo=Path(os.path.realpath(self.config.repo)),
            trials_base=base,
            trial_home=root / "home",
            trial_work=root / "work",
            capture=base / "_capture" / slot,
            cli_read=cli_read,
            extra_deny_read=[Path(os.path.realpath(self.config.runs_dir))],
        )
        for p in (paths.trial_home, paths.trial_work, paths.trial_home / "tmp", paths.capture):
            p.mkdir(parents=True, exist_ok=True)
        if self.run_as:
            # The trial's own dirs belong to the owner but are writable for the agents' user; the sandbox
            # keeps each agent to its own pair.  The capture dir stays the owner's alone (0700).
            (base / "_capture").chmod(0o700)
            paths.capture.chmod(0o700)
            root.chmod(0o711)
            for p in (paths.trial_home, paths.trial_work, paths.trial_home / "tmp"):
                p.chmod(0o777)
        return paths

    def cli_read_paths(self, binary: str) -> list[Path]:
        """The CLI's install directory when it is outside the system paths every agent may read
        (e.g. ~/.local/share/claude/versions for claude)."""
        real = Path(os.path.realpath(binary))
        if any(real == Path(p) or Path(p) in real.parents for p in sandbox.SYSTEM_READ):
            return []
        return [real.parent]

    def prove_sandbox(self) -> list[sandbox.Probe]:
        paths = self._paths("_proof", [])
        profile_path = self._write_profile(paths)
        try:
            probes = sandbox.prove(paths, profile_path, self.run_as)
        finally:
            self._clean_dirs(paths)
        bad = [p for p in probes if not p.ok]
        if bad:
            raise RuntimeError("sandbox proof failed: " + "; ".join(f"{p.label} ({p.output[:120]})" for p in bad))
        return probes

    def _write_profile(self, paths: sandbox.SandboxPaths) -> Path:
        """The profile beside the trial's dirs (sandbox-exec reads it as the agents' user before it applies;
        the capture directory stays the owner's alone)."""
        profile_path = paths.trial_home.parent / "profile.sb"
        profile_path.write_text(sandbox.profile(paths))
        profile_path.chmod(0o644)
        return profile_path

    def _seed(self, paths: sandbox.SandboxPaths, launch: prov.Launch) -> list[Path]:
        """Copy the sign-in files into the trial HOME (0600, owned by the agents' user)."""
        placed: list[Path] = []
        files = [(src.read_bytes(), rel) for src, rel in launch.seed_files]
        files += [(content.encode(), rel) for rel, content in launch.home_files.items()]
        for data, rel in files:
            dest = paths.trial_home / rel
            if self.run_as:
                script = 'umask 077; mkdir -p "$(dirname "$1")" && cat > "$1"'
                result = subprocess.run(sandbox.as_user(["/bin/sh", "-c", script, "sh", str(dest)], self.run_as),
                                        input=data, capture_output=True, timeout=30)
                if result.returncode != 0:
                    raise RuntimeError(f"could not place {rel} as {self.run_as}")
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
            placed.append(dest)
        return placed

    def _remove_as_agent(self, targets: list[Path]) -> None:
        """Delete what the agents' user created (the owner may not unlink inside its directories)."""
        existing = [str(t) for t in targets if os.path.lexists(t)]
        if not existing:
            return
        if self.run_as:
            subprocess.run(sandbox.as_user(["/bin/rm", "-rf", "--", *existing], self.run_as),
                           capture_output=True, timeout=120)
        for target in existing:
            path = Path(target)
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    path.unlink()
                except OSError:
                    pass

    def _clean_dirs(self, paths: sandbox.SandboxPaths) -> None:
        self._remove_as_agent([paths.trial_home, paths.trial_work])
        shutil.rmtree(paths.trial_home.parent, ignore_errors=True)
        shutil.rmtree(paths.capture, ignore_errors=True)

    def _kill_agent_group(self, pgid: int) -> None:
        if self.run_as:
            subprocess.run(sandbox.as_user(["/bin/kill", "-KILL", "--", f"-{pgid}"], self.run_as),
                           capture_output=True, timeout=30)
            subprocess.run(sandbox.as_user(["/usr/bin/pkill", "-KILL", "-g", str(pgid)], self.run_as),
                           capture_output=True, timeout=30)

    # -- one trial ---------------------------------------------------------

    def run_trial(self, spec: TrialSpec, t0: float) -> dict:
        adapter = prov.ADAPTERS[spec.provider]
        out_dir = self.run_dir / spec.scenario / spec.label
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "prompt.txt").write_text(spec.prompt)
        meta: dict = {"scenario": spec.scenario, "provider": spec.provider, "model": adapter.model,
                      "n": spec.n, "group": spec.group, "role": spec.role, "params": spec.params,
                      "base_url": self.config.base_url, "staging_host": host_of(self.config.base_url),
                      "production_ips": self.production_ips, "run_as_user": self.run_as,
                      "isolation": self.config.isolation, "timeout_s": self.config.timeout_s}
        slot = f"{spec.scenario}-{spec.label}"
        if spec.start_delay:
            time.sleep(spec.start_delay)
        queued = time.monotonic()
        with self.pool.slot(spec.provider):
            started = time.monotonic()
            meta["queued_s"] = round(started - queued, 2)
            meta["start_offset_s"] = round(started - t0, 2)
            meta["started_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            paths = None
            container_root: Path | None = None
            seeded: list[Path] = []
            redact = Redactor()
            captured: tuple[Path, Path] | None = None  # the capture files, once the CLI was started
            saved = False
            begin: float | None = None
            try:
                ctx = prov.AdapterContext(trial_home=Path("/nonexistent"), trial_tmp=Path("/nonexistent"),
                                          zshenv=self.config.zshenv, runner_env=self.config.runner_env,
                                          gemini_auth_home=self.config.gemini_auth_home,
                                          gemini_disposable=self.config.gemini_disposable,
                                          claude_bin=self.config.claude_bin, gemini_bin=self.config.gemini_bin,
                                          proxy=self.proxy, owner_home=self.config.owner_home,
                                          isolation=self.config.isolation, env_file=self.config.env_file,
                                          codex_auth=self.config.codex_auth)
                if self.in_container:
                    container_root = self._container_dir(slot)
                    ctx.trial_home, ctx.trial_tmp = Path(container.HOME), Path("/tmp")
                else:
                    binary = adapter.binary_path(ctx)
                    paths = self._paths(slot, self.cli_read_paths(binary))
                    ctx.trial_home, ctx.trial_tmp = paths.trial_home, paths.trial_home / "tmp"
                launch = adapter.build(spec.prompt, ctx)
                redact = Redactor(launch.secrets)
                self._check_secrets(spec, launch)
                meta["argv"] = [redact(a) for a in launch.argv]
                meta["env"] = launch.redacted_env()
                if launch.preflight_problem:
                    meta.update(status="needs_sign_in", reason=launch.preflight_problem, wall_s=0.0)
                    return self._finish(out_dir, meta, redact)
                if self.in_container:
                    name = container.container_name(self.config.stamp, slot)
                    argv, env = container.docker_command(
                        launch, name=name, stamp=self.config.stamp, image=self.config.image,
                        limits=self.config.container_limits, mounts=self._stage_mounts(container_root, launch),
                        docker=self.docker.binary, client_base=self.config.runner_env)
                    if any(secret in a for secret in launch.secrets for a in argv):
                        raise RuntimeError("a secret value would reach the docker command line; refusing")
                    meta["container"] = {"name": name, "image": self.config.image, "image_id": self.image_id,
                                         "limits": asdict(self.config.container_limits),
                                         "mounts": [target for _src, target in launch.mount_files]}
                    meta["docker_argv"] = [redact(a) for a in argv]
                    cwd, capture = container_root, container_root / "capture"

                    def kill(_pgid: int, name: str = name) -> None:
                        self.docker.kill(name)  # killing the docker client would leave the container running
                else:
                    seeded = self._seed(paths, launch)
                    argv, env = launch.argv, launch.env
                    if self.config.use_sandbox:
                        profile_path = self._write_profile(paths)
                        (out_dir / "sandbox.sb").write_text(profile_path.read_text())
                        argv, env = sandbox.command(argv, profile_path, env, self.run_as)
                    cwd, capture, kill = paths.trial_work, paths.capture, self._kill_agent_group
                raw_out, raw_err = capture / "stdout", capture / "stderr"
                captured = (raw_out, raw_err)
                begin = time.monotonic()
                extra = {"on_timeout": kill} if self.executor is execute_subprocess else {}
                result = self.executor(argv, env, launch.stdin, cwd, raw_out, raw_err,
                                       self.config.timeout_s, **extra)
                meta["wall_s"] = round(time.monotonic() - begin, 1)
                meta["returncode"] = result.returncode
                stdout, stderr = _save_streams(out_dir, raw_out, raw_err, redact)
                saved = True
                problem = adapter.auth_problem(stdout, stderr, result.returncode)
                if result.timed_out:
                    meta["status"] = "timeout"
                elif problem:
                    meta.update(status="needs_sign_in", reason=problem)
                elif result.returncode == 0:
                    meta["status"] = "ok"
                else:
                    meta["status"] = "error"
            except prov.ProviderUnavailable as exc:
                meta.update(status="unavailable", reason=str(exc), wall_s=0.0)
            except Exception as exc:  # noqa: BLE001 - one failing trial must not stop the others
                if "wall_s" not in meta:
                    meta["wall_s"] = round(time.monotonic() - begin, 1) if begin is not None else 0.0
                meta.update(status="runner_error", reason=redact(f"{type(exc).__name__}: {exc}"))
            finally:
                if captured is not None and not saved:
                    # The CLI ran (or was being run) but its output was not saved yet: keep what was captured so
                    # far, redacted, before the raw files are deleted below.
                    try:
                        _save_streams(out_dir, *captured, redact)
                        meta["partial_output"] = True
                    except Exception as exc:  # noqa: BLE001
                        meta["save_error"] = f"{type(exc).__name__}: {exc}"
                if paths is not None:
                    # Always, even with --keep-workdirs: the unredacted output and the copied sign-in files.
                    for raw in (paths.capture / "stdout", paths.capture / "stderr"):
                        raw.unlink(missing_ok=True)
                    self._remove_as_agent(seeded)
                    if not self.config.keep_workdirs:
                        self._clean_dirs(paths)
                if container_root is not None:
                    # The raw output and the sign-in copies; the container's own HOME was a tmpfs (--rm).
                    shutil.rmtree(container_root, ignore_errors=True)
        return self._finish(out_dir, meta, redact)

    def _check_secrets(self, spec: TrialSpec, launch: prov.Launch) -> None:
        """No secret in the prompt or the CLI's argv.  macOS mode: none in the environment either (the proxy holds
        them).  Container mode: only in the variables the provider declares secret (passed by name)."""
        for secret in launch.secrets:
            if secret in spec.prompt:
                raise RuntimeError("a secret value occurs in the prompt; refusing to start")
            in_env = [k for k, v in launch.env.items() if secret in v
                      and not (self.in_container and k in launch.secret_env)]
            if in_env or any(secret in a for a in launch.argv):
                raise RuntimeError("a secret value would reach the agent's environment or argv; refusing")

    def _finish(self, out_dir: Path, meta: dict, redact: Callable[[str], str] | None = None) -> dict:
        meta["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            # Every agent gets its readable transcript, also after a timeout, an error or no run at all.
            render.write_transcript(out_dir, meta=meta, redact=redact, max_chars=self.config.transcript_max_chars)
        except Exception as exc:  # noqa: BLE001 - a rendering problem must not lose the trial's results
            meta["transcript_error"] = f"{type(exc).__name__}: {exc}"
        (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
        self.log(f"  {meta['scenario']}/{meta['provider']}-{meta['n']}: {meta.get('status')}"
                 + (f" ({meta['reason']})" if meta.get("reason") else "")
                 + (f" in {meta['wall_s']} s" if meta.get("wall_s") else ""))
        return meta

    # -- the whole run -----------------------------------------------------

    def run(self, trials: list[TrialSpec]) -> list[dict]:
        refuse_disabled(sorted({t.provider for t in trials}), self.config.isolation)
        runner_lock = None
        if self.config.slots_dir is not None:
            runner_lock = _try_lock(self.config.slots_dir / "runner.lock")
            if runner_lock is None:
                raise SlotBusy("another agent-trials runner is running on this machine (one at a time: its agents "
                               "share the run-as user, which is swept at the end of each run)")
        try:
            return self._run(trials)
        finally:
            if runner_lock is not None:
                runner_lock.close()

    def _run(self, trials: list[TrialSpec]) -> list[dict]:
        if self.in_container:
            container.check_env_file(self.config.env_file)
            self.image_id = self.docker.check(self.config.image)
        elif self.config.use_sandbox:
            if not sandbox.available():
                raise RuntimeError("sandbox-exec is not available; refusing to run agents unsandboxed (on a Linux "
                                   "VM, use --isolation container)")
            if not self.config.run_as_user:
                raise RuntimeError("refusing to run agents as the owner's own user: any process of that user can "
                                   "read the environment of every other (KERN_PROCARGS2), and every shell holds "
                                   "ZAI_API_KEY; pass --run-as-user (README, 'Separate user')")
            check_run_as_user(self.config.run_as_user)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.trials_base()
        self.production_ips = resolve_addresses(self.config.production_hosts)
        # Container mode needs no proxy: the VM holds trial credentials only, and they go into each container.
        self.proxy = None if self.in_container else self._proxy_factory()
        start = getattr(self.proxy, "start", None)
        if start is not None:
            start()
        try:
            if self.config.use_sandbox and not self.in_container:
                probes = self.prove_sandbox()
                (self.run_dir / "sandbox-proof.json").write_text(json.dumps(
                    [{"label": p.label, "path": str(p.path), "kind": p.kind, "exists": p.exists_outside,
                      "denied": p.denied, "ok": p.ok} for p in probes], indent=2))
                self.log("sandbox proof: " + ", ".join(f"{p.label} {'ok' if p.ok else 'FAILED'}" for p in probes))
            (self.run_dir / "run.json").write_text(json.dumps({
                "stamp": self.config.stamp, "scenario": self.config.scenario, "base_url": self.config.base_url,
                "timeout_s": self.config.timeout_s, "limits": self.config.limits, "run_as_user": self.run_as,
                "production_ips": self.production_ips, "isolation": self.config.isolation,
                **({"image": self.config.image, "image_id": self.image_id,
                    "container_limits": asdict(self.config.container_limits)} if self.in_container else {}),
                "trials": [{"provider": t.provider, "n": t.n, "group": t.group, "role": t.role,
                            "start_delay": t.start_delay} for t in trials],
            }, indent=2))
            results: list[dict] = [None] * len(trials)  # type: ignore[list-item]
            t0 = time.monotonic()

            def work(i: int, spec: TrialSpec):
                results[i] = self.run_trial(spec, t0)

            threads = [threading.Thread(target=work, args=(i, spec), daemon=True) for i, spec in enumerate(trials)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            (self.run_dir / "run.json").write_text(json.dumps({
                **json.loads((self.run_dir / "run.json").read_text()),
                "peak_concurrency": self.pool.peak,
            }, indent=2))
            return results
        finally:
            stop = getattr(self.proxy, "stop", None)
            if stop is not None:
                stop()
            if self.in_container:
                # Nothing of this run may outlive it (a container whose client was killed, for instance).
                self.docker.sweep(self.config.stamp)
            if self.run_as:
                # Nothing an agent started may outlive the run (single runner: the user is the harness's alone).
                subprocess.run(sandbox.as_user(["/usr/bin/pkill", "-KILL", "-U", self.run_as], self.run_as),
                               capture_output=True, timeout=30)
            # Container mode keeps nothing on the host: each agent's HOME and work dir were the container's tmpfs.
            if self._base is not None and (self.in_container or not self.config.keep_workdirs):
                for root in sorted(self._base.iterdir()) if self._base.exists() else []:
                    self._remove_as_agent([root / "home", root / "work"])
                shutil.rmtree(self._base, ignore_errors=True)


def _docker_client_env(runner_env: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in runner_env.items() if k in container.DOCKER_CLIENT_ENV}
    env["PATH"] = runner_env.get("PATH") or "/usr/local/bin:/usr/bin:/bin"
    return env


_final_event = final_event


def _save_streams(out_dir: Path, raw_out: Path, raw_err: Path, redact: Callable[[str], str]) -> tuple[str, str]:
    """Save the CLI's captured stdout (``transcript.jsonl``: the event stream as received, redacted event by event)
    and stderr (``stderr.txt``), and its final event (``result.json``) when it has one.  Works on whatever was
    captured so far, so also after a timeout kill or a runner error.  Returns the unredacted text for the auth
    checks; it is never written anywhere."""
    stdout = raw_out.read_text(errors="replace") if raw_out.exists() else ""
    stderr = raw_err.read_text(errors="replace") if raw_err.exists() else ""
    (out_dir / render.RAW_STREAM).write_text(redact_stream(stdout, redact))
    (out_dir / render.STDERR).write_text(redact(stderr))
    final = final_event(stdout)
    if final is not None:
        (out_dir / "result.json").write_text(json.dumps(redact_value(final, redact), indent=2, ensure_ascii=False))
    return stdout, stderr


def describe(spec: TrialSpec) -> dict:
    return asdict(spec) | {"label": spec.label}
