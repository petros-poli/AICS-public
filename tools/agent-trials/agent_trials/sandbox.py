"""macOS sandbox-exec profile for one trial agent, the separate-user wrapper, and a proof that both hold.

Policy (last matching rule wins in SBPL, so the order below matters):

* reads: denied by default.  Allowed: file metadata (stat) anywhere, the root directory, the
  system paths in :data:`SYSTEM_READ`, the CLI's own install directory and this trial's
  HOME/work.  ``~/.ssh``, ``~/.aics``, ``~/.zshenv``, the repository, the capture and runs
  directories are denied again last, whatever came before.  So the owner's HOME, other
  trials, ``/private/tmp`` (the Claude sessions' task outputs), ``/private/var/folders``,
  ``/Volumes``, ``/Users`` and ``/Library/Keychains`` are all out of reach;
* writes: denied everywhere except this trial's HOME/work and ``/dev``;
* network: allowed, except TCP to ports 7700/7701 on any host (production's text gate; on
  the single-IP VPS ``test.wesupport-ai.com:7700/7701`` *is* production);
* signals: only to the agent itself and to processes in the same sandbox;
* the login keychain service (``com.apple.SecurityServer``) is not reachable.

What a profile cannot do: stop a process from reading the environment of other processes of
the same user (``sysctl KERN_PROCARGS2``; ``(deny process-info*)`` breaks Python, a
``kern.procargs2`` sysctl rule does not hold).  Every shell of the owner holds ``ZAI_API_KEY``
from ``~/.zshenv``, so agents run as a separate unprivileged user (:func:`command` with
``run_as``); the kernel then refuses KERN_PROCARGS2 and signals for the owner's processes.
:func:`prove` checks exactly that with a canary process and refuses to pass otherwise.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
SUDO = "/usr/bin/sudo"
ENV = "/usr/bin/env"

#: System locations every agent may read: binaries, libraries, the system config in /etc
#: (resolver, TLS roots, zsh/sh startup files), time zones, and the command-line tools that
#: /usr/bin/python3 and git hand off to.  Nothing here belongs to a user.
SYSTEM_READ: tuple[str, ...] = (
    "/System", "/usr", "/bin", "/sbin", "/opt/homebrew", "/private/etc", "/private/var/db/timezone",
    "/private/var/select", "/Library/Developer/CommandLineTools", "/dev",
)
#: Production's text gate ports: no agent may open a TCP connection to them, on any host.
PRODUCTION_GATE_PORTS = (7700, 7701)


def available() -> bool:
    return sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC)


def _q(path: str | Path) -> str:
    text = os.path.realpath(str(path))
    if '"' in text or "\\" in text:
        raise ValueError(f"path not representable in a sandbox profile: {text!r}")
    return f'"{text}"'


@dataclass
class SandboxPaths:
    owner_home: Path
    repo: Path
    trials_base: Path
    trial_home: Path
    trial_work: Path
    capture: Path
    #: Directories the CLI needs to read outside :data:`SYSTEM_READ` (its install directory).
    cli_read: list[Path] = field(default_factory=list)
    #: Extra paths whose reads are always denied (the runs directory).
    extra_deny_read: list[Path] = field(default_factory=list)

    def protected(self) -> list[Path]:
        home = self.owner_home
        return [home / ".ssh", home / ".aics", home / ".zshenv", self.repo, self.capture, *self.extra_deny_read]


def profile(paths: SandboxPaths) -> str:
    home = paths.owner_home
    allow_read = [*SYSTEM_READ, *paths.cli_read, paths.trial_home, paths.trial_work]
    ports = " ".join(f'(remote tcp "*:{p}")' for p in PRODUCTION_GATE_PORTS)
    lines = [
        "(version 1)",
        "(allow default)",
        "; reads: deny by default; stat anywhere, list only the root directory",
        "(deny file-read*)",
        "(allow file-read-metadata)",
        '(allow file-read* (literal "/"))',
        "; the system, the CLI's install directory and this trial only",
        "(allow file-read* " + " ".join(f"(subpath {_q(p)})" for p in allow_read) + ")",
        "; always denied, whatever was allowed above",
        "(deny file-read* "
        + f"(subpath {_q(home / '.ssh')}) (subpath {_q(home / '.aics')}) (literal {_q(home / '.zshenv')}) "
        + f"(subpath {_q(paths.repo)}) (subpath {_q(paths.capture)})"
        + "".join(f" (subpath {_q(p)})" for p in paths.extra_deny_read)
        + ")",
        "; writes: only this trial and /dev",
        "(deny file-write*)",
        f'(allow file-write* (subpath "/dev") (subpath {_q(paths.trial_home)}) (subpath {_q(paths.trial_work)}))',
        f"(deny file-write* (subpath {_q(paths.capture)}) (subpath {_q(paths.repo)}))",
        "; production's text gate (7700 TLS, 7701 plain) on any host: on the VPS, test.* shares production's IP",
        f"(deny network-outbound {ports})",
        "; signals: the agent and its own sandboxed processes only",
        "(deny signal)",
        "(allow signal (target self))",
        "(allow signal (target same-sandbox))",
        "; the login keychain stays out of reach of the agent's tools",
        '(deny mach-lookup (global-name "com.apple.SecurityServer"))',
    ]
    return "\n".join(lines) + "\n"


def wrap(argv: list[str], profile_path: Path) -> list[str]:
    return [SANDBOX_EXEC, "-f", str(profile_path), *argv]


def command(argv: list[str], profile_path: Path, env: dict[str, str],
            run_as: str | None) -> tuple[list[str], dict[str, str]]:
    """The argv and environment that start ``argv`` inside the sandbox, as user ``run_as`` when given.

    As another user: ``sudo -n -u <user> -- /usr/bin/env -i K=V ... sandbox-exec -f <profile> argv``.
    ``sudo`` resets the environment, so the agent's environment travels in ``env -i``'s arguments;
    it holds no secret (the credential proxy keeps the real ones), only dummy tokens.
    """
    inner = wrap(argv, profile_path)
    if run_as is None:
        return inner, env
    assignments = [f"{k}={v}" for k, v in sorted(env.items())]
    return [SUDO, "-n", "-u", run_as, "--", ENV, "-i", *assignments, *inner], {"PATH": "/usr/bin:/bin"}


def as_user(argv: list[str], run_as: str | None) -> list[str]:
    """``argv`` as ``run_as`` (no sandbox), for setup and cleanup steps; unchanged when ``run_as`` is None."""
    return argv if run_as is None else [SUDO, "-n", "-u", run_as, "--", *argv]


@dataclass
class Probe:
    label: str
    path: Path
    #: "read" | "write-denied" | "write-allowed" | "net-denied" | "env-hidden" | "signal-denied"
    kind: str
    exists_outside: bool
    returncode: int
    output: str

    @property
    def denied(self) -> bool:
        if self.kind == "env-hidden":
            return self.returncode == 0 and "HIDDEN" in self.output and "LEAK" not in self.output
        if self.kind in ("read", "write-denied"):
            # EPERM from the sandbox, or EACCES from file permissions when running as another user.
            return self.returncode != 0 and ("Operation not permitted" in self.output
                                             or "Permission denied" in self.output)
        return self.returncode != 0 and "Operation not permitted" in self.output

    @property
    def ok(self) -> bool:
        if self.kind == "write-allowed":
            return self.returncode == 0
        if self.kind == "read" and not self.exists_outside:
            # A target that does not exist proves nothing either way; it is reported, not failed.
            return True
        return self.denied


#: Reads another process's environment the way an agent would (KERN_PROCARGS2).  Prints HIDDEN
#: when the kernel refuses or the canary is absent, LEAK when the canary value is visible.
_PROCARGS_PROBE = r"""
import ctypes, ctypes.util, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
mib = (ctypes.c_int * 3)(1, 49, int(sys.argv[1]))
size = ctypes.c_size_t(0)
if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
    print("HIDDEN refused errno", ctypes.get_errno()); sys.exit(0)
buf = ctypes.create_string_buffer(size.value)
if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
    print("HIDDEN refused errno", ctypes.get_errno()); sys.exit(0)
print("LEAK" if sys.argv[2].encode() in buf.raw[: size.value] else "HIDDEN no canary")
"""


def _run_in(profile_path: Path, script: str, cwd: Path, env: dict[str, str], run_as: str | None,
            *, argv: list[str] | None = None) -> tuple[int, str]:
    full, full_env = command(argv or ["/bin/sh", "-c", script], profile_path, env, run_as)
    result = subprocess.run(full, cwd=cwd, env=full_env, capture_output=True, text=True, timeout=30)
    return result.returncode, (result.stdout + result.stderr).strip()


def _start_canary() -> tuple[subprocess.Popen, str]:
    """A process of the runner's user whose environment holds a canary secret, like the owner's shells
    (which hold ZAI_API_KEY).  Started from the runner's own Python, which, unlike a platform binary,
    exposes its environment to KERN_PROCARGS2 of the same user."""
    value = "agent-trials-canary-" + secrets.token_hex(12)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                            env={"AGENT_TRIALS_CANARY": value, "PATH": "/usr/bin:/bin"},
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, value


def prove(paths: SandboxPaths, profile_path: Path, run_as: str | None = None) -> list[Probe]:
    """Run probes inside the sandbox, as the agents' user: forbidden reads, writes, gate ports, the
    environment and signals of the runner's processes must all be refused, and the trial's own work
    directory must be writable.  A canary file in the capture directory makes the read proof
    meaningful even when the owner's ~/.ssh does not exist."""
    paths.capture.mkdir(parents=True, exist_ok=True)
    canary = paths.capture / "sandbox-canary.txt"
    canary.write_text("canary\n")
    if run_as is not None:
        # Readable for the agents' user as far as file permissions go, so that only the sandbox stops it.
        paths.capture.chmod(0o711)
        canary.chmod(0o644)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(paths.trial_home), "LANG": "C"}
    probes: list[Probe] = []
    uid = os.getuid()
    targets = [
        ("owner ~/.ssh", paths.owner_home / ".ssh"),
        ("owner ~/.zshenv", paths.owner_home / ".zshenv"),
        ("owner ~/.aics", paths.owner_home / ".aics"),
        ("owner HOME listing", paths.owner_home),
        ("repository", paths.repo),
        ("capture canary", canary),
        ("/private/tmp listing", Path("/private/tmp")),
        (f"Claude task outputs /private/tmp/claude-{uid}", Path(f"/private/tmp/claude-{uid}")),
        ("/private/var/folders listing", Path("/private/var/folders")),
        ("/Volumes listing", Path("/Volumes")),
        ("/Users listing", Path("/Users")),
        ("System keychain", Path("/Library/Keychains/System.keychain")),
    ]
    for label, target in targets:
        exists = target.exists()
        script = f'ls -A "{target}"' if target.is_dir() else f'cat "{target}"'
        code, out = _run_in(profile_path, script + " >/dev/null", paths.trial_work, env, run_as)
        probes.append(Probe(label, target, "read", exists, code, out))
    stamp = f"{os.getpid()}-{secrets.token_hex(4)}"
    for label, target in (("write into owner HOME", paths.owner_home / f".agent-trials-write-probe-{stamp}"),
                          ("write into repository", paths.repo / f".agent-trials-write-probe-{stamp}"),
                          ("write into /private/tmp", Path(f"/private/tmp/agent-trials-write-probe-{stamp}"))):
        code, out = _run_in(profile_path, f'echo x > "{target}"', paths.trial_work, env, run_as)
        probes.append(Probe(label, target, "write-denied", False, code, out))
        try:
            target.unlink()
        except (FileNotFoundError, PermissionError):
            pass
    for port in PRODUCTION_GATE_PORTS:
        code, out = _run_in(profile_path, f"/usr/bin/nc -v -z -w 2 127.0.0.1 {port}", paths.trial_work, env, run_as)
        probes.append(Probe(f"TCP to port {port}", Path(f"tcp/{port}"), "net-denied", True, code, out))
    proc, value = _start_canary()
    try:
        code, out = _run_in(profile_path, "", paths.trial_work, env, run_as,
                            argv=["/usr/bin/python3", "-c", _PROCARGS_PROBE, str(proc.pid), value])
        out = "\n".join(line for line in out.splitlines() if "xcrun" not in line)  # xcrun cache noise
        probes.append(Probe("runner's process environment (KERN_PROCARGS2)", Path(f"pid/{proc.pid}"),
                            "env-hidden", True, code, out.replace(value, "<canary>")))
        code, out = _run_in(profile_path, f"kill -CONT {proc.pid}", paths.trial_work, env, run_as)
        probes.append(Probe("signal to the runner's processes", Path(f"pid/{proc.pid}"), "signal-denied", True,
                            code, out))
    finally:
        proc.kill()
        proc.wait()
    own = paths.trial_work / f"sandbox-write-probe-{stamp}"
    code, out = _run_in(profile_path, f'echo x > "{own}" && rm "{own}"', paths.trial_work, env, run_as)
    probes.append(Probe("write into own work dir", own, "write-allowed", True, code, out))
    canary.unlink(missing_ok=True)
    return probes
