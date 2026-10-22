"""Container isolation for a throwaway Linux VM: one fresh Docker container per agent.

The macOS mode (``sandbox.py``, a separate user, the credential proxy) exists because there the agents
run next to the owner's own keys.  On a VM that holds nothing but trial credentials, each agent instead
runs in its own container from the image built from ``container/Dockerfile`` (README, "Cloud VM
(container mode)"):

* ``--read-only`` root file system; the agent's HOME (``/home/agent``) and ``/tmp`` are size-limited
  tmpfs mounts that vanish with the container (``--rm``);
* ``--network bridge``; on the VM, ``bootstrap-vm.sh`` rejects container TCP to production's gate
  ports 7700/7701 in the DOCKER-USER chain;
* memory (no swap), pids and CPU limits; every capability dropped, ``no-new-privileges``, uid 1000;
* no Docker socket and no host directory: the only host file a container sees is, for sol, a
  per-trial read-only copy of the codex sign-in (``auth.json``);
* only the environment variables the provider needs.  Secret values travel by name (``-e NAME``, the
  value in the docker client's own environment), so they appear in no argv and in no saved file;
* ``--log-driver none``: the daemon keeps no unredacted copy of the output (the runner captures the
  attached streams and redacts them); ``--pull never``: a missing image is an error, never a download.

Inside the container the CLIs run with their own permission prompts off, because the container is
the sandbox.  The agent can read its own provider's credential (its environment, or CODEX_HOME), so
the VM must hold trial-only credentials.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

IMAGE = "agent-trials:latest"
#: The image's ``agent`` user (container/Dockerfile).
AGENT_UID = 1000
HOME = "/home/agent"
CODEX_HOME = HOME + "/.codex"
#: Where sol's read-only sign-in copy is mounted; the image's entrypoint copies it into CODEX_HOME.
CODEX_AUTH_TARGET = "/run/agent-trials/codex-auth.json"
PATH = "/usr/local/bin:/usr/bin:/bin"
#: Credentials for container mode: plain NAME=value lines, parsed, never sourced (bootstrap-vm.sh).
DEFAULT_ENV_FILE = Path("/etc/agent-trials/env")
#: The docker client's own configuration, passed on from the runner's environment when set.
DOCKER_CLIENT_ENV = ("HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
                     "DOCKER_TLS_VERIFY")

_SIZE = re.compile(r"^[1-9][0-9]*[kmg]?$", re.I)
_CPUS = re.compile(r"^(?:[1-9][0-9]*|[0-9]+\.[0-9]+)$")
_NAME = re.compile(r"[^a-z0-9_.-]+")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Limits:
    memory: str = "2g"
    pids: int = 512
    cpus: str = "2"
    home_size: str = "1g"
    tmp_size: str = "512m"

    def __post_init__(self):
        for label, value in (("memory", self.memory), ("home size", self.home_size), ("tmp size", self.tmp_size)):
            if not _SIZE.match(str(value)):
                raise ValueError(f"container {label} must look like 2g or 512m, got {value!r}")
        if not _CPUS.match(str(self.cpus)) or float(self.cpus) <= 0:
            raise ValueError(f"container cpus must be a positive number, got {self.cpus!r}")
        if int(self.pids) < 64:
            raise ValueError(f"container pids limit must be at least 64, got {self.pids!r}")


DEFAULT_LIMITS = Limits()


def base_env() -> dict[str, str]:
    """The environment every agent container starts with (the image's own ENV adds nothing)."""
    return {
        "HOME": HOME,
        "TMPDIR": "/tmp",
        "PATH": PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "USER": "agent",
        "LOGNAME": "agent",
        "SHELL": "/bin/bash",
    }


def container_name(stamp: str, slot: str) -> str:
    return "agent-trials-" + _NAME.sub("-", f"{stamp}-{slot}".lower()).strip("-")


def run_label(stamp: str) -> str:
    return f"agent-trials.run={stamp}"


def docker_command(launch, *, name: str, stamp: str, image: str = IMAGE, limits: Limits = DEFAULT_LIMITS,
                   mounts: list[tuple[Path, str]] | tuple = (), docker: str = "docker",
                   client_base: dict[str, str] | None = None) -> tuple[list[str], dict[str, str]]:
    """The ``docker run`` argv and the docker client's environment that start ``launch`` in a fresh container.

    ``mounts`` are (host file, container path) pairs, bind-mounted read-only.  Variables named in
    ``launch.secret_env`` are passed by name only; their values go into the returned client environment.
    """
    uid = f"{AGENT_UID}:{AGENT_UID}"
    argv = [
        docker, "run", "--rm", "--pull", "never", "--name", name,
        "--label", "agent-trials=1", "--label", run_label(stamp),
        "--init", "--network", "bridge", "--read-only",
        "--tmpfs", f"{HOME}:rw,exec,nosuid,nodev,size={limits.home_size},mode=0700,uid={AGENT_UID},gid={AGENT_UID}",
        "--tmpfs", f"/tmp:rw,exec,nosuid,nodev,size={limits.tmp_size},mode=1777",
        "--memory", limits.memory, "--memory-swap", limits.memory,
        "--pids-limit", str(int(limits.pids)), "--cpus", str(limits.cpus),
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", uid, "--workdir", HOME, "--log-driver", "none",
    ]
    if launch.stdin is not None:
        argv.append("--interactive")
    client = {"PATH": (client_base or {}).get("PATH") or "/usr/local/bin:/usr/bin:/bin"}
    for key in DOCKER_CLIENT_ENV:
        value = (client_base or {}).get(key)
        if value:
            client[key] = value
    for key, value in sorted(launch.env.items()):
        if not _ENV_NAME.match(key):
            raise ValueError(f"not an environment variable name: {key!r}")
        if key in launch.secret_env:
            argv += ["--env", key]
            client[key] = value
        else:
            argv += ["--env", f"{key}={value}"]
    for source, target in mounts:
        for path in (str(source), target):
            if "," in path or "\n" in path:
                raise ValueError(f"path not usable in a --mount option: {path!r}")
        argv += ["--mount", f"type=bind,source={source},target={target},readonly"]
    argv += [image, *launch.argv]
    return argv, client


def check_env_file(path: Path) -> None:
    """Refuse a credentials file other users of the VM could read (as ssh refuses a loose key)."""
    try:
        st = path.stat()
    except FileNotFoundError:
        return  # every provider that needs it then reports "needs sign-in"
    if not path.is_file():
        raise RuntimeError(f"{path} is not a regular file")
    if st.st_mode & 0o077:
        raise RuntimeError(f"{path} is readable by other users (mode {st.st_mode & 0o777:o}); chmod 600 {path}")


class DockerControl:
    """The few docker calls the runner makes besides ``docker run``: check the image, kill a container at
    the time limit, and remove whatever of this run is left at the end."""

    def __init__(self, docker: str = "docker", env: dict[str, str] | None = None,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self.binary = docker
        self.env = env if env is not None else {
            k: v for k, v in os.environ.items() if k in DOCKER_CLIENT_ENV or k == "PATH"}
        self._run = run

    def _call(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return self._run([self.binary, *args], env=self.env, capture_output=True, text=True, timeout=timeout)

    def check(self, image: str) -> str:
        """The image id, or RuntimeError when docker or the image is missing."""
        if shutil.which(self.binary, path=self.env.get("PATH")) is None:
            raise RuntimeError(f"{self.binary} not found: container mode needs Docker (run container/bootstrap-vm.sh)")
        result = self._call("image", "inspect", "--format", "{{.Id}}", image)
        if result.returncode != 0:
            raise RuntimeError(f"docker image {image} not found or docker not usable ({result.stderr.strip()[:200]}); "
                               "build it with container/bootstrap-vm.sh, and log in again after it adds you to "
                               "the docker group")
        return result.stdout.strip()

    def kill(self, name: str) -> None:
        for args in (("kill", name), ("rm", "-f", name)):
            try:
                self._call(*args, timeout=60)
            except (OSError, subprocess.SubprocessError):
                pass

    def sweep(self, stamp: str) -> None:
        try:
            listed = self._call("ps", "-aq", "--filter", f"label={run_label(stamp)}")
            ids = listed.stdout.split()
            if ids:
                self._call("rm", "-f", *ids, timeout=120)
        except (OSError, subprocess.SubprocessError):
            pass
