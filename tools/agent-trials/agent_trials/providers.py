"""Provider adapters: how each model CLI is started as an unattended agent.

An adapter only *builds* a launch (argv, environment, stdin, files to seed into the
per-trial HOME); the runner executes it inside the sandbox.  Nothing here runs a model.

Secrets: the z.ai key is read from ``~/.zshenv`` (never from the runner's own
environment, never sourced through a shell); the sonnet adapter's long-lived Claude Code
OAuth token (``claude setup-token``) comes from ``CLAUDE_CODE_OAUTH_TOKEN`` in the
runner's environment or ``~/.zshenv``.  Neither reaches the agent: both stay in the
runner's :class:`~agent_trials.proxy.CredentialProxy`, and the CLI gets the proxy's
loopback URL and a per-run dummy token instead (``ctx.proxy.route``).

The gemini adapter cannot be proxied that way: it copies a sign-in (an OAuth refresh
token) into the trial HOME, where the agent can read it.  It starts only when the owner
has confirmed that the sign-in belongs to a dedicated, disposable account
(``--gemini-account-is-disposable`` or a marker file in the sign-in HOME), and never
from the owner's own ``~/.gemini``.  Every secret value an adapter touches is returned
in ``Launch.secrets`` so the runner can redact it from transcripts and can assert that
no prompt carries it.

Container mode (``ctx.isolation == "container"``, a throwaway Linux VM, see ``container.py``):
the credentials come from the VM's ``/etc/agent-trials/env`` (parsed, never sourced) and go
straight into the agent's container environment, by name only (no proxy: the VM holds
nothing but trial credentials); sol gets a read-only copy of the VM's codex sign-in.  The
CLIs run there with their permission prompts off, because the container is the sandbox.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import container

#: Hard per-provider concurrency ceilings (owner, 2026-10-19).  The runner may lower
#: them on the command line, never raise them.
MAX_CONCURRENCY: dict[str, int] = {
    "sonnet": 4,
    "glm53": 2,
    "glm53flash": 4,
    "gemini": 4,
    "sol": 2,
}
#: Concurrency when the command line does not lower it: the ceiling, except sol (save the
#: owner's ChatGPT usage: one at a time unless asked for two).
DEFAULT_CONCURRENCY: dict[str, int] = {**MAX_CONCURRENCY, "sol": 1}
#: Isolation modes: the macOS sandbox next to the owner's keys, or one Docker container per agent on a
#: throwaway Linux VM.
MACOS = "macos"
CONTAINER = "container"
ISOLATIONS = (MACOS, CONTAINER)
#: Container mode's defaults: every ceiling, sol's 2 included (owner, 2026-10-19).
CONTAINER_CONCURRENCY: dict[str, int] = dict(MAX_CONCURRENCY)

ZAI_BASE_URL = "https://api.z.ai/api/anthropic"
ANTHROPIC_API_URL = "https://api.anthropic.com"
#: The beta flag the Anthropic API wants with a Claude Code OAuth bearer token.
OAUTH_BETA = "oauth-2025-04-20"
CLAUDE_TOOLS = ("Bash", "Read", "Write", "WebSearch", "WebFetch")
GEMINI_MODEL = "gemini-3.8-flash"
GEMINI_SEED_FILES = (".gemini/oauth_creds.json", ".gemini/google_accounts.json", ".gemini/settings.json")
#: A file in a sign-in HOME by which the owner states, once, that its account is disposable.
DISPOSABLE_MARKER = ".agent-trials-disposable-account"

#: Base system PATH for every agent; the CLI binary itself is started by absolute path.
BASE_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


class ProviderUnavailable(RuntimeError):
    """The provider cannot be started at all (disabled, or its CLI is missing)."""


@dataclass
class Launch:
    provider: str
    model: str
    argv: list[str]
    env: dict[str, str]
    stdin: str | None
    #: (source path, path relative to the trial HOME) copied before start.
    seed_files: list[tuple[Path, str]] = field(default_factory=list)
    #: Files written into the trial HOME before start: relative path -> content.
    home_files: dict[str, str] = field(default_factory=dict)
    #: Names of env vars whose values are secret.
    secret_env: tuple[str, ...] = ()
    #: Every secret value involved (for redaction); never written anywhere.
    secrets: list[str] = field(default_factory=list)
    #: Set when the adapter already knows it cannot authenticate; the runner records
    #: ``needs_sign_in`` with this reason instead of starting the CLI.
    preflight_problem: str | None = None
    #: Container mode: (host file, container path); the runner copies each file per trial and
    #: bind-mounts the copy read-only.
    mount_files: list[tuple[Path, str]] = field(default_factory=list)

    def redacted_env(self) -> dict[str, str]:
        return {k: ("[REDACTED]" if k in self.secret_env else v) for k, v in sorted(self.env.items())}


def read_zshenv_value(name: str, zshenv: Path) -> str | None:
    """The literal value assigned to ``name`` in ``zshenv`` (last assignment wins).

    Only plain ``NAME=value`` / ``export NAME=value`` lines with an optionally quoted
    literal are understood; a value that needs shell expansion is refused (None),
    because the file is never executed.
    """
    try:
        text = zshenv.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found: str | None = None
    for line in text.splitlines():
        match = _ASSIGN.match(line)
        if not match or match.group(1) != name:
            continue
        raw = match.group(2).strip()
        if raw.startswith("'"):
            end = raw.find("'", 1)
            value = raw[1:end] if end > 0 else None
        elif raw.startswith('"'):
            end = raw.find('"', 1)
            value = raw[1:end] if end > 0 else None
            if value is not None and ("$" in value or "`" in value):
                value = None
        else:
            value = raw.split("#", 1)[0].strip().split()[0] if raw.split() else None
            if value is not None and ("$" in value or "`" in value):
                value = None
        found = value or None
    return found


def base_env(trial_home: Path, trial_tmp: Path) -> dict[str, str]:
    """A minimal environment built from scratch: nothing of the runner's own env leaks."""
    return {
        "HOME": str(trial_home),
        "TMPDIR": str(trial_tmp) + "/",
        "PATH": BASE_PATH,
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "USER": "agent",
        "LOGNAME": "agent",
        "SHELL": "/bin/zsh",
    }


def _claude_env(trial_tmp: Path) -> dict[str, str]:
    """The Claude CLI's environment additions; its own temp dir (default /tmp/claude-<uid>, outside the
    sandbox's write area and shared with the owner's sessions) goes into the trial HOME."""
    return _claude_common_env() | {
        # Strip provider credentials from the environment of the agent's own Bash tool.
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_TMPDIR": str(trial_tmp),
    }


def _claude_common_env() -> dict[str, str]:
    """Shared by both modes.  Container mode leaves the subprocess scrub off: it would force the default
    permission mode, and the agent can read its own container's environment anyway."""
    return {
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    }


def _resolve(binary: str, override: str | None) -> str:
    path = override or shutil.which(binary, path=os.environ.get("PATH", "") + ":" + BASE_PATH
                                   + ":" + str(Path.home() / ".local/bin"))
    if not path:
        raise ProviderUnavailable(f"{binary} CLI not found on PATH")
    real = os.path.realpath(path)
    # A CLI installed under the owner's HOME (claude: ~/.local/bin -> ~/.local/share/claude) is started by
    # its real path, because the sandbox denies the HOME and re-allows only the install directory.  Others
    # (gemini: a node script behind /opt/homebrew/bin) keep their launcher path.
    home = os.path.realpath(str(Path.home()))
    return real if real.startswith(home + os.sep) else path


@dataclass
class AdapterContext:
    trial_home: Path
    trial_tmp: Path
    zshenv: Path = field(default_factory=lambda: Path.home() / ".zshenv")
    runner_env: dict[str, str] = field(default_factory=lambda: dict(os.environ))
    claude_bin: str | None = None
    gemini_bin: str | None = None
    gemini_auth_home: Path | None = None
    gemini_disposable: bool = False
    #: The credential proxy (``route(upstream, inject, append) -> (base_url, dummy_token)``).
    proxy: Any = None
    owner_home: Path = field(default_factory=Path.home)
    #: ``macos`` (sandbox-exec, separate user, credential proxy) or ``container`` (Docker on a Linux VM).
    isolation: str = MACOS
    #: Container mode: the credentials file (NAME=value lines) and the codex sign-in to copy for sol.
    env_file: Path = container.DEFAULT_ENV_FILE
    codex_auth: Path | None = field(default_factory=lambda: Path.home() / ".codex" / "auth.json")

    @property
    def in_container(self) -> bool:
        return self.isolation == CONTAINER

    def credential(self, name: str) -> str | None:
        """Container mode: a literal value from the credentials file (never from the runner's environment)."""
        return read_zshenv_value(name, self.env_file)


class Adapter:
    name: str = ""
    model: str = ""
    binary: str = ""
    disabled_reason: str | None = None
    #: Isolation modes in which the provider runs despite ``disabled_reason``.
    enabled_in: tuple[str, ...] = ()

    def unavailable_reason(self, isolation: str = MACOS) -> str | None:
        if self.disabled_reason and isolation not in self.enabled_in:
            return self.disabled_reason
        return None

    def build(self, prompt: str, ctx: AdapterContext) -> Launch:  # pragma: no cover - interface
        raise NotImplementedError

    def binary_path(self, ctx: AdapterContext) -> str:
        if ctx.in_container:
            return self.binary  # installed in the image, on its PATH
        override = ctx.claude_bin if self.binary == "claude" else ctx.gemini_bin
        return _resolve(self.binary, override)

    def auth_problem(self, stdout: str, stderr: str, returncode: int | None) -> str | None:
        """A sign-in problem visible in the CLI's output, or None."""
        return None


_CLAUDE_AUTH = re.compile(
    r"not logged in|please run /login|invalid api key|authentication_error|oauth token (?:has )?expired"
    r"|invalid bearer token|\b401\b.*(?:unauthori[sz]ed|authentication)|credit balance is too low",
    re.I,
)


class SonnetAdapter(Adapter):
    name = "sonnet"
    model = "sonnet"
    binary = "claude"

    def build(self, prompt: str, ctx: AdapterContext) -> Launch:
        if ctx.in_container:
            return self._build_container(prompt, ctx)
        env = base_env(ctx.trial_home, ctx.trial_tmp) | _claude_env(ctx.trial_tmp)
        token = ctx.runner_env.get("CLAUDE_CODE_OAUTH_TOKEN") or read_zshenv_value("CLAUDE_CODE_OAUTH_TOKEN", ctx.zshenv)
        problem = None
        secrets: list[str] = []
        if token:
            # The OAuth token stays in the runner's proxy; the CLI talks API-key style to the proxy.
            base, dummy = _proxy(ctx).route(ANTHROPIC_API_URL, {"authorization": f"Bearer {token}"},
                                            {"anthropic-beta": OAUTH_BETA})
            env["ANTHROPIC_BASE_URL"] = base
            env["ANTHROPIC_AUTH_TOKEN"] = dummy
            secrets.append(token)
        else:
            problem = ("needs sign-in: no Claude login for the proxy; run `claude setup-token` and export "
                       "CLAUDE_CODE_OAUTH_TOKEN in the shell that starts the runner")
        argv = [
            self.binary_path(ctx), "-p",
            "--model", "sonnet",
            "--output-format", "stream-json", "--verbose",
            "--no-session-persistence",
            "--allowedTools", *CLAUDE_TOOLS,
        ]
        return Launch(self.name, self.model, argv, env, prompt, secret_env=("ANTHROPIC_AUTH_TOKEN",),
                      secrets=secrets, preflight_problem=problem)

    def _build_container(self, prompt: str, ctx: AdapterContext) -> Launch:
        """The CLI reads the setup-token from CLAUDE_CODE_OAUTH_TOKEN itself; the container is the sandbox."""
        env = container.base_env() | _claude_common_env()
        token = ctx.credential("CLAUDE_CODE_OAUTH_TOKEN")
        problem = None
        if token:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = token
        else:
            problem = (f"needs sign-in: no CLAUDE_CODE_OAUTH_TOKEN value in {ctx.env_file}; create one with "
                       "`claude setup-token` (README, 'Cloud VM (container mode)')")
        argv = [
            self.binary_path(ctx), "-p",
            "--model", "sonnet",
            "--output-format", "stream-json", "--verbose",
            "--no-session-persistence",
            "--dangerously-skip-permissions",
            "--allowedTools", *CLAUDE_TOOLS,
        ]
        return Launch(self.name, self.model, argv, env, prompt, secret_env=("CLAUDE_CODE_OAUTH_TOKEN",),
                      secrets=[token] if token else [], preflight_problem=problem)

    def auth_problem(self, stdout: str, stderr: str, returncode: int | None) -> str | None:
        if returncode and _CLAUDE_AUTH.search(error_text(stdout) + stderr[-4000:]):
            return "needs sign-in: Claude CLI reported an authentication error"
        return None


class GlmAdapter(Adapter):
    binary = "claude"

    def __init__(self, name: str, model: str):
        self.name = name
        self.model = model

    def settings(self) -> str:
        return json.dumps({
            "modelPicker": {"options": [{"model": self.model, "behavesAs": "claude-sonnet-4-6"}]},
            "skipWebFetchPreflight": True,
        }, separators=(",", ":"))

    def model_env(self) -> dict[str, str]:
        return {
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": self.model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": self.model,
            "API_TIMEOUT_MS": "3000000",
            "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1",
        }

    def build(self, prompt: str, ctx: AdapterContext) -> Launch:
        if ctx.in_container:
            return self._build_container(prompt, ctx)
        key = read_zshenv_value("ZAI_API_KEY", ctx.zshenv)
        env = base_env(ctx.trial_home, ctx.trial_tmp) | _claude_env(ctx.trial_tmp) | self.model_env()
        problem = None
        secrets: list[str] = []
        if key:
            # The z.ai key stays in the runner's proxy; the CLI only holds the proxy's dummy token.
            base, dummy = _proxy(ctx).route(ZAI_BASE_URL, {"authorization": f"Bearer {key}"})
            env["ANTHROPIC_BASE_URL"] = base
            env["ANTHROPIC_AUTH_TOKEN"] = dummy
            secrets.append(key)
        else:
            problem = f"needs sign-in: no literal ZAI_API_KEY assignment found in {ctx.zshenv}"
        argv = [
            self.binary_path(ctx), "-p", "--bare",
            "--model", self.model,
            "--settings", self.settings(),
            "--output-format", "stream-json", "--verbose",
            "--no-session-persistence",
            "--allowedTools", *CLAUDE_TOOLS,
        ]
        return Launch(self.name, self.model, argv, env, prompt, secret_env=("ANTHROPIC_AUTH_TOKEN",),
                      secrets=secrets, preflight_problem=problem)

    def _build_container(self, prompt: str, ctx: AdapterContext) -> Launch:
        """The claude CLI's Anthropic-compatible form for z.ai (README; the GLM worker memory note), with the key
        in the container's own environment."""
        key = ctx.credential("ZAI_API_KEY")
        env = container.base_env() | _claude_common_env() | self.model_env() | {"ANTHROPIC_BASE_URL": ZAI_BASE_URL}
        problem = None
        if key:
            env["ANTHROPIC_AUTH_TOKEN"] = key
        else:
            problem = f"needs sign-in: no ZAI_API_KEY value in {ctx.env_file}"
        argv = [
            self.binary_path(ctx), "-p", "--bare",
            "--model", self.model,
            "--settings", self.settings(),
            "--output-format", "stream-json", "--verbose",
            "--no-session-persistence",
            "--dangerously-skip-permissions",
            "--allowedTools", *CLAUDE_TOOLS,
        ]
        return Launch(self.name, self.model, argv, env, prompt, secret_env=("ANTHROPIC_AUTH_TOKEN",),
                      secrets=[key] if key else [], preflight_problem=problem)

    def auth_problem(self, stdout: str, stderr: str, returncode: int | None) -> str | None:
        if returncode and _CLAUDE_AUTH.search(error_text(stdout) + stderr[-4000:]):
            return "needs sign-in: z.ai rejected the key"
        return None


#: Specific sign-in failures only: the CLI prints "Loaded cached credentials." on every normal start,
#: so words like "credentials", "oauth" or "sign in" alone say nothing.
_GEMINI_AUTH = re.compile(
    r"please set an auth method|invalid_grant|\bUNAUTHENTICATED\b|login required|token has been expired or revoked"
    r"|request had invalid authentication credentials|GEMINI_API_KEY environment variable not found"
    r"|API key not valid|\bAPI_KEY_INVALID\b", re.I,
)
_GEMINI_NOISE = re.compile(r"(?im)^.*loaded cached credentials\.?.*$")


class GeminiAdapter(Adapter):
    name = "gemini"
    model = GEMINI_MODEL
    binary = "gemini"

    @staticmethod
    def common_env() -> dict[str, str]:
        return {"NO_BROWSER": "true", "BROWSER": "/usr/bin/false", "GEMINI_CLI_NO_RELAUNCH": "true"}

    def argv(self, prompt: str, ctx: AdapterContext) -> list[str]:
        return [self.binary_path(ctx), "-m", self.model, "-p", prompt, "--yolo", "--skip-trust", "-o", "stream-json"]

    def build(self, prompt: str, ctx: AdapterContext) -> Launch:
        if ctx.in_container:
            return self._build_container(prompt, ctx)
        env = base_env(ctx.trial_home, ctx.trial_tmp) | self.common_env()
        seeds: list[tuple[Path, str]] = []
        secrets: list[str] = []
        auth_home = ctx.gemini_auth_home
        if auth_home is not None:
            check_disposable_sign_in("gemini", auth_home, ctx.gemini_disposable, ctx.owner_home,
                                     owner_dirs=(".gemini",), flag="--gemini-account-is-disposable")
            for rel in GEMINI_SEED_FILES:
                src = auth_home / rel
                if src.is_file():
                    seeds.append((src, rel))
                    if rel.endswith("oauth_creds.json"):
                        secrets.extend(_json_secret_values(src))
        return Launch(self.name, self.model, self.argv(prompt, ctx), env, None, seed_files=seeds, secrets=secrets)

    def _build_container(self, prompt: str, ctx: AdapterContext) -> Launch:
        """The Gemini CLI with an API key (GEMINI_API_KEY selects it in non-interactive mode); no Google sign-in
        is copied anywhere."""
        env = container.base_env() | self.common_env()
        key = ctx.credential("GEMINI_API_KEY")
        problem = None
        if key:
            env["GEMINI_API_KEY"] = key
        else:
            problem = f"needs sign-in: no GEMINI_API_KEY value in {ctx.env_file}"
        return Launch(self.name, self.model, self.argv(prompt, ctx), env, None, secret_env=("GEMINI_API_KEY",),
                      secrets=[key] if key else [], preflight_problem=problem)

    def auth_problem(self, stdout: str, stderr: str, returncode: int | None) -> str | None:
        if returncode == 41:
            return "needs sign-in: gemini has no auth method in the trial HOME (exit 41)"
        if returncode and _GEMINI_AUTH.search(_GEMINI_NOISE.sub("", error_text(stdout) + "\n" + stderr[-4000:])):
            return "needs sign-in: gemini reported an authentication error"
        return None


#: Sign-in failures in codex's own error events or stderr (codex_error_text), not in the agent's conversation.
_CODEX_AUTH = re.compile(
    r"not logged in|please (?:run `?codex login|log ?in)|\b401\b|unauthori[sz]ed"
    r"|refresh_token_(?:reused|expired|invalidated)|could not be refreshed|token (?:is |has )?expired"
    r"|sign in again|invalid_grant", re.I,
)


class SolAdapter(Adapter):
    name = "sol"
    model = "gpt-6.1-sol"
    binary = "codex"
    disabled_reason = (
        "sol (OpenAI Sol 6.1, codex model gpt-6.1-sol) is disabled in macOS mode. The model is listed for this "
        "machine's ChatGPT sign-in (codex-cli 0.162.1), so it is reachable, but a trial here would need (1) a copy "
        "of a ChatGPT auth.json in the trial HOME, readable by the agent, next to the owner's own keys, and (2) "
        "Codex's own sandbox switched off, because it cannot nest inside sandbox-exec. It runs in container mode "
        "on a throwaway Linux VM instead (--isolation container; README, 'Cloud VM (container mode)'). Remove sol "
        "from --providers here."
    )
    enabled_in = (CONTAINER,)

    def build(self, prompt: str, ctx: AdapterContext) -> Launch:
        if not ctx.in_container:
            raise ProviderUnavailable(self.disabled_reason)
        env = container.base_env() | {"CODEX_HOME": container.CODEX_HOME}
        auth = ctx.codex_auth
        mounts: list[tuple[Path, str]] = []
        secrets: list[str] = []
        problem = None
        if auth is not None and auth.is_file():
            # A per-trial read-only copy; the image's entrypoint puts it into CODEX_HOME (0600).
            mounts.append((auth, container.CODEX_AUTH_TARGET))
            secrets = _nested_secret_values(auth)
        else:
            problem = (f"needs sign-in: no codex sign-in at {auth}; run the device login on the VM (README, "
                       "'Cloud VM (container mode)')")
        argv = [self.binary_path(ctx), "exec", "--json", "-m", self.model,
                "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", "--ephemeral",
                "--color", "never", "-"]
        return Launch(self.name, self.model, argv, env, prompt, secrets=secrets, preflight_problem=problem,
                      mount_files=mounts)

    def auth_problem(self, stdout: str, stderr: str, returncode: int | None) -> str | None:
        if returncode and _CODEX_AUTH.search(codex_error_text(stdout) + "\n" + stderr[-4000:]):
            return "needs sign-in: codex reported an authentication error (device login on the VM again)"
        return None


def check_disposable_sign_in(provider: str, auth_home: Path, confirmed: bool, owner_home: Path, *,
                             owner_dirs: tuple[str, ...], flag: str) -> None:
    """Refuse a sign-in the agent could steal unless it belongs to a disposable account.

    The copied files (an OAuth refresh token) are readable by the agent, which runs with a shell and
    open network; only a dedicated, throwaway account may be signed in there.
    """
    real = Path(os.path.realpath(auth_home))
    home = Path(os.path.realpath(owner_home))
    if real == home or any(real == home / d or (home / d) in real.parents for d in owner_dirs):
        raise ProviderUnavailable(
            f"{provider}: refusing the owner's own sign-in ({real}); the agent can read the copied token. Sign a "
            "dedicated, disposable account into a separate sign-in HOME (README)")
    if not (confirmed or (auth_home / DISPOSABLE_MARKER).is_file()):
        raise ProviderUnavailable(
            f"{provider}: the agent can read the sign-in copied from {auth_home}; start it only for a dedicated, "
            f"disposable account: pass {flag} or create {auth_home / DISPOSABLE_MARKER} (README)")


def _proxy(ctx: AdapterContext):
    if ctx.proxy is None:
        raise ProviderUnavailable("no credential proxy: the runner starts one before any Claude-based agent")
    return ctx.proxy


def error_text(stdout: str) -> str:
    """Only the CLI's own error/result events from a stream-json stdout (not the agent's conversation),
    or the tail of a non-JSON stdout."""
    parts: list[str] = []
    saw_json = False
    for line in stdout.splitlines()[-200:]:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        saw_json = True
        if not isinstance(event, dict):
            continue
        if "error" in event:
            parts.append(json.dumps(event["error"]))
        if event.get("type") == "result" and event.get("is_error"):
            parts.append(str(event.get("result", "")))
    if not saw_json:
        return stdout[-2000:]
    return "\n".join(parts)


def codex_error_text(stdout: str) -> str:
    """Only codex's own error events (``error``, ``turn.failed``, error items) from ``exec --json`` output."""
    parts: list[str] = []
    for line in stdout.splitlines()[-200:]:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        item = event.get("item") if isinstance(event.get("item"), dict) else {}
        if event.get("type") == "error":
            parts.append(str(event.get("message", "")))
        elif event.get("type") == "turn.failed":
            parts.append(json.dumps(event.get("error", "")))
        elif item.get("type") == "error":
            parts.append(str(item.get("message", "")))
    return "\n".join(parts)


#: Keys whose string values in a sign-in file are credentials or identify the account.
_SECRET_KEYS = {"access_token", "refresh_token", "id_token", "openai_api_key", "api_key", "account_id"}


def _nested_secret_values(path: Path) -> list[str]:
    """Every credential-looking string of a JSON sign-in file (codex auth.json nests them under "tokens"):
    the values of known secret keys, and any long string (a token under a key not known yet)."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    out: list[str] = []

    def walk(value, key=""):
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, str(k))
        elif isinstance(value, list):
            for v in value:
                walk(v, key)
        elif isinstance(value, str) and len(value) >= 8 and (key.lower() in _SECRET_KEYS or len(value) >= 40):
            out.append(value)

    walk(data)
    return out


def _json_secret_values(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    out = []
    for key in ("access_token", "refresh_token", "id_token"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, str) and len(value) >= 8:
            out.append(value)
    return out


ADAPTERS: dict[str, Adapter] = {
    "sonnet": SonnetAdapter(),
    "glm53": GlmAdapter("glm53", "glm-5.3"),
    "glm53flash": GlmAdapter("glm53flash", "glm-5.3-flash"),
    "gemini": GeminiAdapter(),
    "sol": SolAdapter(),
}


def resolve_limits(overrides: dict[str, int] | None = None, isolation: str = MACOS) -> dict[str, int]:
    """Concurrency per provider: the defaults (the ceilings; sol 1 in macOS mode, where it is refused anyway, and 2
    in container mode), optionally changed within the ceilings."""
    limits = dict(CONTAINER_CONCURRENCY if isolation == CONTAINER else DEFAULT_CONCURRENCY)
    for name, value in (overrides or {}).items():
        if name not in limits:
            raise ValueError(f"unknown provider {name!r}")
        if value < 1:
            raise ValueError(f"concurrency for {name} must be at least 1")
        if value > MAX_CONCURRENCY[name]:
            raise ValueError(f"concurrency for {name} may not exceed {MAX_CONCURRENCY[name]}")
        limits[name] = value
    return limits
