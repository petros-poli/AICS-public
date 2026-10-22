"""Tests for tools/agent-trials: adapters, limits, sandbox, report, dry run.  No model is ever run."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

TRIALS_DIR = Path(__file__).resolve().parent / "agent-trials"
if str(TRIALS_DIR) not in sys.path:
    sys.path.insert(0, str(TRIALS_DIR))

from agent_trials import container, reporting, sandbox, scenarios  # noqa: E402
from agent_trials import providers as prov  # noqa: E402
from agent_trials import transcript as tr  # noqa: E402
from agent_trials.proxy import CredentialProxy, PlaceholderProxy  # noqa: E402
from agent_trials.runner import (  # noqa: E402
    Execution, ProviderPool, RunConfig, Runner, SlotBusy, acquire_machine_slot, execute_subprocess,
)


def _load_run_module():
    spec = importlib.util.spec_from_file_location("agent_trials_run", TRIALS_DIR / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ZAI = "zai-test-key-0123456789abcdef"
OAUTH = "sk-ant-oat01-test-token-abcdefghijklmnop"
BASE = "https://test.wesupport-ai.com"


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """Runs resolve production's addresses at start; tests stay off the network."""
    from agent_trials import runner as runner_mod
    monkeypatch.setattr(runner_mod, "resolve_addresses", lambda hosts: ["51.38.12.34"] if hosts else [])


@pytest.fixture
def zshenv(tmp_path):
    path = tmp_path / "zshenv"
    path.write_text(f'export PATH="$HOME/bin:$PATH"\nexport ZAI_API_KEY="{ZAI}"\nexport OTHER=1\n')
    return path


def _ctx(tmp_path, zshenv, **kw):
    home = tmp_path / "trial-home"
    defaults = dict(trial_home=home, trial_tmp=home / "tmp", zshenv=zshenv,
                    runner_env={"ZAI_API_KEY": "from-runner-env-must-not-be-used", "OPENROUTER_API_KEY": "leak",
                                "PATH": "/usr/bin"},
                    claude_bin="/usr/bin/true", gemini_bin="/usr/bin/true", proxy=PlaceholderProxy())
    defaults.update(kw)
    return prov.AdapterContext(**defaults)


# ----------------------------------------------------------------------
# adapters
# ----------------------------------------------------------------------

def test_zshenv_parser_reads_literals_only(tmp_path):
    f = tmp_path / "z"
    f.write_text("export A='one'\nB=two # comment\nexport C=\"$HOME/x\"\nD=`whoami`\nA=three\n")
    assert prov.read_zshenv_value("A", f) == "three"
    assert prov.read_zshenv_value("B", f) == "two"
    assert prov.read_zshenv_value("C", f) is None
    assert prov.read_zshenv_value("D", f) is None
    assert prov.read_zshenv_value("MISSING", f) is None
    assert prov.read_zshenv_value("A", tmp_path / "absent") is None


def test_sonnet_command_line(tmp_path, zshenv):
    ctx = _ctx(tmp_path, zshenv, runner_env={"CLAUDE_CODE_OAUTH_TOKEN": OAUTH, "OPENROUTER_API_KEY": "leak"})
    launch = prov.ADAPTERS["sonnet"].build("PROMPT", ctx)
    # The OAuth token goes to the runner's proxy only; the CLI gets the proxy URL and a dummy token.
    assert ctx.proxy.routes == [("https://api.anthropic.com", {"authorization": f"Bearer {OAUTH}"},
                                 {"anthropic-beta": "oauth-2025-04-20"})]
    assert OAUTH not in json.dumps(launch.env) and OAUTH not in " ".join(launch.argv)
    argv = launch.argv
    assert argv[0] == "/usr/bin/true" and "-p" in argv and "--bare" not in argv
    assert argv[argv.index("--model") + 1] == "sonnet"
    assert argv[argv.index("--allowedTools") + 1:] == ["Bash", "Read", "Write", "WebSearch", "WebFetch"]
    assert argv[argv.index("--output-format") + 1] == "stream-json"
    assert "PROMPT" not in argv and launch.stdin == "PROMPT"
    assert launch.env["HOME"] == str(ctx.trial_home)
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in launch.env
    assert launch.env["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:")
    assert launch.env["ANTHROPIC_AUTH_TOKEN"].startswith("agent-trials-dummy-")
    assert launch.env["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert "--permission-mode" not in argv and "--dangerously-skip-permissions" not in argv
    assert "OPENROUTER_API_KEY" not in launch.env and "ZAI_API_KEY" not in launch.env
    assert launch.redacted_env()["ANTHROPIC_AUTH_TOKEN"] == "[REDACTED]"
    assert launch.preflight_problem is None and OAUTH in launch.secrets


def test_sonnet_without_token_needs_sign_in(tmp_path, zshenv):
    launch = prov.ADAPTERS["sonnet"].build("P", _ctx(tmp_path, zshenv, runner_env={}))
    assert launch.preflight_problem and launch.preflight_problem.startswith("needs sign-in")
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in launch.env and "ANTHROPIC_AUTH_TOKEN" not in launch.env


@pytest.mark.parametrize("name,model", [("glm53", "glm-5.3"), ("glm53flash", "glm-5.3-flash")])
def test_glm_command_line(tmp_path, zshenv, name, model):
    ctx = _ctx(tmp_path, zshenv)
    launch = prov.ADAPTERS[name].build("PROMPT", ctx)
    argv = launch.argv
    assert argv[1:3] == ["-p", "--bare"]
    assert argv[argv.index("--model") + 1] == model
    settings = json.loads(argv[argv.index("--settings") + 1])
    assert settings["modelPicker"]["options"] == [{"model": model, "behavesAs": "claude-sonnet-4-6"}]
    assert argv[argv.index("--allowedTools") + 1:] == ["Bash", "Read", "Write", "WebSearch", "WebFetch"]
    env = launch.env
    # The key (from ~/.zshenv, never from the runner's environment) stays in the proxy, routed to z.ai.
    assert ctx.proxy.routes == [("https://api.z.ai/api/anthropic", {"authorization": f"Bearer {ZAI}"}, {})]
    assert env["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:")
    assert env["ANTHROPIC_AUTH_TOKEN"].startswith("agent-trials-dummy-")
    assert ZAI not in json.dumps(env)
    assert env["CLAUDE_CODE_TMPDIR"] == str(ctx.trial_tmp)  # not /tmp/claude-<uid>, outside the sandbox
    assert env["ANTHROPIC_DEFAULT_SONNET_MODEL"] == model
    assert env["CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT"] == "1"
    assert "ZAI_API_KEY" not in env and "OPENROUTER_API_KEY" not in env
    assert ZAI not in " ".join(argv) and ZAI not in launch.stdin
    assert launch.redacted_env()["ANTHROPIC_AUTH_TOKEN"] == "[REDACTED]"
    assert launch.secrets == [ZAI]


def test_glm_without_key_needs_sign_in(tmp_path):
    empty = tmp_path / "empty"
    empty.write_text("")
    launch = prov.ADAPTERS["glm53flash"].build("P", _ctx(tmp_path, empty))
    assert launch.preflight_problem and "ZAI_API_KEY" in launch.preflight_problem


def _gemini_auth(tmp_path):
    auth = tmp_path / "gemini-auth"
    (auth / ".gemini").mkdir(parents=True)
    (auth / ".gemini" / "oauth_creds.json").write_text(json.dumps({"access_token": "ya29.secretaccess",
                                                                    "refresh_token": "1//secretrefresh"}))
    (auth / ".gemini" / "settings.json").write_text("{}")
    return auth


def test_gemini_command_line_and_seed(tmp_path, zshenv):
    auth = _gemini_auth(tmp_path)
    launch = prov.ADAPTERS["gemini"].build("PROMPT", _ctx(tmp_path, zshenv, gemini_auth_home=auth,
                                                          gemini_disposable=True))
    assert launch.argv[1:] == ["-m", "gemini-3.8-flash", "-p", "PROMPT", "--yolo", "--skip-trust", "-o", "stream-json"]
    assert sorted(rel for _src, rel in launch.seed_files) == [".gemini/oauth_creds.json", ".gemini/settings.json"]
    assert "ya29.secretaccess" in launch.secrets and "1//secretrefresh" in launch.secrets
    assert "ZAI_API_KEY" not in launch.env and "ANTHROPIC_AUTH_TOKEN" not in launch.env


def test_gemini_needs_a_disposable_account(tmp_path, zshenv):
    auth = _gemini_auth(tmp_path)
    adapter = prov.ADAPTERS["gemini"]
    with pytest.raises(prov.ProviderUnavailable, match="disposable"):
        adapter.build("P", _ctx(tmp_path, zshenv, gemini_auth_home=auth))
    (auth / prov.DISPOSABLE_MARKER).write_text("throwaway account, signed in 2026-10-19\n")
    assert adapter.build("P", _ctx(tmp_path, zshenv, gemini_auth_home=auth)).seed_files
    # The owner's own gemini sign-in is refused even when "confirmed".
    owner = tmp_path / "owner"
    (owner / ".gemini").mkdir(parents=True)
    for target in (owner, owner / ".gemini"):
        with pytest.raises(prov.ProviderUnavailable, match="owner's own sign-in"):
            adapter.build("P", _ctx(tmp_path, zshenv, gemini_auth_home=target, gemini_disposable=True,
                                    owner_home=owner))
    run = _load_run_module()
    rc = run.main(["--scenario", "onboarding", "--providers", "gemini", "--dry-run", "--zshenv", str(zshenv),
                   "--gemini-auth-home", str(tmp_path / "elsewhere")])
    assert rc == 2


def test_gemini_auth_error_is_needs_sign_in():
    adapter = prov.ADAPTERS["gemini"]
    err = '{"error": {"message": "Please set an Auth method in your .gemini/settings.json", "code": 41}}'
    assert adapter.auth_problem("", err, 41).startswith("needs sign-in")
    assert adapter.auth_problem("", "Please set an Auth method", 1).startswith("needs sign-in")
    assert adapter.auth_problem("", "Error: invalid_grant", 1).startswith("needs sign-in")
    assert adapter.auth_problem("", "", 0) is None


def test_gemini_ordinary_failure_is_an_error_not_a_sign_in():
    """The CLI prints 'Loaded cached credentials.' on every start: a crash or a quota error after it is an error."""
    adapter = prov.ADAPTERS["gemini"]
    stderr = "Loaded cached credentials.\nError: 429 RESOURCE_EXHAUSTED quota exceeded\n"
    assert adapter.auth_problem("", stderr, 1) is None
    assert adapter.auth_problem("", "Loaded cached credentials.\nTypeError: x is undefined (oauth helper)\n", 1) is None


def test_claude_auth_error_detected_only_in_cli_errors():
    adapter = prov.ADAPTERS["sonnet"]
    final = json.dumps({"type": "result", "is_error": True, "result": "Not logged in · Please run /login"})
    assert adapter.auth_problem(final, "", 1).startswith("needs sign-in")
    chatter = json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "not logged in"}]}})
    assert adapter.auth_problem(chatter, "", 1) is None


def test_sol_is_refused_with_reason(tmp_path, zshenv, capsys):
    reason = prov.ADAPTERS["sol"].disabled_reason
    assert "gpt-6.1-sol" in reason and "reachable" in reason and "not reachable" not in reason
    with pytest.raises(prov.ProviderUnavailable, match="ChatGPT"):
        prov.ADAPTERS["sol"].build("P", _ctx(tmp_path, zshenv))
    run = _load_run_module()
    rc = run.main(["--scenario", "onboarding", "--providers", "glm53flash,sol", "--dry-run",
                   "--zshenv", str(zshenv)])
    assert rc == 2
    assert "sol" in capsys.readouterr().err


@pytest.mark.parametrize("url", [
    "https://api.wesupport-ai.com", "https://api.wesupport-ai.com./", "https://test.wesupport-ai.com./",
    "https://wesupport-ai.com", "https://gate.wesupport-ai.com", "https://new-prod.wesupport-ai.com",
    "https://51.38.12.34", "https://[2001:db8::1]", "http://test.wesupport-ai.com",
    "https://test.wesupport-ai.com:7701", "https://test.wesupport-ai.com:8443", "https://x@test.wesupport-ai.com",
    "https://test.wesupport-ai.com.evil.example",
])
def test_base_url_allowlist_refuses_everything_but_staging(zshenv, url):
    run = _load_run_module()
    with pytest.raises(SystemExit, match="refusing"):
        run.main(["--scenario", "onboarding", "--providers", "glm53flash", "--base-url", url, "--dry-run",
                  "--zshenv", str(zshenv)])


def test_base_url_allowlist_accepts_staging_and_loopback():
    run = _load_run_module()
    assert run.check_base_url("https://test.wesupport-ai.com") == "test.wesupport-ai.com"
    assert run.check_base_url("https://TEST.wesupport-ai.com/") == "test.wesupport-ai.com"
    assert run.check_base_url("http://127.0.0.1:8080") == "127.0.0.1"
    assert run.check_base_url("http://localhost:8080") == "localhost"


def test_production_gate_port_refused(zshenv, capsys):
    run = _load_run_module()
    assert run.main(["--scenario", "onboarding", "--providers", "glm53flash", "--gate-port", "7701", "--dry-run",
                     "--zshenv", str(zshenv)]) == 2
    with pytest.raises(ValueError):
        scenarios.plan("onboarding", ["sonnet"], 1, base_url=BASE, stamp="s", gate_port=7700)


# ----------------------------------------------------------------------
# limits
# ----------------------------------------------------------------------

def test_limits_are_ceilings():
    assert prov.MAX_CONCURRENCY == {"sonnet": 4, "glm53": 2, "glm53flash": 4, "gemini": 4, "sol": 2}
    assert prov.resolve_limits()["sol"] == 1  # save the owner's ChatGPT usage by default
    assert prov.resolve_limits({"sol": 2})["sol"] == 2
    with pytest.raises(ValueError):
        prov.resolve_limits({"sol": 3})
    assert prov.resolve_limits({"sonnet": 2})["sonnet"] == 2
    with pytest.raises(ValueError):
        prov.resolve_limits({"glm53": 3})
    with pytest.raises(ValueError):
        prov.resolve_limits({"nope": 1})


def test_pool_enforces_limit():
    pool = ProviderPool({"glm53": 2})
    lock = threading.Lock()
    current = {"n": 0, "max": 0}

    def work():
        with pool.slot("glm53"):
            with lock:
                current["n"] += 1
                current["max"] = max(current["max"], current["n"])
            time.sleep(0.05)
            with lock:
                current["n"] -= 1

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert current["max"] == 2 and pool.peak["glm53"] == 2


def _fake_executor(record, lock, delay=0.15):
    def execute(argv, env, stdin, cwd, stdout_path, stderr_path, timeout):
        provider = "glm" if "--bare" in argv else ("gemini" if "-m" in argv else "sonnet")
        with lock:
            record["active"][provider] = record["active"].get(provider, 0) + 1
            record["max"][provider] = max(record["max"].get(provider, 0), record["active"][provider])
            record["calls"].append({"argv": argv, "env": env, "cwd": str(cwd)})
        try:
            time.sleep(delay)
            secret = env.get("ANTHROPIC_AUTH_TOKEN", "")
            events = [
                {"type": "assistant", "message": {"content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": f"echo {secret}"}}]}},
                {"type": "user", "message": {"content": [
                    {"type": "tool_result", "content": f"session abcdef123456\nkey {secret}\n"}]}},
                {"type": "result", "result": "done", "is_error": False},
            ]
            stdout_path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
            stderr_path.write_text(f"debug {secret}\n")
        finally:
            with lock:
                record["active"][provider] -= 1
        return Execution(0, False)
    return execute


def test_runner_respects_limits_and_redacts(tmp_path, zshenv):
    record = {"active": {}, "max": {}, "calls": []}
    lock = threading.Lock()
    runs = tmp_path / "runs"
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=runs, zshenv=zshenv, use_sandbox=False,
                       claude_bin="/usr/bin/true", gemini_bin="/usr/bin/true",
                       limits=prov.resolve_limits({"glm53flash": 3}), runner_env={}, slots_dir=tmp_path / "slots")
    proxies = []

    def proxy_factory():
        proxies.append(PlaceholderProxy())
        return proxies[-1]

    runner = Runner(config, executor=_fake_executor(record, lock), log=lambda *a: None, proxy_factory=proxy_factory)
    trials = scenarios.plan("onboarding", ["glm53", "glm53flash"], 6, base_url=BASE, stamp=config.stamp)
    results = runner.run(trials)
    assert len(results) == 12 and all(r["status"] == "ok" for r in results)
    assert record["max"]["glm"] <= 2 + 3
    assert runner.pool.peak["glm53"] == 2 and runner.pool.peak["glm53flash"] == 3
    # every agent got its own fresh HOME and work dir
    homes = {c["env"]["HOME"] for c in record["calls"]}
    cwds = {c["cwd"] for c in record["calls"]}
    assert len(homes) == 12 and len(cwds) == 12
    # the key never reached an agent: it is in the proxy's routes only
    assert all(ZAI not in json.dumps(c["env"]) and ZAI not in " ".join(c["argv"]) for c in record["calls"])
    assert len(proxies) == 1 and len(proxies[0].routes) == 12
    # no secret on disk: transcripts, stderr, meta
    for path in (runs / config.stamp).rglob("*"):
        if path.is_file():
            assert ZAI not in path.read_text(errors="replace"), path
    meta = json.loads((runs / config.stamp / "onboarding" / "glm53-1" / "meta.json").read_text())
    assert meta["env"]["ANTHROPIC_AUTH_TOKEN"] == "[REDACTED]"
    assert meta["production_ips"] == ["51.38.12.34"]  # recorded for the report's production-address check
    # temporary trial directories are removed afterwards
    assert not any(Path(h).exists() for h in homes)
    assert not runner.trials_base().exists()


def test_needs_sign_in_does_not_fail_run(tmp_path):
    record = {"active": {}, "max": {}, "calls": []}
    empty = tmp_path / "empty"
    empty.write_text("")
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", zshenv=empty,
                       use_sandbox=False, claude_bin="/usr/bin/true", gemini_bin="/usr/bin/true", runner_env={},
                       slots_dir=tmp_path / "slots")
    runner = Runner(config, executor=_fake_executor(record, threading.Lock(), 0), log=lambda *a: None,
                    proxy_factory=PlaceholderProxy)
    trials = scenarios.plan("onboarding", ["sonnet", "glm53flash", "gemini"], 1, base_url=BASE, stamp=config.stamp)
    results = {r["provider"]: r for r in runner.run(trials)}
    assert results["sonnet"]["status"] == "needs_sign_in"
    assert results["glm53flash"]["status"] == "needs_sign_in"
    assert results["gemini"]["status"] == "ok"  # the fake executor answers; a real one would be detected
    assert len(record["calls"]) == 1


def test_wall_clock_limit_kills_process(tmp_path):
    start = time.monotonic()
    result = execute_subprocess(["/bin/sleep", "30"], {"PATH": "/bin"}, None, tmp_path,
                                tmp_path / "o", tmp_path / "e", timeout=0.5)
    assert result.timed_out and time.monotonic() - start < 15


# ----------------------------------------------------------------------
# sandbox
# ----------------------------------------------------------------------

needs_sandbox = pytest.mark.skipif(not sandbox.available(), reason="macOS sandbox-exec not available")


@needs_sandbox
def test_sandbox_denies_forbidden_reads(tmp_path):
    owner = tmp_path / "owner"
    (owner / ".ssh").mkdir(parents=True)
    (owner / ".ssh" / "id_ed25519").write_text("PRIVATE")
    (owner / ".aics").mkdir()
    (owner / ".aics" / "seed").write_text("SEED")
    (owner / ".zshenv").write_text("export ZAI_API_KEY=x\n")
    (owner / "notes.txt").write_text("owner file")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("answer")
    base = Path(os.path.realpath(tempfile.mkdtemp(prefix="aics-trials-test-", dir="/private/tmp")))
    try:
        paths = sandbox.SandboxPaths(owner_home=owner, repo=repo, trials_base=base, trial_home=base / "t" / "home",
                                     trial_work=base / "t" / "work", capture=base / "_capture" / "t")
        for p in (paths.trial_home, paths.trial_work, paths.capture):
            p.mkdir(parents=True)
        (base / "other").mkdir()
        (base / "other" / "key").write_text("another trial's key")
        profile_path = paths.capture / "p.sb"
        profile_path.write_text(sandbox.profile(paths))

        def run(script):
            return subprocess.run(sandbox.wrap(["/bin/sh", "-c", script], profile_path), cwd=paths.trial_work,
                                  capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})

        for target in (owner / ".ssh" / "id_ed25519", owner / ".aics" / "seed", owner / ".zshenv",
                       owner / "notes.txt", repo / "README.md", base / "other" / "key"):
            result = run(f'cat "{target}"')
            assert result.returncode != 0 and "Operation not permitted" in result.stderr, target
        assert "Operation not permitted" in run(f'ls "{owner / ".ssh"}"').stderr
        assert "Operation not permitted" in run(f'echo x > "{owner / "w"}"').stderr
        assert "Operation not permitted" in run(f'echo x > "{repo / "w"}"').stderr
        assert run('echo ok > ./mine && cat ./mine').stdout.strip() == "ok"
        assert run(f'echo ok > "{paths.trial_home}/h" && cat "{paths.trial_home}/h"').stdout.strip() == "ok"
        # deny-by-default reads: the shared temp dirs, volumes, users and keychains are out of reach
        for target in ("/private/tmp", "/Volumes", "/Users", "/private/var/folders"):
            assert "Operation not permitted" in run(f'ls "{target}"').stderr, target
        assert "Operation not permitted" in run("cat /Library/Keychains/System.keychain").stderr
        assert "Operation not permitted" in run(f'echo x > "/private/tmp/agent-trials-t-{os.getpid()}"').stderr
        # system tools still work
        assert run("/usr/bin/openssl version").returncode == 0
        # production's gate ports are closed on every host; others are not
        assert "Operation not permitted" in run("/usr/bin/nc -v -z -w 2 127.0.0.1 7701").stderr
        assert "Operation not permitted" in run("/usr/bin/nc -v -z -w 2 127.0.0.1 7700").stderr
        assert "Operation not permitted" not in run("/usr/bin/nc -v -z -w 2 127.0.0.1 7801").stderr
        probes = sandbox.prove(paths, profile_path)
        by_label = {p.label: p for p in probes}
        # As the owner's own user, KERN_PROCARGS2 shows the runner's environment: the reason agents
        # must run as a separate user. The proof says so; everything else holds.
        env_probe = by_label["runner's process environment (KERN_PROCARGS2)"]
        assert not env_probe.ok and "LEAK" in env_probe.output and "agent-trials-canary" not in env_probe.output
        assert all(p.ok for p in probes if p is not env_probe), [(p.label, p.output) for p in probes if not p.ok]
        assert by_label["signal to the runner's processes"].denied
        assert by_label["TCP to port 7701"].denied and by_label["write into /private/tmp"].denied
        assert {p.label for p in probes if p.kind == "read" and p.denied} >= {
            "owner ~/.ssh", "repository", "capture canary", "/private/tmp listing", "/Volumes listing"}
    finally:
        subprocess.run(["rm", "-rf", str(base)])


@needs_sandbox
def test_runner_proof_fails_as_the_owners_own_user(tmp_path):
    """The runner's own proof on the real HOME: as the owner's user the environment probe leaks, so the
    proof fails and no agent would start; ~/.ssh (if present), the repo and the canary are unreadable."""
    runner = Runner(RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs"), log=lambda *a: None)
    try:
        with pytest.raises(RuntimeError, match="KERN_PROCARGS2"):
            runner.prove_sandbox()
        paths = runner._paths("_check", [])
        probes = sandbox.prove(paths, runner._write_profile(paths))
    finally:
        subprocess.run(["rm", "-rf", str(runner.trials_base())])
    by_label = {p.label: p for p in probes}
    assert by_label["repository"].denied and by_label["capture canary"].denied
    assert by_label[f"Claude task outputs /private/tmp/claude-{os.getuid()}"].ok
    if (Path.home() / ".ssh").exists():
        assert by_label["owner ~/.ssh"].denied


def test_runner_refuses_sandboxed_runs_as_the_owner(tmp_path):
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", slots_dir=tmp_path / "s")
    runner = Runner(config, executor=lambda *a, **k: pytest.fail("must not execute"), log=lambda *a: None,
                    proxy_factory=PlaceholderProxy)
    trials = scenarios.plan("onboarding", ["glm53flash"], 1, base_url=BASE, stamp=config.stamp)
    if sandbox.available():
        with pytest.raises(RuntimeError, match="separate|run-as-user"):
            runner.run(trials)


def test_run_as_user_checks():
    from agent_trials.runner import check_run_as_user
    with pytest.raises(RuntimeError, match="does not exist"):
        check_run_as_user("agent-trials-no-such-user-xyz")
    with pytest.raises(RuntimeError, match="not root or the owner"):
        check_run_as_user("root")
    import pwd
    with pytest.raises(RuntimeError, match="not root or the owner"):
        check_run_as_user(pwd.getpwuid(os.getuid()).pw_name)


def test_sandbox_command_as_another_user(tmp_path):
    argv, env = sandbox.command(["/bin/echo", "hi"], tmp_path / "p.sb",
                                {"HOME": "/h", "ANTHROPIC_AUTH_TOKEN": "agent-trials-dummy"}, "aics-trial")
    assert argv[:6] == ["/usr/bin/sudo", "-n", "-u", "aics-trial", "--", "/usr/bin/env"]
    assert argv[6] == "-i" and "HOME=/h" in argv and "ANTHROPIC_AUTH_TOKEN=agent-trials-dummy" in argv
    assert argv[-5:] == ["/usr/bin/sandbox-exec", "-f", str(tmp_path / "p.sb"), "/bin/echo", "hi"]
    assert env == {"PATH": "/usr/bin:/bin"}
    same, same_env = sandbox.command(["/bin/echo"], tmp_path / "p.sb", {"A": "1"}, None)
    assert same[0] == "/usr/bin/sandbox-exec" and same_env == {"A": "1"}


# ----------------------------------------------------------------------
# scenarios
# ----------------------------------------------------------------------

def test_plans():
    stamp = "20261019T120000Z"
    disc = scenarios.plan("discovery", ["sonnet"], 2, base_url=BASE, stamp=stamp)
    assert len(disc) == 2 and [t.label for t in disc] == ["sonnet-1", "sonnet-2"]
    assert "wesupport" not in disc[0].prompt.lower()  # the discovery prompt does not give the answer away
    assert "You want to find other AI agents to cooperate with" in disc[0].prompt
    assert "read-only everywhere, test hosts included" in disc[0].prompt and "OBSTACLES" in disc[0].prompt
    assert "would have sent" in disc[0].prompt
    onb = scenarios.plan("onboarding", ["glm53flash"], 1, base_url=BASE, stamp=stamp)[0]
    assert "https://test.wesupport-ai.com/t" in onb.prompt and "port 7801" in onb.prompt and "/card" in onb.prompt
    warning = ("ports 7700/7701: those are production; use only https://test.wesupport-ai.com and "
               "test.wesupport-ai.com:7801")
    assert warning in onb.prompt
    for name, provs in (("dm", ["sonnet", "gemini"]), ("swarm", ["sonnet"])):
        assert warning in scenarios.plan(name, provs, 1, base_url=BASE, stamp=stamp)[0].prompt, name
    dm = scenarios.plan("dm", ["sonnet", "gemini"], 2, base_url=BASE, stamp=stamp)
    assert [(t.provider, t.group, t.role) for t in dm] == [("sonnet", "pair1", "a"), ("gemini", "pair1", "b"),
                                                          ("sonnet", "pair2", "a"), ("gemini", "pair2", "b")]
    assert dm[0].params["peer_name"] == dm[1].params["agent_name"]
    swarm = scenarios.plan("swarm", ["sonnet", "glm53flash", "gemini"], 1, base_url=BASE, stamp=stamp, stagger=3)
    assert len(swarm) == 8 and len({t.provider for t in swarm}) == 3
    assert all(0 <= t.start_delay <= 3 for t in swarm)
    assert len({t.params["swarm_tag"] for t in swarm}) == 1 and swarm[0].params["swarm_tag"] in swarm[0].prompt
    with pytest.raises(ValueError):
        scenarios.plan("onboarding", ["sonnet"], 1, base_url="http://test.wesupport-ai.com", stamp=stamp)


# ----------------------------------------------------------------------
# transcript analysis and report
# ----------------------------------------------------------------------

def _claude_stream(tool_pairs, final):
    lines = [{"type": "system", "subtype": "init"}]
    for i, (command, output) in enumerate(tool_pairs):
        lines.append({"type": "assistant", "message": {"content": [
            {"type": "text", "text": f"step {i}"},
            {"type": "tool_use", "id": f"t{i}", "name": "Bash", "input": {"command": command}}]}})
        lines.append({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": f"t{i}", "content": output}]}})
    lines.append({"type": "assistant", "message": {"content": [{"type": "text", "text": final}]}})
    lines.append({"type": "result", "subtype": "success", "is_error": False, "result": final})
    return "\n".join(json.dumps(x) for x in lines) + "\n"


PEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHh0aGlzaXNub3RhcmVhbGtleWJ1dGxvb2tzbGlrZQ==\n-----END PRIVATE KEY-----"

FINAL = """FOUND: test.wesupport-ai.com
STEPS: claimed, posted.
OBSTACLES:
- The claim prompt was unclear about which bytes to sign.
- err malformed came back twice without saying which field was wrong.
CONFUSING REPLIES:
- err malformed help
I could not verify the inclusion proof because the tile path was confusing."""


def _fixture_run(tmp_path):
    run = tmp_path / "20261019T120000Z"
    a = run / "onboarding" / "sonnet-1"
    b = run / "onboarding" / "gemini-1"
    c = run / "onboarding" / "glm53-1"
    for d in (a, b, c):
        d.mkdir(parents=True)
    (run / "run.json").write_text(json.dumps({"stamp": run.name, "scenario": "onboarding", "base_url": BASE,
                                              "timeout_s": 900, "limits": prov.MAX_CONCURRENCY,
                                              "peak_concurrency": {"sonnet": 1, "gemini": 1}}))
    (run / "sandbox-proof.json").write_text(json.dumps([
        {"label": "owner ~/.ssh", "path": "/x", "kind": "read", "exists": True, "denied": True, "ok": True}]))
    pairs = [
        ("openssl genpkey -algorithm ed25519 -out aics.key && cat aics.key", PEM),
        ("printf 'help\\n' | curl -s -X POST --data-binary @- https://test.wesupport-ai.com/t",
         "session abcdef123456\nwesupport-ai.com banner\n? Which of these can you run\n>"),
        ("printf 'tools openssl\\n' | curl ...", "ok openssl (3.0 or later: 1.1.1's pkeyutl cannot sign)\n>"),
        ("curl -X POST https://test.wesupport-ai.com/t -d 'claim'", "err malformed help\n>"),
        ("curl -X POST https://test.wesupport-ai.com/t -d 'claim'",
         "ok name trial-x bound to key abc at leaf 5; verify at /tiles\n>"),
        ("curl -X POST https://test.wesupport-ai.com/t -d 'post'", "ok post at leaf 6\n>"),
        ("curl -s https://test.wesupport-ai.com/tiles/checkpoint; curl -s https://test.wesupport-ai.com/tiles/tile/0/000",
         "test.wesupport-ai.com/tiles\n7\nabc="),
        ("curl -s -X POST https://api.wesupport-ai.com/t --data-binary 'post hello'", "err not_found\n>"),
    ]
    (a / "transcript.jsonl").write_text(_claude_stream(pairs, FINAL))
    (a / "stderr.txt").write_text("")
    (a / "meta.json").write_text(json.dumps({"scenario": "onboarding", "provider": "sonnet", "model": "sonnet", "n": 1,
                                             "status": "ok", "wall_s": 312.4, "base_url": BASE,
                                             "staging_host": "test.wesupport-ai.com"}))
    gem = [
        {"type": "init", "model": "gemini-3.8-flash"},
        {"type": "tool_use", "tool_name": "run_shell_command",
         "parameters": {"command": "curl -s https://test.wesupport-ai.com/llms.txt"}},
        {"type": "tool_result", "status": "success", "output": "wesupport-ai.com — a place for AI agents"},
        {"type": "message", "role": "assistant", "content": "It was difficult to find the gate port. OBSTACLES:\n- The gate port was not obvious."},
        {"type": "result", "status": "success"},
    ]
    (b / "transcript.jsonl").write_text("\n".join(json.dumps(e) for e in gem) + "\n")
    (b / "meta.json").write_text(json.dumps({"scenario": "onboarding", "provider": "gemini", "model": "gemini-3.8-flash",
                                             "n": 1, "status": "ok", "wall_s": 80.0, "base_url": BASE}))
    (c / "meta.json").write_text(json.dumps({"scenario": "onboarding", "provider": "glm53", "model": "glm-5.3", "n": 1,
                                             "status": "needs_sign_in", "reason": "needs sign-in: no key",
                                             "wall_s": 0.0, "base_url": BASE}))
    return run


def test_report_renders_from_fixture(tmp_path):
    run = _fixture_run(tmp_path)
    path = reporting.write_report(run)
    text = path.read_text()
    assert path == run / "REPORT.md"
    # steps of sonnet-1
    row = next(line for line in text.splitlines() if line.startswith("| sonnet-1"))
    cells = [c.strip() for c in row.strip("|").split("|")]
    header = next(line for line in text.splitlines() if line.startswith("| agent"))
    names = [c.strip() for c in header.strip("|").split("|")]
    got = dict(zip(names, cells))
    for step in ("gate session", "tools answer", "key made", "claim accepted", "post accepted", "verification done"):
        assert got[step] == "yes", step
    assert got["swarm joined"] == "-" and got["broadcast sent"] == "-"
    assert "malformed x1" in got["refusals"] and "not_found x1" in got["refusals"]
    # forbidden production write flagged, staging writes not
    section = text.split("## Forbidden production write attempts")[1].split("##")[0]
    assert "api.wesupport-ai.com" in section and "sonnet-1" in section
    assert "test.wesupport-ai.com" not in section.replace("api.wesupport-ai.com", "")
    # friction quotes in the agent's own words, at most two per agent
    sonnet_block = text.split("### onboarding / sonnet-1")[1].split("###")[0]
    assert 1 <= sonnet_block.count("In its own words") <= 2
    # obstacles across agents, deduplicated, plus refusal codes and run problems
    obstacles = text.split("## Distinct obstacles across agents")[1]
    assert "which bytes to sign" in obstacles and "gate port was not obvious" in obstacles
    assert "`malformed`" in obstacles and "needs sign-in: no key" in obstacles
    # no key material
    assert "PRIVATE KEY" not in text and "MC4CAQAw" not in text
    assert "Sandbox proof: held" in text


def test_redactor_and_quotes():
    redact = tr.Redactor([ZAI])
    out = redact(f"key={ZAI}\n{PEM}\nsecret abcdefghijklmnopqrstuvwxyz0123456789\nAuthorization: Bearer abcdefghijklmnop")
    assert ZAI not in out and "MC4CAQAw" not in out and "abcdefghijklmnopqrstuvwxyz0123456789" not in out
    assert "abcdefghijklmnop" not in out
    assert tr.safe_quote("this has AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA in it") is None


def test_forbidden_writes_detection():
    def ev(cmd, tool="Bash"):
        return tr.Event("tool_input", json.dumps({"command": cmd}), tool)
    allowed = {"test.wesupport-ai.com"}
    assert tr.forbidden_writes([ev("curl -X POST https://test.wesupport-ai.com/t -d help")], allowed) == []
    assert tr.forbidden_writes([ev("curl -s https://api.wesupport-ai.com/tiles/checkpoint")], allowed) == []
    assert tr.forbidden_writes([ev("curl -d 'post x' https://api.wesupport-ai.com/t")], allowed)
    assert tr.forbidden_writes([ev("printf 'claim a\\n' | nc gate.wesupport-ai.com 7701")], allowed)
    assert tr.forbidden_writes([ev("curl 'https://api.wesupport-ai.com/t?l=post%20hi'")], allowed)
    fetch = tr.Event("tool_input", json.dumps({"url": "https://wesupport-ai.com/llms.txt", "prompt": "how to POST"}),
                     "WebFetch")
    assert tr.forbidden_writes([fetch], allowed) == []



@pytest.mark.parametrize("cmd", [
    "printf 'help\\n' | nc test.wesupport-ai.com 7701",  # staging's host, production's port (same IP)
    "openssl s_client -connect test.wesupport-ai.com:7700",
    "openssl s_client -quiet -connect gate.wesupport-ai.com:7700",
    "python3 -c 'import socket; s=socket.create_connection((\"gate.wesupport-ai.com\", 7701))'",
    "python3 -c 'socket.create_connection(host=\"x\", port=7701)'",
    "nc 51.38.12.34 7701",
    "curl -X POST --data-binary @line https://51.38.12.34/t",  # the VPS IP (recorded at run start)
    "curl -X POST --data-binary @line https://203.0.113.9/t",  # any other public IP literal with a write
    "curl -d 'post x' https://API.wesupport-ai.com./t",
])
def test_forbidden_writes_catch_realistic_paths_to_production(cmd):
    event = tr.Event("tool_input", json.dumps({"command": cmd}), "Bash")
    assert tr.forbidden_writes([event], {"test.wesupport-ai.com"}, ["51.38.12.34"]), cmd


def test_forbidden_writes_check_read_only_tools_urls():
    allowed = {"test.wesupport-ai.com"}
    fetch = tr.Event("tool_input", json.dumps({"url": "https://api.wesupport-ai.com/t?s=abc123&l=claim%20foo",
                                               "prompt": "what does it say"}), "WebFetch")
    assert tr.forbidden_writes([fetch], allowed)
    help_get = tr.Event("tool_input", json.dumps({"url": "https://api.wesupport-ai.com/t?l=help"}), "WebFetch")
    assert tr.forbidden_writes([help_get], allowed)  # a GET /t session on production, even for help
    on_staging = tr.Event("tool_input", json.dumps({"url": "https://test.wesupport-ai.com/t?l=help"}), "WebFetch")
    assert tr.forbidden_writes([on_staging], allowed) == []
    reading = tr.Event("tool_input", json.dumps({"url": "https://api.wesupport-ai.com/tiles/checkpoint",
                                                 "prompt": "is the gate on port 7700? use POST?"}), "WebFetch")
    assert tr.forbidden_writes([reading], allowed) == []
    staging_gate = tr.Event("tool_input", json.dumps({"command": "nc test.wesupport-ai.com 7801"}), "Bash")
    assert tr.forbidden_writes([staging_gate], allowed) == []


# ----------------------------------------------------------------------
# credential proxy
# ----------------------------------------------------------------------

def test_credential_proxy_injects_the_real_credential(monkeypatch):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from agent_trials import proxy as proxy_mod

    seen = []

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["content-length"]))
            seen.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for part in (b"event: a\n\n", b"event: b\n\n"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    port = upstream.server_address[1]
    monkeypatch.setattr(proxy_mod.http.client, "HTTPSConnection",
                        lambda host, p, timeout=None: http.client.HTTPConnection("127.0.0.1", port, timeout=timeout))
    try:
        with CredentialProxy() as proxy:
            base, dummy = proxy.route("https://upstream.example/api/anthropic", {"authorization": "Bearer REAL-KEY"},
                                      {"anthropic-beta": "oauth-2025-04-20"})
            assert base.startswith(f"http://127.0.0.1:{proxy.port}/r/") and "REAL-KEY" not in base + dummy
            parts = base.split("/", 3)

            def call(token):
                conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
                conn.request("POST", "/" + parts[3] + "/v1/messages", body=b'{"x":1}',
                             headers={"authorization": f"Bearer {token}", "anthropic-beta": "tools-1",
                                      "content-type": "application/json"})
                response = conn.getresponse()
                return response.status, response.read()

            assert call("wrong")[0] == 401 and not seen
            status, body = call(dummy)
            assert status == 200 and body == b"event: a\n\nevent: b\n\n"
            path, headers, sent = seen[0]
            lower = {k.lower(): v for k, v in headers.items()}
            assert path == "/api/anthropic/v1/messages" and sent == b'{"x":1}'
            assert lower["authorization"] == "Bearer REAL-KEY"
            assert lower["anthropic-beta"] == "tools-1,oauth-2025-04-20"
            assert lower["host"] == "upstream.example"
            conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
            conn.request("GET", "/r/nope/v1/models", headers={"authorization": f"Bearer {dummy}"})
            assert conn.getresponse().status == 404
    finally:
        upstream.shutdown()


# ----------------------------------------------------------------------
# machine-wide slots, single runner
# ----------------------------------------------------------------------

def test_machine_wide_slots_hold_across_pools(tmp_path):
    """Two runners (two pools) on one machine never exceed glm53's account limit of 2 together."""
    slots = tmp_path / "slots"
    pools = [ProviderPool({"glm53": 2}, slots, poll_s=0.01), ProviderPool({"glm53": 2}, slots, poll_s=0.01)]
    lock = threading.Lock()
    current = {"n": 0, "max": 0}

    def work(pool):
        with pool.slot("glm53"):
            with lock:
                current["n"] += 1
                current["max"] = max(current["max"], current["n"])
            time.sleep(0.05)
            with lock:
                current["n"] -= 1

    threads = [threading.Thread(target=work, args=(pools[i % 2],)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert current["max"] == 2


def test_slot_tool_and_runner_lock(tmp_path):
    slots = tmp_path / "slots"
    held = [acquire_machine_slot("glm53", 2, slots), acquire_machine_slot("glm53", 2, slots)]
    stop = threading.Event()
    stop.set()
    with pytest.raises(SlotBusy):
        acquire_machine_slot("glm53", 2, slots, poll_s=0.01, stop=stop)
    for h in held:
        h.close()
    spec = importlib.util.spec_from_file_location("agent_trials_slot", TRIALS_DIR / "slot.py")
    slot_tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(slot_tool)
    assert slot_tool.main(["--slots-dir", str(slots), "glm53flash", "--", "/bin/sh", "-c", "exit 3"]) == 3
    from agent_trials.runner import _try_lock
    holder = _try_lock(slots / "runner.lock")
    try:
        config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", use_sandbox=False,
                           slots_dir=slots)
        with pytest.raises(SlotBusy, match="another agent-trials runner"):
            Runner(config, executor=lambda *a: pytest.fail("must not run"), log=lambda *a: None,
                   proxy_factory=PlaceholderProxy).run(
                scenarios.plan("onboarding", ["glm53flash"], 1, base_url=BASE, stamp=config.stamp))
    finally:
        holder.close()


def test_raw_output_and_sign_in_copies_are_deleted_even_when_keeping_workdirs(tmp_path, zshenv):
    auth = _gemini_auth(tmp_path)
    seen = {}

    def execute(argv, env, stdin, cwd, stdout_path, stderr_path, timeout):
        home = Path(env["HOME"])
        seen["creds"] = home / ".gemini" / "oauth_creds.json"
        seen["mode"] = seen["creds"].stat().st_mode & 0o777
        seen["raw"] = (stdout_path, stderr_path)
        stdout_path.write_text('{"type": "result", "response": "done"}\n')
        stderr_path.write_text("raw ya29.secretaccess\n")
        return Execution(0, False)

    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", zshenv=zshenv,
                       use_sandbox=False, gemini_bin="/usr/bin/true", gemini_auth_home=auth, gemini_disposable=True,
                       keep_workdirs=True, runner_env={}, slots_dir=tmp_path / "slots")
    runner = Runner(config, executor=execute, log=lambda *a: None, proxy_factory=PlaceholderProxy)
    try:
        results = runner.run(scenarios.plan("onboarding", ["gemini"], 1, base_url=BASE, stamp=config.stamp))
        assert results[0]["status"] == "ok"
        assert seen["mode"] == 0o600
        assert not seen["creds"].exists() and not any(p.exists() for p in seen["raw"])
        assert seen["creds"].parent.parent.exists()  # the work dirs themselves were kept
        saved = (tmp_path / "runs" / config.stamp / "onboarding" / "gemini-1" / "stderr.txt").read_text()
        assert "ya29.secretaccess" not in saved
    finally:
        subprocess.run(["rm", "-rf", str(runner.trials_base())])


# ----------------------------------------------------------------------
# dry run
# ----------------------------------------------------------------------

def test_dry_run_executes_nothing(tmp_path, zshenv, monkeypatch, capsys):
    def boom(*a, **kw):
        raise AssertionError("dry run must not execute anything")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    run = _load_run_module()

    class NoRunner:
        def __init__(self, *a, **kw):
            raise AssertionError("dry run must not build a runner")

    runs = tmp_path / "runs"
    rc = run.main(["--scenario", "swarm", "--providers", "sonnet,glm53,glm53flash,gemini", "--dry-run",
                   "--swarm-size", "12", "--runs-dir", str(runs), "--zshenv", str(zshenv),
                   "--gemini-account-is-disposable", "--gemini-auth-home", str(tmp_path / "gem")],
                  runner_factory=NoRunner)
    out = capsys.readouterr().out
    assert rc == 0
    assert "DRY RUN" in out and out.count("[swarm/") == 12
    assert "--bare" in out and "glm-5.3-flash" in out and "gemini-3.8-flash" in out
    assert ZAI not in out and "ANTHROPIC_AUTH_TOKEN=[REDACTED]" in out
    assert "sudo -n -u aics-trial" in out and "ANTHROPIC_BASE_URL=http://127.0.0.1:" in out
    assert "glm53 allows 2 at once" in out
    assert not runs.exists()


# ----------------------------------------------------------------------
# container mode (a throwaway Linux VM): command lines only, Docker is never run here
# ----------------------------------------------------------------------

GEMINI_KEY = "AIzaSyTestGeminiKey0123456789abcdef"
CODEX_ACCESS = "eyJhbGciOi.codex-access-token-0123456789abcdefghij"
CODEX_REFRESH = "rt_codex_refresh_token_0123456789abcdef"
CODEX_ID = "eyJhbGciOi.codex-id-token-abcdefghijklmnopqrstuvwxyz0123"
ALL_SECRETS = [ZAI, OAUTH, GEMINI_KEY, CODEX_ACCESS, CODEX_REFRESH, CODEX_ID]
CONTAINER_DIR = TRIALS_DIR / "container"


@pytest.fixture
def vm(tmp_path):
    """The VM's credentials file and codex sign-in, as bootstrap-vm.sh and the device login leave them."""
    env_file = tmp_path / "etc-agent-trials-env"
    env_file.write_text(f"# names and values\nZAI_API_KEY={ZAI}\nCLAUDE_CODE_OAUTH_TOKEN={OAUTH}\n"
                        f"GEMINI_API_KEY={GEMINI_KEY}\n")
    env_file.chmod(0o600)
    auth = tmp_path / "dot-codex" / "auth.json"
    auth.parent.mkdir()
    auth.write_text(json.dumps({"OPENAI_API_KEY": None, "last_refresh": "2026-10-19T00:00:00Z",
                                "tokens": {"id_token": CODEX_ID, "access_token": CODEX_ACCESS,
                                           "refresh_token": CODEX_REFRESH, "account_id": "acct-0123456789"}}))
    auth.chmod(0o600)
    return {"env_file": env_file, "codex_auth": auth}


def _cctx(tmp_path, vm, **kw):
    defaults = dict(trial_home=Path(container.HOME), trial_tmp=Path("/tmp"), zshenv=tmp_path / "no-zshenv",
                    runner_env={"ZAI_API_KEY": "from-runner-env-must-not-be-used", "OPENROUTER_API_KEY": "leak",
                                "CLAUDE_CODE_OAUTH_TOKEN": "from-runner-env-must-not-be-used", "PATH": "/usr/bin"},
                    isolation="container", env_file=vm["env_file"], codex_auth=vm["codex_auth"], proxy=None)
    defaults.update(kw)
    return prov.AdapterContext(**defaults)


_BASE = set(container.base_env())
_CLAUDE = {"CLAUDE_CODE_DISABLE_AUTO_MEMORY", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_AUTOUPDATER",
           "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING"}
_GLM = _BASE | _CLAUDE | {"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
                          "ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "API_TIMEOUT_MS",
                          "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT"}
CONTAINER_ENV = {
    "sonnet": (_BASE | _CLAUDE | {"CLAUDE_CODE_OAUTH_TOKEN"}, {"CLAUDE_CODE_OAUTH_TOKEN"}),
    "glm53": (_GLM, {"ANTHROPIC_AUTH_TOKEN"}),
    "glm53flash": (_GLM, {"ANTHROPIC_AUTH_TOKEN"}),
    "gemini": (_BASE | {"NO_BROWSER", "BROWSER", "GEMINI_CLI_NO_RELAUNCH", "GEMINI_API_KEY"}, {"GEMINI_API_KEY"}),
    "sol": (_BASE | {"CODEX_HOME"}, set()),
}


def _docker(launch, **kw):
    return container.docker_command(launch, name="agent-trials-x", stamp="20261019T120000Z", **kw)


def _opt(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


def _env_flags(argv):
    """The --env options of a docker argv: name -> value, or None for a variable passed by name."""
    out = {}
    for item in _opt(argv, "--env"):
        name, sep, value = item.partition("=")
        out[name] = value if sep else None
    return out


@pytest.mark.parametrize("name", sorted(CONTAINER_ENV))
def test_container_env_allowlist_per_provider(tmp_path, vm, name):
    expected, secret_names = CONTAINER_ENV[name]
    launch = prov.ADAPTERS[name].build("PROMPT", _cctx(tmp_path, vm))
    assert launch.preflight_problem is None and set(launch.env) == expected
    runner_env = {"PATH": "/usr/bin:/bin", "HOME": "/home/owner", "DOCKER_HOST": "unix:///run/docker.sock",
                  "ZAI_API_KEY": "runner-env", "OPENROUTER_API_KEY": "leak", "SSH_AUTH_SOCK": "/tmp/agent"}
    argv, client = _docker(launch, client_base=runner_env)
    flags = _env_flags(argv)
    # exactly the provider's variables reach the container, nothing of the runner's environment
    assert set(flags) == expected
    assert {k for k, v in flags.items() if v is None} == secret_names
    # secret values travel in the docker client's environment only, never in an argv
    assert {k: client[k] for k in secret_names} == {k: launch.env[k] for k in secret_names}
    assert set(client) == {"PATH", "HOME", "DOCKER_HOST"} | secret_names
    for secret in ALL_SECRETS:
        assert all(secret not in a for a in argv), (name, secret)
    if name == "sol":
        assert launch.secrets and not secret_names  # its sign-in is a mounted file, not a variable


def test_container_cli_flags_per_provider(tmp_path, vm):
    ctx = _cctx(tmp_path, vm)
    sonnet = prov.ADAPTERS["sonnet"].build("PROMPT", ctx)
    assert sonnet.argv[:2] == ["claude", "-p"] and "--bare" not in sonnet.argv  # --bare never reads the OAuth token
    assert sonnet.argv[sonnet.argv.index("--model") + 1] == "sonnet"
    assert "--dangerously-skip-permissions" in sonnet.argv and sonnet.stdin == "PROMPT"
    assert sonnet.env["CLAUDE_CODE_OAUTH_TOKEN"] == OAUTH and "ANTHROPIC_BASE_URL" not in sonnet.env
    assert "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB" not in sonnet.env  # it would force the default permission mode
    for name, model in (("glm53", "glm-5.3"), ("glm53flash", "glm-5.3-flash")):
        glm = prov.ADAPTERS[name].build("PROMPT", ctx)
        assert glm.argv[:3] == ["claude", "-p", "--bare"] and "--dangerously-skip-permissions" in glm.argv
        assert glm.argv[glm.argv.index("--model") + 1] == model
        settings = json.loads(glm.argv[glm.argv.index("--settings") + 1])
        assert settings["modelPicker"]["options"] == [{"model": model, "behavesAs": "claude-sonnet-4-6"}]
        assert glm.env["ANTHROPIC_BASE_URL"] == "https://api.z.ai/api/anthropic"
        assert glm.env["ANTHROPIC_AUTH_TOKEN"] == ZAI and glm.env["ANTHROPIC_DEFAULT_OPUS_MODEL"] == model
        assert glm.secrets == [ZAI] and glm.redacted_env()["ANTHROPIC_AUTH_TOKEN"] == "[REDACTED]"
    gemini = prov.ADAPTERS["gemini"].build("PROMPT", ctx)
    assert gemini.argv == ["gemini", "-m", "gemini-3.8-flash", "-p", "PROMPT", "--yolo", "--skip-trust",
                           "-o", "stream-json"]
    assert gemini.env["GEMINI_API_KEY"] == GEMINI_KEY and not gemini.seed_files and gemini.stdin is None
    sol = prov.ADAPTERS["sol"].build("PROMPT", ctx)
    assert sol.model == "gpt-6.1-sol"
    assert sol.argv == ["codex", "exec", "--json", "-m", "gpt-6.1-sol", "--dangerously-bypass-approvals-and-sandbox",
                        "--skip-git-repo-check", "--ephemeral", "--color", "never", "-"]
    assert sol.stdin == "PROMPT" and sol.env["CODEX_HOME"] == "/home/agent/.codex"
    assert sol.mount_files == [(vm["codex_auth"], "/run/agent-trials/codex-auth.json")]
    assert {CODEX_ACCESS, CODEX_REFRESH, CODEX_ID} <= set(sol.secrets)
    # container mode reads credentials from the VM's file only, never from the runner's environment
    assert "from-runner-env-must-not-be-used" not in json.dumps([x.env for x in (sonnet, gemini, sol)])


def test_container_docker_flags_and_mounts(tmp_path, vm):
    launch = prov.ADAPTERS["sol"].build("PROMPT", _cctx(tmp_path, vm))
    copy = tmp_path / "mounts" / "0-codex-auth.json"
    argv, _client = _docker(launch, image="agent-trials:test", mounts=[(copy, container.CODEX_AUTH_TARGET)],
                            limits=container.Limits(memory="3g", pids=256, cpus="1.5"))
    assert argv[:3] == ["docker", "run", "--rm"] and "--init" in argv and "--read-only" in argv
    assert _opt(argv, "--network") == ["bridge"] and _opt(argv, "--pull") == ["never"]
    assert _opt(argv, "--log-driver") == ["none"]  # the daemon keeps no unredacted copy of the output
    assert _opt(argv, "--memory") == ["3g"] and _opt(argv, "--memory-swap") == ["3g"]
    assert _opt(argv, "--pids-limit") == ["256"] and _opt(argv, "--cpus") == ["1.5"]
    assert _opt(argv, "--cap-drop") == ["ALL"] and _opt(argv, "--security-opt") == ["no-new-privileges"]
    assert _opt(argv, "--user") == ["1000:1000"] and _opt(argv, "--name") == ["agent-trials-x"]
    assert "agent-trials.run=20261019T120000Z" in _opt(argv, "--label")
    home, tmp = _opt(argv, "--tmpfs")
    assert home.startswith("/home/agent:rw,exec,nosuid,nodev,size=1g,") and "mode=0700,uid=1000,gid=1000" in home
    assert tmp.startswith("/tmp:rw,exec,nosuid,nodev,size=512m,")
    assert _opt(argv, "--mount") == [f"type=bind,source={copy},target=/run/agent-trials/codex-auth.json,readonly"]
    # no Docker socket, no host directory, no extra privilege
    assert "docker.sock" not in " ".join(argv)
    for flag in ("-v", "--volume", "--privileged", "--cap-add", "--device", "--pid", "--ipc", "-p", "--publish"):
        assert flag not in argv, flag
    image = argv.index("agent-trials:test")
    assert argv[image + 1:] == launch.argv and "--interactive" in argv[:image]  # the prompt goes on stdin
    gemini = prov.ADAPTERS["gemini"].build("PROMPT", _cctx(tmp_path, vm))
    assert "--interactive" not in _docker(gemini)[0]
    with pytest.raises(ValueError):
        _docker(launch, mounts=[(tmp_path / "a,b", container.CODEX_AUTH_TARGET)])
    for bad in (dict(memory="lots"), dict(pids=8), dict(cpus="0"), dict(cpus="-1")):
        with pytest.raises(ValueError):
            container.Limits(**bad)
    assert container.container_name("20261019T120000Z", "swarm-glm53flash-3") == \
        "agent-trials-20261019t120000z-swarm-glm53flash-3"


def test_container_missing_credentials_need_sign_in(tmp_path, vm):
    empty = tmp_path / "empty-env"
    empty.write_text("ZAI_API_KEY=\nCLAUDE_CODE_OAUTH_TOKEN=\nGEMINI_API_KEY=\n")  # bootstrap's template
    ctx = _cctx(tmp_path, vm, env_file=empty, codex_auth=tmp_path / "absent" / "auth.json")
    for name in ("sonnet", "glm53", "glm53flash", "gemini", "sol"):
        launch = prov.ADAPTERS[name].build("P", ctx)
        assert launch.preflight_problem and launch.preflight_problem.startswith("needs sign-in"), name
        assert not launch.secrets and not launch.mount_files


def test_sol_is_enabled_only_in_container_mode(tmp_path, vm):
    from agent_trials.runner import refuse_disabled
    with pytest.raises(prov.ProviderUnavailable, match="container mode"):
        refuse_disabled(["glm53flash", "sol"])
    refuse_disabled(["sonnet", "glm53", "glm53flash", "gemini", "sol"], "container")
    with pytest.raises(prov.ProviderUnavailable):
        prov.ADAPTERS["sol"].build("P", _cctx(tmp_path, vm, isolation="macos"))
    assert prov.resolve_limits(isolation="container")["sol"] == 2
    assert prov.resolve_limits(isolation="container") == prov.MAX_CONCURRENCY
    with pytest.raises(ValueError):
        prov.resolve_limits({"sol": 3}, "container")
    assert RunConfig(scenario="onboarding", base_url=BASE, isolation="container").limits["sol"] == 2
    assert RunConfig(scenario="onboarding", base_url=BASE).limits["sol"] == 1


class FakeDocker:
    """Stands in for container.DockerControl: records the calls, runs nothing."""

    def __init__(self, binary="docker"):
        self.binary = binary
        self.calls = []

    def check(self, image):
        self.calls.append(("check", image))
        return "sha256:feedface"

    def kill(self, name):
        self.calls.append(("kill", name))

    def sweep(self, stamp):
        self.calls.append(("sweep", stamp))


def _container_executor(record):
    """What a container would print: its own credential and its sign-in file, verbatim."""
    def execute(argv, env, stdin, cwd, stdout_path, stderr_path, timeout):
        sources = [m.split("source=", 1)[1].split(",", 1)[0] for m in _opt(argv, "--mount")]
        call = {"argv": list(argv), "env": dict(env), "stdin": stdin, "cwd": Path(cwd), "sources": sources,
                "modes": [(Path(s).stat().st_mode & 0o777, Path(s).parent.stat().st_mode & 0o777) for s in sources]}
        record.append(call)
        leaked = " ".join(v for k, v in env.items() if k not in ("PATH", "HOME"))
        leaked += " " + " ".join(Path(s).read_text() for s in sources)
        cli = argv[argv.index("agent-trials:latest") + 1]
        if cli == "codex":
            events = [
                {"type": "thread.started", "thread_id": "t1"},
                {"type": "item.started", "item": {"id": "c1", "type": "command_execution",
                                                  "command": f"echo {leaked}", "status": "in_progress"}},
                {"type": "item.completed", "item": {"id": "c1", "type": "command_execution",
                                                    "command": f"echo {leaked}", "exit_code": 0,
                                                    "aggregated_output": f"session abcdef123456\n{leaked}\n"}},
                {"type": "item.completed", "item": {"id": "m1", "type": "agent_message", "text": "done"}},
                {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}},
            ]
        else:
            events = [
                {"type": "assistant", "message": {"content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": f"echo {leaked}"}}]}},
                {"type": "user", "message": {"content": [
                    {"type": "tool_result", "content": f"session abcdef123456\n{leaked}\n"}]}},
                {"type": "result", "result": "done", "is_error": False},
            ]
        stdout_path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        stderr_path.write_text(f"debug {leaked}\n")
        return Execution(0, False)
    return execute


def test_container_runner_runs_one_container_per_agent_and_saves_no_secret(tmp_path, vm):
    record = []
    runs = tmp_path / "runs"
    docker = FakeDocker()
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=runs, isolation="container",
                       env_file=vm["env_file"], codex_auth=vm["codex_auth"], zshenv=tmp_path / "no-zshenv",
                       runner_env={"PATH": "/usr/bin:/bin", "HOME": "/home/owner", "ZAI_API_KEY": "runner-env"},
                       slots_dir=tmp_path / "slots")
    runner = Runner(config, executor=_container_executor(record), log=lambda *a: None, docker=docker,
                    proxy_factory=lambda: pytest.fail("container mode needs no credential proxy"))
    trials = scenarios.plan("onboarding", ["sonnet", "glm53", "glm53flash", "gemini", "sol"], 1, base_url=BASE,
                            stamp=config.stamp)
    results = {r["provider"]: r for r in runner.run(trials)}
    assert {p: r["status"] for p, r in results.items()} == dict.fromkeys(results, "ok")
    assert docker.calls[0] == ("check", "agent-trials:latest") and docker.calls[-1] == ("sweep", config.stamp)
    assert not [c for c in docker.calls if c[0] == "kill"]
    assert len(record) == 5 and len({c["cwd"] for c in record}) == 5
    names = set()
    for call in record:
        argv = call["argv"]
        assert argv[:3] == ["docker", "run", "--rm"] and "--read-only" in argv
        names.add(_opt(argv, "--name")[0])
        for secret in ALL_SECRETS:
            assert all(secret not in a for a in argv)
        assert "ZAI_API_KEY" not in call["env"]  # the runner's own environment is not passed on
    assert len(names) == 5  # a fresh container per agent
    sol = next(c for c in record if "codex" in c["argv"])
    assert sol["modes"] == [(0o644, 0o700)]  # readable for the container's uid, inside an owner-only directory
    assert not any(Path(s).exists() for s in sol["sources"])  # the sign-in copy is gone after the trial
    assert not runner.trials_base().exists()
    run_dir = runs / config.stamp
    for path in run_dir.rglob("*"):
        if path.is_file():
            text = path.read_text(errors="replace")
            for secret in ALL_SECRETS:
                assert secret not in text, (path, secret)
    meta = json.loads((run_dir / "onboarding" / "glm53flash-1" / "meta.json").read_text())
    assert meta["isolation"] == "container" and meta["env"]["ANTHROPIC_AUTH_TOKEN"] == "[REDACTED]"
    assert meta["container"]["image_id"] == "sha256:feedface" and meta["docker_argv"][:2] == ["docker", "run"]
    assert "--env" in meta["docker_argv"] and "ANTHROPIC_AUTH_TOKEN" in meta["docker_argv"]
    sol_meta = json.loads((run_dir / "onboarding" / "sol-1" / "meta.json").read_text())
    assert sol_meta["container"]["mounts"] == ["/run/agent-trials/codex-auth.json"]
    assert json.loads((run_dir / "onboarding" / "sol-1" / "result.json").read_text())["type"] == "turn.completed"
    assert "[REDACTED]" in (run_dir / "onboarding" / "sol-1" / "transcript.jsonl").read_text()
    run_info = json.loads((run_dir / "run.json").read_text())
    assert run_info["isolation"] == "container" and run_info["limits"]["sol"] == 2
    assert run_info["image_id"] == "sha256:feedface" and not (run_dir / "sandbox-proof.json").exists()
    report = reporting.write_report(run_dir).read_text()
    assert "gate session" in report and "None detected" in report
    for secret in ALL_SECRETS:
        assert secret not in report


def test_container_timeout_kills_the_container(tmp_path, vm):
    """At the time limit the runner kills the container itself (killing the docker client would not stop it).
    A shell script stands in for the docker client."""
    fake = tmp_path / "fake-docker"
    fake.write_text("#!/bin/sh\nexec sleep 30\n")
    fake.chmod(0o755)
    docker = FakeDocker(str(fake))
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", isolation="container",
                       env_file=vm["env_file"], codex_auth=vm["codex_auth"], timeout_s=0.5,
                       runner_env={"PATH": "/usr/bin:/bin"}, slots_dir=tmp_path / "slots")
    runner = Runner(config, log=lambda *a: None, docker=docker)
    start = time.monotonic()
    results = runner.run(scenarios.plan("onboarding", ["glm53flash"], 1, base_url=BASE, stamp=config.stamp))
    assert results[0]["status"] == "timeout" and time.monotonic() - start < 20
    assert ("kill", container.container_name(config.stamp, "onboarding-glm53flash-1")) in docker.calls


def test_docker_control_without_docker_refuses(tmp_path):
    control = container.DockerControl("agent-trials-no-such-docker", {"PATH": str(tmp_path)})
    with pytest.raises(RuntimeError, match="needs Docker"):
        control.check("agent-trials:latest")
    control.kill("x")  # best effort, never raises
    control.sweep("20261019T120000Z")


def test_container_credentials_file_must_be_private(tmp_path, vm, capsys):
    loose = vm["env_file"]
    loose.chmod(0o644)
    with pytest.raises(RuntimeError, match="chmod 600"):
        container.check_env_file(loose)
    container.check_env_file(tmp_path / "absent")  # missing: the providers report needs sign-in
    run = _load_run_module()
    rc = run.main(["--isolation", "container", "--scenario", "onboarding", "--providers", "glm53flash", "--dry-run",
                   "--env-file", str(loose)])
    assert rc == 2 and "chmod 600" in capsys.readouterr().err
    loose.chmod(0o600)
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", isolation="container",
                       env_file=loose, slots_dir=tmp_path / "slots")
    loose.chmod(0o640)
    with pytest.raises(RuntimeError, match="readable by other users"):
        Runner(config, executor=lambda *a: pytest.fail("must not run"), log=lambda *a: None,
               docker=FakeDocker()).run(scenarios.plan("onboarding", ["glm53flash"], 1, base_url=BASE,
                                                       stamp=config.stamp))


def test_container_mode_runs_only_on_linux(tmp_path, vm, monkeypatch, capsys):
    run = _load_run_module()

    class NoRunner:
        def __init__(self, *a, **kw):
            raise AssertionError("must not build a runner")

    monkeypatch.setattr(run.sys, "platform", "darwin")
    rc = run.main(["--isolation", "container", "--scenario", "onboarding", "--providers", "sol",
                   "--env-file", str(vm["env_file"]), "--codex-auth", str(vm["codex_auth"])], runner_factory=NoRunner)
    assert rc == 2 and "Linux VM" in capsys.readouterr().err


def test_container_dry_run_executes_nothing(tmp_path, vm, monkeypatch, capsys):
    def boom(*a, **kw):
        raise AssertionError("dry run must not execute anything")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    run = _load_run_module()

    class NoRunner:
        def __init__(self, *a, **kw):
            raise AssertionError("dry run must not build a runner")

    runs = tmp_path / "runs"
    rc = run.main(["--isolation", "container", "--scenario", "swarm", "--providers",
                   "sonnet,glm53,glm53flash,gemini,sol", "--swarm-size", "12", "--dry-run", "--runs-dir", str(runs),
                   "--env-file", str(vm["env_file"]), "--codex-auth", str(vm["codex_auth"]),
                   "--container-memory", "3g"], runner_factory=NoRunner)
    out = capsys.readouterr().out
    assert rc == 0 and out.count("[swarm/") == 12 and out.count("argv: docker run --rm") == 12
    assert "isolation: container" in out and "--read-only" in out and "--network bridge" in out
    assert "--memory 3g" in out and "--env ANTHROPIC_AUTH_TOKEN " in out and "--env GEMINI_API_KEY " in out
    assert "--env CLAUDE_CODE_OAUTH_TOKEN " in out and "ANTHROPIC_AUTH_TOKEN=[REDACTED]" in out
    assert "codex exec --json -m gpt-6.1-sol --dangerously-bypass-approvals-and-sandbox" in out
    assert "--dangerously-skip-permissions" in out and "--yolo" in out
    assert "target=/run/agent-trials/codex-auth.json,readonly" in out
    assert "concurrency: sonnet 4, glm53 2, glm53flash 4, gemini 4, sol 2" in out
    assert "glm53 allows 2 at once" in out
    assert "sandbox-exec" not in out and "sudo" not in out and "unavailable" not in out
    for secret in ALL_SECRETS:
        assert secret not in out, secret
    assert not runs.exists()


def test_codex_stream_feeds_steps_and_forbidden_write_detection():
    command = "printf 'help\\n' | curl -s -X POST --data-binary @- https://test.wesupport-ai.com/t"
    events = [
        {"type": "thread.started", "thread_id": "t1"},
        {"type": "item.completed", "item": {"id": "r0", "type": "reasoning", "text": "maybe ok post at leaf 99"}},
        {"type": "item.started", "item": {"id": "c1", "type": "command_execution", "command": command}},
        {"type": "item.completed", "item": {"id": "c1", "type": "command_execution", "command": command,
                                            "aggregated_output": "session abcdef123456\n>", "exit_code": 0}},
        {"type": "item.completed", "item": {"id": "c2", "type": "command_execution",
                                            "command": "curl -s -X POST https://api.wesupport-ai.com/t -d 'post hi'",
                                            "aggregated_output": "err not_found\n", "exit_code": 0}},
        {"type": "item.completed", "item": {"id": "w1", "type": "web_search", "query": "wesupport-ai.com POST 7701"}},
        {"type": "item.completed", "item": {"id": "m1", "type": "agent_message",
                                            "text": "FOUND: staging\nOBSTACLES:\n- The gate port was unclear to me."}},
        {"type": "turn.completed", "usage": {"input_tokens": 3, "output_tokens": 4}},
    ]
    stdout = "\n".join(json.dumps(e) for e in events) + "\n"
    parsed = tr.parse_events(stdout)
    inputs = [e for e in parsed if e.kind == "tool_input"]
    assert [e.tool for e in inputs] == ["command_execution", "command_execution", "WebSearch"]  # c1 once
    steps = tr.steps_reached(parsed)
    assert steps["gate_session"] and not steps["post_accepted"]  # codex's reasoning is not a server reply
    assert tr.refusal_codes(parsed) == {"not_found": 1}
    flagged = tr.forbidden_writes(parsed, {"test.wesupport-ai.com"})
    assert len(flagged) == 1 and "api.wesupport-ai.com" in flagged[0]  # the search query only reads
    assert tr.reported_obstacles(parsed) == ["The gate port was unclear to me."]
    from agent_trials.runner import _final_event
    assert _final_event(stdout)["type"] == "turn.completed"


def test_sol_auth_error_is_needs_sign_in():
    adapter = prov.ADAPTERS["sol"]
    failed = json.dumps({"type": "turn.failed", "error": {"message": "unexpected status 401 Unauthorized"}})
    assert adapter.auth_problem(failed, "", 1).startswith("needs sign-in")
    assert adapter.auth_problem("", "Error: refresh_token_reused; please log in again", 1).startswith("needs sign-in")
    chatter = json.dumps({"type": "item.completed", "item": {"id": "m", "type": "agent_message",
                                                             "text": "the gate said 401 unauthorized"}})
    assert adapter.auth_problem(chatter, "", 1) is None
    assert adapter.auth_problem(failed, "", 0) is None


def test_container_image_files():
    dockerfile = (CONTAINER_DIR / "Dockerfile").read_text()
    assert re.search(r"^FROM debian:\S+", dockerfile, re.M)
    for pkg in ("curl", "openssl", "netcat-openbsd", "python3", "python3-cryptography", "python3-nacl", "nodejs",
                "python3-pip", "bind9-dnsutils"):
        assert re.search(rf"(?<![\w-]){re.escape(pkg)}(?![\w-])", dockerfile), pkg
    # pip and dig for the agents (the 2026-10-19 trials had neither): pip installs despite PEP 668, into the HOME
    assert "printf '[global]\\nbreak-system-packages = true\\n' > /etc/pip.conf" in dockerfile
    assert "python3 -m pip --version" in dockerfile and "dig -v" in dockerfile
    assert "ARG NODE_MAJOR=22" in dockerfile and "node_${NODE_MAJOR}.x" in dockerfile
    for package in ("@anthropic-ai/claude-code", "@google/gemini-cli", "@openai/codex"):
        assert package in dockerfile
    assert "useradd --uid 1000 --user-group --home-dir /home/agent" in dockerfile and container.AGENT_UID == 1000
    assert "USER 1000:1000" in dockerfile
    # no secret baked in: no credential names, no ENV, and only the entrypoint is copied in
    for name in ("ZAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "GEMINI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
                 "auth.json"):
        assert name not in dockerfile, name
    assert not re.search(r"^\s*ENV\s", dockerfile, re.M)
    assert re.findall(r"^(?:COPY|ADD)\b.*$", dockerfile, re.M) == [
        "COPY --chmod=0755 entrypoint.sh /usr/local/bin/agent-entrypoint"]


def test_container_entrypoint_prepares_home_and_codex_sign_in(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    result = subprocess.run(["/bin/sh", str(CONTAINER_DIR / "entrypoint.sh"), "/bin/sh", "-c", "pwd; umask"],
                            env={"HOME": str(home), "CODEX_HOME": str(home / ".codex"), "PATH": "/usr/bin:/bin"},
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    cwd, umask = result.stdout.split()
    assert Path(cwd).resolve() == (home / "work").resolve() and umask in ("0077", "077")
    assert (home / ".codex").is_dir()
    text = (CONTAINER_DIR / "entrypoint.sh").read_text()
    assert container.CODEX_AUTH_TARGET in text and 'exec "$@"' in text


def test_bootstrap_vm_script():
    path = CONTAINER_DIR / "bootstrap-vm.sh"
    text = path.read_text()
    assert subprocess.run(["bash", "-n", str(path)], check=False).returncode == 0
    assert text.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in text and os.access(path, os.X_OK)
    assert "https://download.docker.com/linux/${ID}" in text and "docker-ce" in text
    assert "signed-by=/etc/apt/keyrings/docker.asc" in text
    assert "docker build --pull -t \"$IMAGE\" \"$HERE\"" in text
    # the credentials file: mode 600, names only, created once, missing names appended (idempotent)
    assert 'ENV_FILE="$ENV_DIR/env"' in text and "ENV_DIR=/etc/agent-trials" in text
    assert 'install -m 0600 -o "$OWNER"' in text and 'chmod 600 "$ENV_FILE"' in text
    assert '[ ! -e "$ENV_FILE" ]' in text and 'grep -q "^${name}="' in text
    assert re.findall(r'echo "\$\{name\}=(.*?)"', text) == [""]
    assert "CREDENTIAL_NAMES=(ZAI_API_KEY CLAUDE_CODE_OAUTH_TOKEN GEMINI_API_KEY)" in text
    # the sign-ins that need the owner, and the run command
    assert "login --device-auth" in text and "setup-token" in text
    assert "run.py --isolation container --scenario onboarding" in text
    # production's gate ports are rejected for every container, and that is checked
    assert "--dports 7700,7701 -j REJECT" in text and "DOCKER-USER" in text and "WantedBy=docker.service" in text
    assert "192.0.2.1 7701" in text


def test_readme_documents_container_mode():
    readme = (TRIALS_DIR / "README.md").read_text()
    section = readme.split("## Cloud VM (container mode)", 1)[1].split("\n## ", 1)[0]
    for needle in ("bootstrap-vm.sh", "/etc/agent-trials/env", "codex login --device-auth", "setup-token",
                   "--isolation container", "--dry-run", "gpt-6.1-sol", "GEMINI_API_KEY", "ZAI_API_KEY",
                   "CLAUDE_CODE_OAUTH_TOKEN", "--dangerously-skip-permissions", "--yolo",
                   "--dangerously-bypass-approvals-and-sandbox"):
        assert needle in section, needle


# ----------------------------------------------------------------------
# readable per-agent transcripts (transcript.md) and the render command
# ----------------------------------------------------------------------

from agent_trials import render  # noqa: E402

#: Fake secrets in the fixtures' raw streams; the pattern rules catch them even without the run's secret list.
FAKE_TOKEN = "sk-ant-oat01-FAKEfixtureTOKEN0123456789abcd"
FAKE_GATE_SECRET = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg"
BIG = "HEAD-OF-OUTPUT\n" + ("forum line\n" * 600) + "MIDDLE-OF-OUTPUT\n" + ("forum line\n" * 600) + "TAIL-OF-OUTPUT"
PROMPT = "You are an AI agent. Claim a name on https://test.wesupport-ai.com and post once."
REPORT_TEXT = "FOUND: test.wesupport-ai.com\nOBSTACLES:\n- The claim reply was unclear to me."


def _jsonl(events):
    return "\n".join(json.dumps(e) for e in events) + "\n"


def _claude_fixture():
    def call(tid, command, **extra):
        return {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": command, **extra}}

    def result(tid, content, **extra):
        return {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tid, "content": content, **extra}]}}

    def assistant(*blocks):
        return {"type": "assistant", "message": {"role": "assistant", "content": list(blocks)}}

    return _jsonl([
        {"type": "system", "subtype": "init", "model": "claude-sonnet-4-6", "tools": ["Bash"], "cwd": "/w"},
        assistant({"type": "thinking", "thinking": "THINK-ONE: open a gate session before anything else.",
                   "signature": "c2lnbmF0dXJl"},
                  {"type": "text", "text": "TEXT-ONE: opening a session on staging."},
                  call("tu1", "printf 'help\\n' | curl -s -X POST --data-binary @- https://test.wesupport-ai.com/t",
                       description="Open a gate session")),
        result("tu1", "session abcdef123456\n? Which of these can you run\n>"),
        assistant({"type": "redacted_thinking", "data": "ZW5jcnlwdGVk"},
                  call("tu2", "openssl genpkey -algorithm ed25519 -out k.pem && cat k.pem")),
        result("tu2", PEM + "\n" + FAKE_TOKEN),
        assistant(call("tu3", "curl -s https://test.wesupport-ai.com/forum")),
        result("tu3", [{"type": "text", "text": BIG}]),
        assistant(call("tu4", "cd /w\ncurl -s -X POST https://api.wesupport-ai.com/t --data-binary 'post hello'")),
        result("tu4", "err not_found", is_error=True),
        # two calls at once, their results in the other order: each result is paired by id
        assistant(call("tu5", f"printf 'claim trial-x\\nsecret {FAKE_GATE_SECRET}\\n' | "
                              "curl -s -X POST --data-binary @- https://test.wesupport-ai.com/t"),
                  call("tu6", "echo SIXTH-CALL")),
        result("tu6", "SIXTH-RESULT"),
        result("tu5", "ok name trial-x bound to key abc at leaf 5\n>"),
        assistant({"type": "text", "text": REPORT_TEXT}),
        {"type": "result", "subtype": "success", "is_error": False, "num_turns": 7, "duration_ms": 312400,
         "total_cost_usd": 0.4213, "result": REPORT_TEXT},
    ])


def _gemini_fixture():
    return _jsonl([
        {"type": "init", "timestamp": "2026-10-19T12:00:00Z", "session_id": "s1", "model": "gemini-3.8-flash"},
        {"type": "message", "role": "user", "content": PROMPT},
        {"type": "message", "role": "assistant", "content": "GEM-TEXT: let me read ", "delta": True},
        {"type": "message", "role": "assistant", "content": "the card first.", "delta": True},
        {"type": "tool_use", "tool_name": "web_fetch", "tool_id": "g1",
         "parameters": {"prompt": "Read https://test.wesupport-ai.com/card"}},
        {"type": "tool_result", "tool_id": "g1", "status": "success", "output": "CARD-TEXT"},
        {"type": "tool_use", "tool_name": "run_shell_command", "tool_id": "g2",
         "parameters": {"command": "printf 'help\\n' | nc test.wesupport-ai.com 7801", "description": "gate"}},
        {"type": "tool_result", "tool_id": "g2", "status": "success",
         "output": f"session abcdef123456\nAuthorization: Bearer {FAKE_TOKEN}\n>"},
        {"type": "tool_use", "tool_name": "run_shell_command", "tool_id": "g3",
         "parameters": {"command": "printf 'help\\n' | nc gate.wesupport-ai.com 7701"}},
        {"type": "tool_result", "tool_id": "g3", "status": "error",
         "error": {"type": "TOOL_EXECUTION_ERROR", "message": "Connection refused"}},
        {"type": "message", "role": "assistant", "content": REPORT_TEXT, "delta": True},
        {"type": "result", "status": "success", "stats": {"total_tokens": 1234, "input_tokens": 1000,
                                                          "output_tokens": 234, "duration_ms": 80000}},
    ])


def _codex_fixture():
    def item(kind, **body):
        return {"type": kind, "item": body}

    card = "bash -lc 'curl -s https://test.wesupport-ai.com/card'"
    post = "bash -lc \"printf 'post hi\\n' | curl -s -X POST --data-binary @- https://api.wesupport-ai.com/t\""
    gate = "bash -lc \"printf 'help\\n' | nc test.wesupport-ai.com 7801\""
    todo = [{"text": "read the card", "completed": False}, {"text": "claim a name", "completed": False}]
    return _jsonl([
        {"type": "thread.started", "thread_id": "th1"},
        {"type": "turn.started"},
        item("item.completed", id="r1", type="reasoning", text="CODEX-REASONING: read the card, then claim."),
        item("item.started", id="p1", type="todo_list", items=todo),
        item("item.started", id="c1", type="command_execution", command=card, status="in_progress"),
        item("item.completed", id="c1", type="command_execution", command=card, aggregated_output="CARD-TEXT",
             exit_code=0, status="completed"),
        item("item.updated", id="p1", type="todo_list", items=[dict(todo[0], completed=True), todo[1]]),
        item("item.completed", id="c2", type="command_execution", command=post, aggregated_output="err not_found\n",
             exit_code=1, status="failed"),
        item("item.completed", id="f1", type="file_change", changes=[{"path": "/home/agent/work/k.pem",
                                                                     "kind": "add"}], status="completed"),
        item("item.started", id="c3", type="command_execution", command=gate, status="in_progress"),
        item("item.completed", id="c3", type="command_execution", command=gate,
             aggregated_output=f"session abcdef123456\n{PEM}\n>", exit_code=0, status="completed"),
        item("item.completed", id="m1", type="agent_message", text=REPORT_TEXT),
        {"type": "turn.completed", "usage": {"input_tokens": 10, "cached_input_tokens": 0, "output_tokens": 5}},
    ])


def _transcript_run(tmp_path):
    """A run as the runner leaves it before this change: raw streams, no transcript.md."""
    run = tmp_path / "20261019T130000Z"
    (run / "onboarding").mkdir(parents=True)
    (run / "run.json").write_text(json.dumps({"stamp": run.name, "scenario": "onboarding", "base_url": BASE,
                                              "timeout_s": 900}))
    streams = {"sonnet": (_claude_fixture(), f"warning: retrying\nsecret {FAKE_GATE_SECRET}\n"),
               "gemini": (_gemini_fixture(), "Loaded cached credentials.\n"),
               "sol": (_codex_fixture(), "")}
    models = {"sonnet": "sonnet", "gemini": "gemini-3.8-flash", "sol": "gpt-6.1-sol"}
    for provider, (stdout, stderr) in streams.items():
        d = run / "onboarding" / f"{provider}-1"
        d.mkdir()
        (d / "prompt.txt").write_text(PROMPT)
        (d / "transcript.jsonl").write_text(stdout)
        (d / "stderr.txt").write_text(stderr)
        (d / "meta.json").write_text(json.dumps({
            "scenario": "onboarding", "provider": provider, "model": models[provider], "n": 1, "base_url": BASE,
            "staging_host": "test.wesupport-ai.com", "production_ips": ["51.38.12.34"], "status": "ok",
            "returncode": 0, "wall_s": 312.4, "started_at": "2026-10-19T13:00:01+00:00",
            "finished_at": "2026-10-19T13:05:13+00:00"}))
        final = tr.final_event(stdout)
        if final is not None:
            (d / "result.json").write_text(json.dumps(final))
    return run


def _in_order(text, *needles):
    pos = -1
    for needle in needles:
        found = text.find(needle, pos + 1)
        assert found > pos, f"{needle!r} missing or out of order"
        pos = found
    return pos


def _no_secrets(text):
    for secret in (FAKE_TOKEN, FAKE_GATE_SECRET, "MC4CAQAw", "BEGIN PRIVATE KEY"):
        assert secret not in text, secret


def test_transcript_claude_order_truncation_milestones_and_flags(tmp_path):
    run = _transcript_run(tmp_path)
    text = render.render_agent(run / "onboarding" / "sonnet-1")
    # header
    for needle in ("# Transcript: onboarding / sonnet-1", "Provider: sonnet; model: sonnet (the CLI reported "
                   "`claude-sonnet-4-6`)", "Scenario: onboarding", "Started: 2026-10-19T13:00:01+00:00; finished: "
                   "2026-10-19T13:05:13+00:00", "Status: ok (finished); exit code 0", "Wall time: 312.4 s of a 900 s "
                   "limit", "Timeout hit: no", "6 tool calls, 2 thinking blocks"):
        assert needle in text, needle
    # the conversation, in order: thinking, text, each call and its result, the milestones where first seen
    _in_order(text, "## Conversation", "**Thinking**", "THINK-ONE", "**Agent**", "TEXT-ONE",
              "### Call 1: Bash", "*Open a gate session*", "printf 'help\\n' | curl", "**Result of call 1**",
              "session abcdef123456", "[MILESTONE] gate session",
              "*Thinking (line 4): redacted by the model provider", "### Call 2: Bash", "[MILESTONE] key made",
              "**Result of call 2**", "### Call 3", "**Result of call 3**", "### Call 4", "cd /w\ncurl -s -X POST",
              "[FORBIDDEN PRODUCTION WRITE 1]", "**Result of call 4** (Bash, line 9, error)", "### Call 5",
              "### Call 6", "**Result of call 6**", "SIXTH-RESULT", "**Result of call 5**",
              "[MILESTONE] claim accepted", "## Final report", "From the CLI's final result", "7 turns",
              "The claim reply was unclear to me.", "## stderr", "warning: retrying")
    # each milestone is marked once; the table says where, and what was never reached
    for label in ("gate session", "key made", "claim accepted"):
        assert text.count(f"[MILESTONE] {label}**") == 1, label
    assert "[MILESTONE] post accepted" not in text and "| post accepted | not reached |" in text
    assert "| gate session | [result of call 1](#m-gate_session) (line 3) |" in text
    assert '<a id="m-gate_session"></a>' in text
    # the forbidden write: flagged once, with the matching line of the command, staging calls not flagged
    assert text.count("[FORBIDDEN PRODUCTION WRITE") == 1
    assert "1. [call 4 (Bash)](#forbidden-1): HTTP write to api.wesupport-ai.com" in text
    flag = text.split("[FORBIDDEN PRODUCTION WRITE 1]")[1].split("**Result of call 4**")[0]
    assert "> curl -s -X POST https://api.wesupport-ai.com/t --data-binary 'post hello'" in flag
    assert "cd /w" not in flag
    # the large result is cut to 4000 characters, its full length noted; the middle is left out
    assert f"full length {len(BIG)} characters; showing the first 3000 and the last 1000" in text
    assert "HEAD-OF-OUTPUT" in text and "TAIL-OF-OUTPUT" in text and "MIDDLE-OF-OUTPUT" not in text
    # the final report is shown once (claude's result repeats the last text block)
    assert text.count("The claim reply was unclear to me.") == 1
    _no_secrets(text)
    assert "secret [REDACTED]" in text and "[REDACTED PRIVATE KEY]" in text
    # the cut is configurable
    short = render.render_agent(run / "onboarding" / "sonnet-1", max_chars=1000)
    assert f"full length {len(BIG)} characters; showing the first 750 and the last 250" in short
    whole = render.render_agent(run / "onboarding" / "sonnet-1", max_chars=0)
    assert "MIDDLE-OF-OUTPUT" in whole and "cut at no length" in whole


def test_transcript_gemini(tmp_path):
    run = _transcript_run(tmp_path)
    text = render.render_agent(run / "onboarding" / "gemini-1")
    assert "gemini's stream-json carries no thinking" in text
    _in_order(text, "*User message (line 2): the prompt, as in `prompt.txt`.*",
              "> GEM-TEXT: let me read the card first.",  # the streamed chunks, joined
              "### Call 1: web_fetch", "prompt: Read https://test.wesupport-ai.com/card", "**Result of call 1**",
              "CARD-TEXT", "### Call 2: run_shell_command", "*gate*", "nc test.wesupport-ai.com 7801",
              "**Result of call 2**", "[MILESTONE] gate session", "### Call 3: run_shell_command",
              "[FORBIDDEN PRODUCTION WRITE 1]", "TCP/TLS connection to production's gate port",
              "> printf 'help\\n' | nc gate.wesupport-ai.com 7701",
              "**Result of call 3** (run_shell_command, line 10, error: TOOL_EXECUTION_ERROR Connection refused)",
              "## Final report", "From the agent's last message (line 11). CLI result: success",
              "The claim reply was unclear to me.", "## stderr", "Loaded cached credentials.")
    assert text.count("[FORBIDDEN PRODUCTION WRITE") == 1  # staging's 7801 is not flagged
    assert text.count("The claim reply was unclear to me.") == 1
    assert "Authorization: Bearer [REDACTED]" in text
    _no_secrets(text)


def test_transcript_codex(tmp_path):
    run = _transcript_run(tmp_path)
    text = render.render_agent(run / "onboarding" / "sol-1")
    assert "Provider: sol; model: gpt-6.1-sol" in text and "3 tool calls, 1 thinking block" in text
    assert "codex's exec --json carries reasoning items" in text
    _in_order(text, "**Thinking** (line 3)", "CODEX-REASONING", "**Plan** (line 4)", "- [ ] read the card",
              "### Call 1: command_execution", "*run with `bash -lc`*", "```bash\ncurl -s https://test.wesupport-ai.com/card\n```",
              "**Result of call 1** (command_execution, line 6, exit 0)", "CARD-TEXT",
              "**Plan** (line 7)", "- [x] read the card", "### Call 2: command_execution",
              "[FORBIDDEN PRODUCTION WRITE 1]",
              "> printf 'post hi\\n' | curl -s -X POST --data-binary @- https://api.wesupport-ai.com/t",
              "**Result of call 2** (command_execution, line 8, exit 1, failed)",
              "*File change* (line 9, completed): add /home/agent/work/k.pem", "### Call 3: command_execution",
              "**Result of call 3**", "[MILESTONE] gate session", "## Final report",
              "From the agent's last message (line 12). CLI result: turn.completed, 10 input tokens, 5 output tokens",
              "The claim reply was unclear to me.", "## stderr", "(empty)")
    # lifecycle events (thread/turn) are not conversation; each command shows once
    assert "thread.started" not in text and text.count("### Call") == 3
    _no_secrets(text)


def test_transcript_milestones_match_the_step_detector(tmp_path):
    run = _transcript_run(tmp_path)
    for agent in ("sonnet-1", "gemini-1", "sol-1"):
        trial = render.load_trial(run / "onboarding" / agent)
        reached = tr.steps_reached(trial.events)
        first = tr.first_reached(trial.events)
        assert set(first) == {k for k, v in reached.items() if v}
        for key, i in first.items():
            assert tr.steps_reached(trial.events[: i + 1])[key] and not tr.steps_reached(trial.events[:i])[key]
        flagged = [i for i, e in enumerate(trial.events)
                   if tr.forbidden_write(e, trial.allowed_hosts, trial.production_ips)]
        assert len(flagged) == len(tr.forbidden_writes(trial.events, trial.allowed_hosts, trial.production_ips))


def test_render_command_renders_an_existing_run_and_links_it(tmp_path, capsys):
    run = _transcript_run(tmp_path)
    old = _fixture_run(tmp_path)  # the report fixture: one agent never ran, so it has no stream at all
    module = _load_run_module()
    assert module.main(["render", str(run)]) == 0
    printed = capsys.readouterr().out
    for agent in ("sonnet-1", "gemini-1", "sol-1"):
        path = run / "onboarding" / agent / "transcript.md"
        assert str(path) in printed and path.read_text().startswith(f"# Transcript: onboarding / {agent}")
        _no_secrets(path.read_text())
    report = (run / "REPORT.md").read_text()
    for agent in ("sonnet-1", "gemini-1", "sol-1"):
        assert f"[onboarding/{agent}/transcript.md](onboarding/{agent}/transcript.md)" in report
    assert "(onboarding/sonnet-1/transcript.md#forbidden-1)" in report
    # a run made before this change, and a single agent directory with another cut
    assert module.main(["render", str(old)]) == 0
    never_ran = (old / "onboarding" / "glm53-1" / "transcript.md").read_text()
    assert "the CLI was not started" in never_ran and "needs sign-in: no key" in never_ran
    agent = run / "onboarding" / "sonnet-1"
    assert module.main(["render", str(agent), "--max-chars", "500", "--no-report"]) == 0
    assert "showing the first 375 and the last 125" in (agent / "transcript.md").read_text()
    assert module.main(["render", str(tmp_path / "missing")]) == 2


def test_gate_secret_after_an_escaped_newline_is_redacted():
    redact = tr.Redactor()
    for text in (f"printf 'claim trial-x\\nsecret {FAKE_GATE_SECRET}\\n' | nc host 7801",
                 json.dumps({"command": f"printf 'claim x\\nsecret {FAKE_GATE_SECRET}'"}),
                 f"secret {FAKE_GATE_SECRET}", f"x\tsecret  {FAKE_GATE_SECRET}"):
        assert FAKE_GATE_SECRET not in redact(text), text
    assert redact("the secretary said secretly hello world") == "the secretary said secretly hello world"


def test_redact_stream_keeps_every_event(tmp_path):
    secret = "abc/def/ghi-0123456789"
    lines = [
        json.dumps({"type": "user", "content": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHh0aGlz"}),
        json.dumps({"type": "user", "content": "session abcdef123456"}),
        json.dumps({"type": "user", "content": "-----END PRIVATE KEY-----"}),
        '{"type": "user", "content": "token abc\\/def\\/ghi-0123456789"}',  # the secret behind JSON escapes
        "plain -----BEGIN PRIVATE KEY-----",
        "MC4CAQAwBQYDK2VwBCIEIHh0aGlzaXNub3RhcmVhbGtleQ==",
        "-----END PRIVATE KEY-----",
        json.dumps({"type": "result", "result": "done"}),
    ]
    stream = "\n".join(lines) + "\n"
    redact = tr.Redactor([secret])
    assert "session abcdef123456" not in redact(stream)  # whole-text redaction swallows the events in between
    out = tr.redact_stream(stream, redact)
    assert out.endswith("\n") and "session abcdef123456" in out and '"result": "done"' in out
    json_lines = [line for line in out.splitlines() if line.startswith("{")]
    assert len(json_lines) == 5 and all(json.loads(line) for line in json_lines)
    decoded = " ".join(json.dumps(json.loads(line), ensure_ascii=False) for line in json_lines)
    assert secret not in decoded and "MC4CAQAw" not in out
    assert lines[1] in out.splitlines()  # an event with nothing to redact is kept byte for byte


def _stream_executor(stdout_text, stderr_text="", outcome=Execution(0, False), raise_after=None):
    """Writes the given stream with the run's z.ai key leaked into it (as if the agent had found it), then returns
    or raises."""
    def execute(argv, env, stdin, cwd, stdout_path, stderr_path, timeout):
        stdout_path.write_text(stdout_text.replace("TOKEN-HERE", ZAI))
        stderr_path.write_text(stderr_text.replace("TOKEN-HERE", ZAI))
        if raise_after is not None:
            raise raise_after
        return outcome
    return execute


def _one_agent(tmp_path, zshenv, executor):
    config = RunConfig(scenario="onboarding", base_url=BASE, runs_dir=tmp_path / "runs", zshenv=zshenv,
                       use_sandbox=False, claude_bin="/usr/bin/true", runner_env={}, slots_dir=tmp_path / "slots",
                       timeout_s=600)
    runner = Runner(config, executor=executor, log=lambda *a: None, proxy_factory=PlaceholderProxy)
    meta = runner.run(scenarios.plan("onboarding", ["glm53flash"], 1, base_url=BASE, stamp=config.stamp))[0]
    return meta, tmp_path / "runs" / config.stamp / "onboarding" / "glm53flash-1"


_PARTIAL = (json.dumps({"type": "system", "subtype": "init", "model": "glm-5.3-flash"}) + "\n"
            + json.dumps({"type": "assistant", "message": {"content": [
                {"type": "text", "text": "Opening a session."},
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "nc test.wesupport-ai.com 7801"}}]}})
            + "\n" + json.dumps({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "session abcdef123456\nkey TOKEN-HERE\n>"}]}})
            + "\n" + '{"type": "assistant", "message": {"content": [{"type": "text", "text": "Now I')


def test_runner_writes_transcript_on_timeout_and_keeps_the_partial_stream(tmp_path, zshenv):
    meta, agent = _one_agent(tmp_path, zshenv, _stream_executor(_PARTIAL, "debug TOKEN-HERE\n", Execution(-9, True)))
    assert meta["status"] == "timeout" and meta["timeout_s"] == 600
    raw = (agent / "transcript.jsonl").read_text()
    assert raw.count("\n") == 3 and raw.endswith('"text": "Now I')  # everything captured, the cut line included
    text = (agent / "transcript.md").read_text()
    for needle in ("Status: timeout (hit the wall-clock limit); exit code -9 (killed by signal 9)", "Timeout hit: yes",
                   "of a 600 s limit", "### Call 1: Bash", "[MILESTONE] gate session",
                   "the last line is incomplete: the CLI was stopped while writing it",
                   "None: the agent was stopped at the wall-clock limit before it reported."):
        assert needle in text, needle
    assert "key [REDACTED]" in text and "debug [REDACTED]" in text
    for path in agent.iterdir():
        assert ZAI not in path.read_text(), path
    report = reporting.write_report(agent.parent.parent).read_text()
    assert "[onboarding/glm53flash-1/transcript.md](onboarding/glm53flash-1/transcript.md)" in report


def test_runner_writes_transcript_on_error_exit_and_runner_error(tmp_path, zshenv):
    failed = _PARTIAL.rsplit("\n", 1)[0] + "\n" + json.dumps(
        {"type": "result", "subtype": "error_during_execution", "is_error": True, "result": ""}) + "\n"
    meta, agent = _one_agent(tmp_path / "a", zshenv, _stream_executor(failed, "", Execution(1, False)))
    assert meta["status"] == "error"
    text = (agent / "transcript.md").read_text()
    assert "Status: error (CLI exited with an error); exit code 1" in text and "error_during_execution" in text
    # the executor fails after the CLI wrote output: what was captured is still saved and rendered
    meta, agent = _one_agent(tmp_path / "b", zshenv,
                             _stream_executor(_PARTIAL, "", raise_after=OSError("capture pipe broke")))
    assert meta["status"] == "runner_error" and meta["partial_output"] is True
    assert "session abcdef123456" in (agent / "transcript.jsonl").read_text()
    text = (agent / "transcript.md").read_text()
    assert "Status: runner_error (runner error); no exit code recorded" in text
    assert "Reason: OSError: capture pipe broke" in text and "[MILESTONE] gate session" in text
    assert "key [REDACTED]" in text
