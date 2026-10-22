"""Run model CLIs as autonomous agents against the AICS staging instance.

    uv run --project packages/aics-server python tools/agent-trials/run.py \\
        --base-url https://test.wesupport-ai.com --scenario onboarding --providers sonnet,glm53flash --count 2

On a throwaway Linux VM with Docker (one container per agent; sol enabled there):

    python3 tools/agent-trials/run.py --isolation container --scenario onboarding \\
        --providers sonnet,glm53flash,gemini,sol --count 1

(Re)render the readable per-agent transcripts (transcript.md) and REPORT.md of an existing run:

    python3 tools/agent-trials/run.py render tools/agent-trials/runs/<stamp> [--max-chars 4000]

See tools/agent-trials/README.md.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_trials import container, render, sandbox  # noqa: E402
from agent_trials import providers as prov  # noqa: E402
from agent_trials.proxy import PlaceholderProxy  # noqa: E402
from agent_trials.reporting import write_report  # noqa: E402
from agent_trials.runner import DEFAULT_RUNS, REPO, RunConfig, Runner, refuse_disabled  # noqa: E402
from agent_trials.scenarios import SCENARIOS, plan  # noqa: E402
from agent_trials.transcript import Redactor, host_of  # noqa: E402

#: The only hosts a trial may target: the staging instance, and the loopback for a local instance.
#: An allowlist: production's names, aliases, a trailing-dot spelling or its IP never pass.
STAGING_HOSTS = {"test.wesupport-ai.com"}
LOCAL_HOSTS = {"localhost", "127.0.0.1"}
PRODUCTION_GATE_PORTS = {7700, 7701}


def _limits(values: list[str], isolation: str = prov.MACOS) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in values:
        name, _, number = item.partition("=")
        if not number.isdigit():
            raise argparse.ArgumentTypeError(f"--max-concurrency wants provider=N, got {item!r}")
        out[name.strip()] = int(number)
    return prov.resolve_limits(out, isolation)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="https://test.wesupport-ai.com",
                   help="staging instance (default https://test.wesupport-ai.com); production hosts are refused")
    p.add_argument("--scenario", required=True, choices=SCENARIOS)
    p.add_argument("--providers", required=True,
                   help="comma-separated: " + ", ".join(prov.ADAPTERS))
    p.add_argument("--count", type=int, default=1,
                   help="agents per provider (discovery, onboarding), pairs (dm) or swarms (swarm)")
    p.add_argument("--swarm-size", type=int, default=8)
    p.add_argument("--stagger", type=float, default=3.0, help="swarm: spread starts over this many seconds")
    p.add_argument("--gate-port", type=int, default=7801, help="staging plain TCP gate port (default 7801)")
    p.add_argument("--timeout-minutes", type=float, default=15.0)
    p.add_argument("--max-concurrency", action="append", default=[], metavar="PROVIDER=N",
                   help="lower a provider's concurrency (never above its ceiling)")
    p.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS)
    p.add_argument("--gemini-auth-home", type=Path,
                   default=Path(os.environ.get("AICS_TRIALS_GEMINI_HOME",
                                               str(Path.home() / ".config/agent-trials/gemini-home"))),
                   help="a HOME the owner signed gemini into once; its .gemini sign-in files are copied per trial")
    p.add_argument("--gemini-account-is-disposable", action="store_true",
                   help="state that the gemini sign-in HOME holds a dedicated, throwaway Google account (the agent "
                        "can read its token); without this or the marker file the runner refuses gemini")
    p.add_argument("--run-as-user", default=os.environ.get("AICS_TRIALS_USER", "aics-trial"),
                   help="the separate unprivileged macOS user the agents run as (default aics-trial, or "
                        "AICS_TRIALS_USER); see README 'Separate user'")
    p.add_argument("--claude-bin", help="the claude binary to start (a copy outside your HOME, readable for the "
                                         "run-as user; README 'Separate user')")
    p.add_argument("--gemini-bin", help="the gemini launcher to start")
    p.add_argument("--zshenv", type=Path, default=Path.home() / ".zshenv", help=argparse.SUPPRESS)
    p.add_argument("--isolation", choices=prov.ISOLATIONS, default=prov.MACOS,
                   help="macos (default: sandbox-exec, separate user, credential proxy) or container (a throwaway "
                        "Linux VM: one Docker container per agent; README 'Cloud VM (container mode)')")
    p.add_argument("--env-file", type=Path,
                   default=Path(os.environ.get("AICS_TRIALS_ENV_FILE", str(container.DEFAULT_ENV_FILE))),
                   help="container mode: the credentials file (NAME=value lines, mode 600; default "
                        "/etc/agent-trials/env)")
    p.add_argument("--codex-auth", type=Path, default=Path.home() / ".codex" / "auth.json",
                   help="container mode: the VM's codex sign-in; sol gets a read-only copy per container")
    p.add_argument("--image", default=container.IMAGE, help="container mode: the agents' image")
    p.add_argument("--container-memory", default=container.Limits.memory,
                   help="container mode: memory per agent, no swap (default 2g)")
    p.add_argument("--container-pids", type=int, default=container.Limits.pids,
                   help="container mode: process limit per agent (default 512)")
    p.add_argument("--container-cpus", default=container.Limits.cpus, help="container mode: CPUs per agent (default 2)")
    p.add_argument("--docker-bin", default="docker", help=argparse.SUPPRESS)
    p.add_argument("--keep-workdirs", action="store_true", help="keep the per-trial temporary directories")
    p.add_argument("--transcript-max-chars", type=int, default=render.DEFAULT_MAX_CHARS, metavar="N",
                   help="transcript.md cuts each tool result to N characters, noting the full length (default "
                        f"{render.DEFAULT_MAX_CHARS}; 0: no limit)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and the command lines; execute nothing")
    return p


def render_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run.py render",
                                description="(Re)render transcript.md for every agent of an existing run (or one "
                                            "agent directory), then the run's REPORT.md, which links them.")
    p.add_argument("path", type=Path, help="runs/<stamp>, or one agent directory runs/<stamp>/<scenario>/<agent>")
    p.add_argument("--max-chars", type=int, default=render.DEFAULT_MAX_CHARS, metavar="N",
                   help=f"cut each tool result to N characters (default {render.DEFAULT_MAX_CHARS}; 0: no limit)")
    p.add_argument("--no-report", action="store_true", help="leave REPORT.md as it is")
    return p


def render_main(argv: list[str]) -> int:
    args = render_parser().parse_args(argv)
    dirs = render.agent_dirs(args.path) if args.path.is_dir() else []
    if not dirs:
        print(f"no agent directories (*/*/meta.json) under {args.path}", file=sys.stderr)
        return 2
    for agent_dir in dirs:
        print(render.write_transcript(agent_dir, max_chars=args.max_chars))
    run_dir = args.path if not (args.path / "meta.json").exists() else args.path.parent.parent
    if not args.no_report and any(run_dir.glob("*/*/meta.json")):
        print(write_report(run_dir))
    return 0


def check_base_url(url: str) -> str:
    """The trial host, or SystemExit: only staging (https, default port) or the loopback is accepted."""
    parts = urlsplit(url.strip())
    raw = parts.hostname or ""
    host = raw.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        raise SystemExit(f"refusing {url}: not a valid URL") from None
    if parts.username or parts.password:
        raise SystemExit(f"refusing {url}: no user information in the base URL")
    if port in PRODUCTION_GATE_PORTS:
        raise SystemExit(f"refusing {url}: port {port} is production's gate")
    if host in LOCAL_HOSTS:
        if parts.scheme not in ("http", "https"):
            raise SystemExit(f"refusing {url}: http(s) only")
        return host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SystemExit(f"refusing {url}: IP literals are refused (production shares the VPS address); use "
                         "https://test.wesupport-ai.com")
    if host not in STAGING_HOSTS or raw.endswith("."):
        raise SystemExit(f"refusing {url}: trials write only to staging ({', '.join(sorted(STAGING_HOSTS))}) or a "
                         "local instance; anything else may be production")
    if parts.scheme != "https" or port not in (None, 443):
        raise SystemExit(f"refusing {url}: staging is https://test.wesupport-ai.com (default port)")
    return host


def dry_run(trials, args, limits, config: RunConfig | None = None) -> int:
    print(f"DRY RUN: nothing is executed. scenario {args.scenario}, {len(trials)} agent(s), "
          f"base {args.base_url}, limit {args.timeout_minutes:g} min each")
    print("concurrency: " + ", ".join(f"{k} {v}" for k, v in limits.items() if v))
    if args.isolation == prov.CONTAINER:
        return dry_run_container(trials, args, limits, config)
    print(f"sandbox-exec available: {sandbox.available()}")
    per_provider: dict[str, int] = {}
    for spec in trials:
        per_provider[spec.provider] = per_provider.get(spec.provider, 0) + 1
    if args.scenario == "swarm":
        for name, n in per_provider.items():
            if n > limits.get(name, 0):
                print(f"note: swarm has {n} {name} agent(s) but {name} allows {limits[name]} at once; "
                      "the rest start when a slot frees")
    print(f"agents run as: {args.run_as_user} (sudo -n -u), through a loopback credential proxy")
    home = Path("/private/tmp/aics-trials-XXXX/<trial>/home")
    proxy = PlaceholderProxy()
    for spec in trials:
        adapter = prov.ADAPTERS[spec.provider]
        ctx = prov.AdapterContext(trial_home=home, trial_tmp=home / "tmp", zshenv=args.zshenv,
                                  claude_bin=args.claude_bin, gemini_bin=args.gemini_bin,
                                  gemini_auth_home=args.gemini_auth_home,
                                  gemini_disposable=args.gemini_account_is_disposable, proxy=proxy)
        print(f"\n[{spec.scenario}/{spec.label}] model {adapter.model}"
              + (f", {spec.group}/{spec.role}" if spec.group else "")
              + (f", start delay {spec.start_delay}s" if spec.start_delay else ""))
        try:
            launch = adapter.build(spec.prompt, ctx)
        except prov.ProviderUnavailable as exc:
            print(f"  unavailable: {exc}")
            continue
        redact = Redactor(launch.secrets)
        shown = [a if a != spec.prompt else f"<prompt {len(a)} chars>" for a in launch.argv]
        print(f"  argv: sudo -n -u {args.run_as_user} -- env -i <env> sandbox-exec -f <profile> "
              + " ".join(redact(a) for a in shown))
        if launch.stdin is not None:
            print(f"  stdin: <prompt {len(launch.stdin)} chars>")
        print("  env: " + " ".join(f"{k}={v}" for k, v in launch.redacted_env().items()))
        if launch.seed_files:
            print("  seeded into trial HOME: " + ", ".join(rel for _src, rel in launch.seed_files))
        if launch.preflight_problem:
            print(f"  would record: {launch.preflight_problem}")
    print("\nprompt of the first agent:\n" + "-" * 60 + "\n" + trials[0].prompt.rstrip() + "\n" + "-" * 60)
    return 0


def dry_run_container(trials, args, limits, config: RunConfig) -> int:
    lim = config.container_limits
    print(f"isolation: container, one fresh container per agent from {config.image} (--rm, --read-only, tmpfs HOME, "
          f"--network bridge, memory {lim.memory}, pids {lim.pids}, cpus {lim.cpus}, no Docker socket)")
    print(f"credentials from: {config.env_file} (parsed, never sourced); sol's codex sign-in: {config.codex_auth}")
    for name, n in _per_provider(trials).items():
        if args.scenario == "swarm" and n > limits.get(name, 0):
            print(f"note: swarm has {n} {name} agent(s) but {name} allows {limits[name]} at once; "
                  "the rest start when a slot frees")
    for spec in trials:
        adapter = prov.ADAPTERS[spec.provider]
        ctx = prov.AdapterContext(trial_home=Path(container.HOME), trial_tmp=Path("/tmp"), zshenv=args.zshenv,
                                  isolation=prov.CONTAINER, env_file=config.env_file, codex_auth=config.codex_auth)
        print(f"\n[{spec.scenario}/{spec.label}] model {adapter.model}"
              + (f", {spec.group}/{spec.role}" if spec.group else "")
              + (f", start delay {spec.start_delay}s" if spec.start_delay else ""))
        try:
            launch = adapter.build(spec.prompt, ctx)
        except prov.ProviderUnavailable as exc:
            print(f"  unavailable: {exc}")
            continue
        redact = Redactor(launch.secrets)
        slot = f"{spec.scenario}-{spec.label}"
        mounts = [(Path(f"<trial dir>/mounts/{i}-{Path(target).name}"), target)
                  for i, (_src, target) in enumerate(launch.mount_files)]
        argv, _client_env = container.docker_command(
            launch, name=container.container_name(config.stamp, slot), stamp=config.stamp, image=config.image,
            limits=lim, mounts=mounts, docker=args.docker_bin)
        shown = [a if a != spec.prompt else f"<prompt {len(a)} chars>" for a in argv]
        print("  argv: " + " ".join(redact(a) for a in shown))
        if launch.stdin is not None:
            print(f"  stdin: <prompt {len(launch.stdin)} chars>")
        print("  env: " + " ".join(f"{k}={v}" for k, v in launch.redacted_env().items()))
        if launch.secret_env:
            print("  passed by name, value only in the docker client's environment: " + ", ".join(launch.secret_env))
        for src, target in launch.mount_files:
            print(f"  mounted read-only: a per-trial copy of {src} at {target}")
        if launch.preflight_problem:
            print(f"  would record: {launch.preflight_problem}")
    print("\nprompt of the first agent:\n" + "-" * 60 + "\n" + trials[0].prompt.rstrip() + "\n" + "-" * 60)
    return 0


def _per_provider(trials) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in trials:
        counts[spec.provider] = counts.get(spec.provider, 0) + 1
    return counts


def main(argv: list[str] | None = None, *, runner_factory=Runner) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["render"]:
        return render_main(argv[1:])
    args = parser().parse_args(argv)
    names = [n.strip() for n in args.providers.split(",") if n.strip()]
    in_container = args.isolation == prov.CONTAINER
    try:
        refuse_disabled(names, args.isolation)
    except prov.ProviderUnavailable as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    try:
        limits = _limits(args.max_concurrency, args.isolation)
        container_limits = container.Limits(memory=args.container_memory, pids=args.container_pids,
                                            cpus=args.container_cpus)
    except (ValueError, argparse.ArgumentTypeError) as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    check_base_url(args.base_url)
    if args.gate_port in PRODUCTION_GATE_PORTS:
        print(f"refusing to start: gate port {args.gate_port} is production's gate (staging: 7801)", file=sys.stderr)
        return 2
    if in_container:
        if not args.dry_run and not sys.platform.startswith("linux"):
            # The point of container mode is a machine that holds nothing but trial credentials; here the
            # owner's own sign-ins (~/.codex, the Claude token) would go into the agents' containers.
            print("refusing to start: container mode runs on a throwaway Linux VM only (README, 'Cloud VM "
                  "(container mode)'); on this machine use the macOS mode", file=sys.stderr)
            return 2
        try:
            container.check_env_file(args.env_file)
        except RuntimeError as exc:
            print(f"refusing to start: {exc}", file=sys.stderr)
            return 2
    elif "gemini" in names:
        try:
            prov.check_disposable_sign_in("gemini", args.gemini_auth_home, args.gemini_account_is_disposable,
                                          Path.home(), owner_dirs=(".gemini",), flag="--gemini-account-is-disposable")
        except prov.ProviderUnavailable as exc:
            print(f"refusing to start: {exc}", file=sys.stderr)
            return 2
    config = RunConfig(scenario=args.scenario, base_url=args.base_url.rstrip("/"),
                       timeout_s=args.timeout_minutes * 60, runs_dir=args.runs_dir, limits=limits,
                       zshenv=args.zshenv, repo=REPO, gemini_auth_home=args.gemini_auth_home,
                       gemini_disposable=args.gemini_account_is_disposable, run_as_user=args.run_as_user,
                       keep_workdirs=args.keep_workdirs, claude_bin=args.claude_bin, gemini_bin=args.gemini_bin,
                       isolation=args.isolation, image=args.image, container_limits=container_limits,
                       env_file=args.env_file, codex_auth=args.codex_auth, docker_bin=args.docker_bin,
                       transcript_max_chars=args.transcript_max_chars)
    trials = plan(args.scenario, names, args.count, base_url=config.base_url, stamp=config.stamp,
                  gate_port=args.gate_port, swarm_size=args.swarm_size,
                  minutes=max(1, int(args.timeout_minutes) - 2), stagger=args.stagger)
    if args.dry_run:
        return dry_run(trials, args, limits, config)
    runner = runner_factory(config)
    print(f"run {config.stamp}: {len(trials)} agent(s) -> {runner.run_dir}")
    runner.run(trials)
    report = write_report(runner.run_dir)
    print(f"report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
