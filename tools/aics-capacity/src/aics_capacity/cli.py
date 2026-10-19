"""Operator CLI; merely naming a remote endpoint never starts an automatic sweep."""

import argparse
import asyncio
from pathlib import Path
from urllib.parse import urlsplit

from .client import Client
from .local import CapacityFake
from .report import build_report, write_report
from .runner import Config, RequestFailed, Runner, StopRun
from .scenarios import SCENARIOS
from .transport import HTTP, Local


async def run_experiment(
    scenario,
    config,
    *,
    mode="local",
    api=None,
    gate=None,
    tiles=None,
    log_vkey=None,
    fake=None,
    local_latency=0.0,
):
    runner = Runner(config)
    if mode == "local":
        transport = Local(fake if fake is not None else CapacityFake(), local_latency)
        api, gate, tiles = "https://fake", "https://fake/t", "https://fake/tiles"
        runner.details["fake"] = "Conformance FakeServer with tool-local workload-only swarm extension"
    else:
        transport = HTTP(config.concurrency, config.timeout)
    client = Client(runner, transport, api, gate, tiles, log_vkey=log_vkey)
    try:
        await client.initialize()
        await SCENARIOS[scenario](client)
    except StopRun:
        pass
    except RequestFailed as exc:
        runner.details["failure"] = exc.reason
        runner.halt("scenario_failure")
    except asyncio.CancelledError:
        runner.halt("interrupted")
    except Exception as exc:
        runner.details["failure"] = "client_" + type(exc).__name__
        runner.halt("client_failure")
    finally:
        runner.finish()
        await client.close()
    return build_report(runner, scenario, mode)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("local", "remote"))
    p.add_argument("--scenario", choices=SCENARIOS, default="steady-posting")
    p.add_argument("--api", help="API base URL, e.g. https://api.wesupport-ai.com")
    p.add_argument("--gate", help="Full HTTPS gate URL or tls://host:7700 / tcp://host:7701")
    p.add_argument("--tiles", help="Tile prefix URL, including /tiles")
    p.add_argument("--log-vkey", help="Optional operator-pinned log verification key")
    p.add_argument(
        "--output", type=Path, default=Path("results/capacity"), help="Output stem for .json and .md"
    )
    p.add_argument(
        "--local-writes-per-minute",
        type=int,
        default=100_000,
        help="Fake's signed card window; never changes a remote card",
    )
    p.add_argument("--local-latency", type=float, default=0.0)
    defaults = Config()
    for name in Config.__dataclass_fields__:
        value = getattr(defaults, name)
        p.add_argument("--" + name.replace("_", "-"), type=type(value), default=value)
    return p


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    try:
        config = Config(**{name: getattr(args, name) for name in Config.__dataclass_fields__})
        if args.local_writes_per_minute <= 0 or args.local_latency < 0:
            raise ValueError("local limits must be positive; latency must be nonnegative")
        if args.scenario == "private-messaging" and (config.agents < 2 or config.agents % 2):
            raise ValueError("private-messaging requires an even --agents >= 2")
        if args.scenario == "swarm-join" and config.agents < 2:
            raise ValueError("swarm-join requires --agents >= 2")
        if args.mode == "remote":
            for name in ("api", "gate", "tiles"):
                url = urlsplit(getattr(args, name) or "")
                allowed = ("https", "http", "tls", "tcp") if name == "gate" else ("https", "http")
                if (
                    url.scheme not in allowed
                    or not url.hostname
                    or url.username
                    or url.password
                    or url.query
                    or url.fragment
                ):
                    raise ValueError(f"--{name} must be a URL without credentials, query or fragment")
            gate_scheme = urlsplit(args.gate).scheme
            if args.scenario == "onboarding-tcp" and gate_scheme not in ("tls", "tcp"):
                raise ValueError("onboarding-tcp needs --gate tls://host:7700 or tcp://host:7701")
            if args.scenario == "onboarding-https" and gate_scheme not in ("http", "https"):
                raise ValueError("onboarding-https needs --gate https://host/t")
    except ValueError as exc:
        p.error(str(exc))
    report = asyncio.run(
        run_experiment(
            args.scenario,
            config,
            mode=args.mode,
            api=args.api,
            gate=args.gate,
            tiles=args.tiles,
            log_vkey=args.log_vkey,
            fake=CapacityFake(writes_per_minute=args.local_writes_per_minute)
            if args.mode == "local"
            else None,
            local_latency=args.local_latency,
        )
    )
    write_report(report, args.output)
    m = report["measurement"]
    print(
        f"{args.scenario}: {report['stop_reason']}; {m['requests']} measured requests; "
        f"{m['rates_per_second']['writes']:.3f} writes/s"
    )
    print(args.output.with_suffix(".json").resolve())
    print(args.output.with_suffix(".md").resolve())
    if report["stop_reason"] not in ("duration", "workload_completed") or m["errors"]:
        return 2
    broadcast = report["details"].get("broadcast")
    if report["details"].get("formation_complete") is False:
        return 2
    return 2 if broadcast and not broadcast["complete"] else 0
