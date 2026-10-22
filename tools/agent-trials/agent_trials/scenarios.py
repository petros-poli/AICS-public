"""Scenario plans: which agents run, with which provider and which prompt."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from urllib.parse import urlparse

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"
SCENARIOS = ("discovery", "onboarding", "dm", "swarm")
LOCAL_HOSTS = ("localhost", "127.0.0.1")


@dataclass
class TrialSpec:
    scenario: str
    provider: str
    n: int  # 1-based index per provider within the scenario
    prompt: str
    group: str = ""  # pair or swarm id
    role: str = ""
    start_delay: float = 0.0
    params: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.provider}-{self.n}"


def load_template(name: str) -> Template:
    return Template((SCENARIO_DIR / f"{name}.md").read_text() + (SCENARIO_DIR / "_footer.md").read_text())


def _short(stamp: str) -> str:
    return hashlib.sha256(stamp.encode()).hexdigest()[:6]


def plan(scenario: str, providers: list[str], count: int, *, base_url: str, stamp: str,
         gate_port: int = 7801, swarm_size: int = 8, minutes: int = 15, stagger: float = 3.0,
         seed: int | None = None) -> list[TrialSpec]:
    """Every trial of one run.

    * discovery / onboarding: ``count`` agents per provider;
    * dm: ``count`` pairs, the two partners taking providers round-robin;
    * swarm: ``count`` swarms of ``swarm_size`` agents each, providers mixed round-robin,
      every start spread over at most ``stagger`` seconds.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")
    if not providers:
        raise ValueError("no providers given")
    if count < 1:
        raise ValueError("count must be at least 1")
    parsed = urlparse(base_url)
    base_host = (parsed.hostname or "").lower().rstrip(".")
    local = base_host in LOCAL_HOSTS
    if not base_host or (parsed.scheme != "https" and not (local and parsed.scheme == "http")):
        raise ValueError(f"base URL must be https://<host> (http only for localhost): {base_url!r}")
    if int(gate_port) in (7700, 7701):
        raise ValueError("gate port 7700/7701 is production's gate; staging's plain TCP gate is 7801")
    template = load_template(scenario)
    tag = _short(stamp)
    rng = random.Random(seed if seed is not None else stamp)
    common = {"base_url": base_url.rstrip("/"), "base_host": base_host, "gate_host": base_host,
              "gate_port": str(gate_port), "minutes": str(minutes), "swarm_size": str(swarm_size)}
    counters: dict[str, int] = {}

    def make(provider: str, params: dict[str, str], group: str = "", role: str = "", delay: float = 0.0):
        counters[provider] = counters.get(provider, 0) + 1
        values = common | params
        return TrialSpec(scenario, provider, counters[provider], template.substitute(values), group, role,
                         delay, values)

    trials: list[TrialSpec] = []
    if scenario in ("discovery", "onboarding"):
        for provider in providers:
            for i in range(count):
                n = counters.get(provider, 0) + 1
                trials.append(make(provider, {"agent_name": f"trial-{tag}-{provider}-{n}"}))
    elif scenario == "dm":
        for pair in range(count):
            a = providers[(2 * pair) % len(providers)]
            b = providers[(2 * pair + 1) % len(providers)]
            name_a, name_b = f"trial-{tag}-p{pair + 1}-a", f"trial-{tag}-p{pair + 1}-b"
            code = hashlib.sha256(f"{stamp}/{pair}".encode()).hexdigest()[:8]
            group = f"pair{pair + 1}"
            trials.append(make(a, {"agent_name": name_a, "peer_name": name_b, "pair_code": code}, group, "a"))
            trials.append(make(b, {"agent_name": name_b, "peer_name": name_a, "pair_code": code}, group, "b"))
    else:
        if swarm_size < 2:
            raise ValueError("a swarm needs at least 2 agents")
        k = 0
        for swarm in range(count):
            swarm_tag = f"swarm{tag}{swarm + 1}"
            for _ in range(swarm_size):
                provider = providers[k % len(providers)]
                k += 1
                trials.append(make(provider, {"swarm_tag": swarm_tag, "agent_name": f"trial-{tag}-s{k}"},
                                   f"swarm{swarm + 1}", "member", round(rng.uniform(0, stagger), 2)))
    return trials
