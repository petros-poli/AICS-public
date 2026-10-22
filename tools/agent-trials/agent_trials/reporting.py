"""Build runs/<stamp>/REPORT.md from the saved transcripts and meta files."""

from __future__ import annotations

import json
from pathlib import Path

from . import render as rd
from . import transcript as tr

_STATUS_NOTE = rd.STATUS_NOTE


def analyse(trial_dir: Path) -> dict:
    # The same events the readable transcript.md marks its milestones and flags on (render.load_trial).
    trial = rd.load_trial(trial_dir)
    events = trial.events
    return {
        "dir": trial_dir,
        "meta": trial.meta,
        "steps": tr.steps_reached(events),
        "refusals": tr.refusal_codes(events),
        "quotes": tr.friction_quotes(events, limit=2),
        "obstacles": tr.reported_obstacles(events),
        "forbidden": tr.forbidden_writes(events, trial.allowed_hosts, trial.production_ips),
    }


def _trial_dirs(run_dir: Path) -> list[Path]:
    return sorted(p.parent for p in run_dir.glob("*/*/meta.json"))


def _cell(value: bool) -> str:
    return "yes" if value else "-"


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render(run_dir: Path) -> str:
    run_info = {}
    if (run_dir / "run.json").exists():
        run_info = json.loads((run_dir / "run.json").read_text())
    analyses = [analyse(d) for d in _trial_dirs(run_dir)]
    scenarios = sorted({a["meta"]["scenario"] for a in analyses}) or [run_info.get("scenario", "?")]
    lines: list[str] = [f"# Agent trials {run_dir.name}", ""]
    lines.append(f"- Scenario: {', '.join(scenarios)}")
    if run_info.get("base_url"):
        lines.append(f"- Staging base URL: {run_info['base_url']}")
    if run_info.get("timeout_s"):
        lines.append(f"- Wall-clock limit per agent: {int(run_info['timeout_s'] // 60)} min")
    if run_info.get("limits"):
        lines.append("- Concurrency limits: " + ", ".join(f"{k} {v}" for k, v in run_info["limits"].items() if v))
    if run_info.get("peak_concurrency"):
        peaks = {k: v for k, v in run_info["peak_concurrency"].items() if v}
        lines.append("- Peak concurrency reached: " + (", ".join(f"{k} {v}" for k, v in peaks.items()) or "none"))
    proof = run_dir / "sandbox-proof.json"
    if proof.exists():
        probes = json.loads(proof.read_text())
        status = "held" if all(p.get("ok") for p in probes) else "FAILED"
        lines.append(f"- Sandbox proof: {status} (" + ", ".join(
            f"{p['label']}: {'denied' if p['denied'] else ('allowed' if p['kind'] == 'write-allowed' else 'absent' if not p['exists'] else 'NOT denied')}"
            for p in probes) + ")")
    statuses: dict[str, int] = {}
    for a in analyses:
        statuses[a["meta"].get("status", "?")] = statuses.get(a["meta"].get("status", "?"), 0) + 1
    lines.append(f"- Agents: {len(analyses)} (" + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())) + ")")
    lines.append("")

    # Forbidden production writes first: they are the one thing that must be looked at.
    forbidden = [(a, k, item) for a in analyses for k, item in enumerate(a["forbidden"], 1)]
    lines.append("## Forbidden production write attempts")
    lines.append("")
    if forbidden:
        for a, k, item in forbidden:
            link = f"{_transcript(a, run_dir)}#forbidden-{k}"
            lines.append(f"- {a['meta']['provider']}-{a['meta']['n']}: {_md(item)} ([in its transcript]({link}))")
    else:
        lines.append("None detected (tool inputs grepped for writes to wesupport-ai.com hosts other than "
                     f"{analyses[0]['meta'].get('staging_host', 'staging') if analyses else 'staging'}, to production's "
                     "IPs, for GET /t sessions there, and for TCP to ports 7700/7701 on any host).")
    lines.append("")

    for scenario in scenarios:
        group = [a for a in analyses if a["meta"]["scenario"] == scenario]
        steps = tr.SCENARIO_STEPS.get(scenario, []) + tr.CORE_STEPS
        labels = {key: label for key, label, _w, _p in tr.STEPS}
        lines.append(f"## Steps reached: {scenario}")
        lines.append("")
        header = ["agent", "model", "status", "wall s"] + [labels[s] for s in steps] + ["refusals"]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "---|" * len(header))
        for a in group:
            m = a["meta"]
            agent = f"{m['provider']}-{m['n']}" + (f" ({m['group']}{'/' + m['role'] if m.get('role') else ''})"
                                                   if m.get("group") else "")
            refusals = ", ".join(f"{k} x{v}" for k, v in a["refusals"].items()) or "-"
            row = [agent, m.get("model", ""), m.get("status", "?"), str(m.get("wall_s", ""))]
            row += [_cell(a["steps"].get(s, False)) for s in steps] + [refusals]
            lines.append("| " + " | ".join(_md(c) for c in row) + " |")
        lines.append("")
        if "verification_done" in steps:
            lines.append("`verification done` is a heuristic: the agent fetched the checkpoint and a tile or proof.")
            lines.append("")

    lines.append("## Per agent")
    lines.append("")
    for a in analyses:
        m = a["meta"]
        lines.append(f"### {m['scenario']} / {m['provider']}-{m['n']}")
        lines.append("")
        lines.append(f"- Model: {m.get('model', '')}; status: {m.get('status', '?')} "
                     f"({_STATUS_NOTE.get(m.get('status', ''), '')})"
                     + (f"; reason: {m['reason']}" if m.get("reason") else ""))
        lines.append(f"- Wall time: {m.get('wall_s', 0)} s; queued {m.get('queued_s', 0)} s; "
                     f"start offset {m.get('start_offset_s', 0)} s")
        reached = [lbl for key, lbl, _w, _p in tr.STEPS if a["steps"].get(key)
                   and (key != "reached_site" or m["scenario"] == "discovery")]
        lines.append(f"- Steps: {', '.join(reached) if reached else 'none'}")
        if a["refusals"]:
            lines.append("- Refusal codes: " + ", ".join(f"`{k}` x{v}" for k, v in a["refusals"].items()))
        for quote in a["quotes"]:
            lines.append(f"- In its own words: \"{quote}\"")
        rel = a["dir"].relative_to(run_dir)
        if (a["dir"] / rd.TRANSCRIPT_MD).exists():
            lines.append(f"- Transcript: [{rel}/{rd.TRANSCRIPT_MD}]({_transcript(a, run_dir)}) (raw stream: "
                         f"`{rel}/{rd.RAW_STREAM}`, `{rd.STDERR}`)")
        else:
            lines.append(f"- Transcript: `{rel}/` ({rd.TRANSCRIPT_MD} not rendered yet: "
                         f"`python3 tools/agent-trials/run.py render {run_dir}`)")
        lines.append("")

    lines.append("## Distinct obstacles across agents")
    lines.append("")
    merged: dict[str, tuple[str, list[str]]] = {}
    for a in analyses:
        who = f"{a['meta']['provider']}-{a['meta']['n']}"
        for item in a["obstacles"]:
            key = tr.obstacle_key(item)
            if key not in merged:
                merged[key] = (item, [])
            if who not in merged[key][1]:
                merged[key][1].append(who)
    codes: dict[str, list[str]] = {}
    for a in analyses:
        for code in a["refusals"]:
            codes.setdefault(code, []).append(f"{a['meta']['provider']}-{a['meta']['n']}")
    runner_problems: dict[str, list[str]] = {}
    for a in analyses:
        status = a["meta"].get("status")
        if status not in ("ok", None):
            reason = a["meta"].get("reason") or _STATUS_NOTE.get(status, status)
            runner_problems.setdefault(reason, []).append(f"{a['meta']['provider']}-{a['meta']['n']}")
    if not (merged or codes or runner_problems):
        lines.append("None reported.")
    for reason, who in sorted(runner_problems.items()):
        lines.append(f"- Run: {_md(reason)} ({', '.join(who)})")
    for code, who in sorted(codes.items()):
        lines.append(f"- Gate refusal `{code}` ({', '.join(who)})")
    for item, who in merged.values():
        lines.append(f"- {_md(item)} ({', '.join(who)})")
    lines.append("")
    return "\n".join(lines)


def _transcript(a: dict, run_dir: Path) -> str:
    return (a["dir"].relative_to(run_dir) / rd.TRANSCRIPT_MD).as_posix()


def write_report(run_dir: Path) -> Path:
    path = run_dir / "REPORT.md"
    path.write_text(render(run_dir))
    return path
