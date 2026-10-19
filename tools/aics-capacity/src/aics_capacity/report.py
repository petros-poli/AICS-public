"""Measured rates, explicit denominators and provisional shared-budget limits."""

import json
import math
from collections import Counter
from dataclasses import asdict
from pathlib import Path


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * fraction
    low, high = math.floor(position), math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def summarize(records, elapsed):
    latency = [r.latency_ms for r in records]
    totals = {
        key: sum(getattr(r, key) for r in records)
        for key in ("writes", "leaves", "registrations", "gate_sessions", "deliveries", "bytes_received")
    }
    return dict(
        requests=len(records),
        errors=sum(not r.success for r in records),
        error_rate=sum(not r.success for r in records) / len(records) if records else 0,
        elapsed_seconds=elapsed,
        totals=totals,
        latency_ms={f"p{p}": percentile(latency, p / 100) for p in (50, 95, 99)},
        queue_p95_ms=percentile([r.queue_ms for r in records], 0.95),
        rates_per_second={key: value / elapsed if elapsed > 0 else 0 for key, value in totals.items()},
        refusals_by_reason=dict(Counter(r.reason for r in records if r.refusal)),
        errors_by_reason=dict(Counter(r.reason for r in records if not r.success)),
        statuses=dict(Counter(str(r.status) if r.status is not None else "transport" for r in records)),
    )


def recommendations(runner, metrics, mode):
    cfg = runner.config
    rates = metrics["rates_per_second"]
    healthy = metrics["requests"] >= cfg.min_samples and metrics["errors"] == 0
    healthy = healthy and runner.stop_reason in (None, "duration") and metrics["elapsed_seconds"] >= 30
    qualified = healthy and mode == "remote"
    count = cfg.agents
    # One budget divided between operations; daily broadcast capacity is a
    # projection of the same writer budget, never an additional daily quota.
    definitions = [
        (
            "writes_per_minute_per_key",
            "writes",
            60,
            count,
            "All accepted writes, including claims, grants and fan-out",
        ),
        (
            "registrations_per_hour_per_key",
            "registrations",
            3600,
            count,
            "Fresh-key registrations per simulated actor slot; not a Sybil control",
        ),
        (
            "broadcast_deliveries_per_day",
            "deliveries",
            86400,
            count,
            "Per broadcasting key, assuming the same competing-key count as the write budget",
        ),
    ]
    rows = []
    for name, metric, period, divisor, meaning in definitions:
        observed = rates[metric]
        candidate = math.floor(observed * cfg.headroom * period / divisor) if observed > 0 else None
        status = "provisional" if qualified and candidate is not None else "insufficient_evidence"
        reason = (
            f"floor({observed:.6f}/s × {cfg.headroom:g} usable fraction × {period}s / {divisor} "
            f"concurrent keys) = {candidate}. {meaning}. "
            if candidate is not None
            else "No measured events of this type. "
        )
        if not qualified:
            reason += "No publishable limit: require a healthy remote measurement lasting >=30s with enough samples. "
        if name == "registrations_per_hour_per_key":
            reason += "The ceremony creates a fresh identity; this does not measure repeated registrations under one existing key. "
            status = "needs_operator_policy"
        if name == "broadcast_deliveries_per_day":
            progress = runner.details.get("broadcast", {})
            if not progress.get("complete"):
                status = "insufficient_evidence"
                reason += "Fan-out was absent or incomplete. "
            if candidate is not None:
                writes_per_minute = math.floor(rates["writes"] * cfg.headroom * 60 / count)
                shared_cap = math.floor(writes_per_minute * 1440 * cfg.recipients / (cfg.recipients + 1))
                candidate = min(candidate, shared_cap)
                reason += (
                    f"Capped to {candidate} by {writes_per_minute} writes/min/key × 1440 × "
                    f"{cfg.recipients}/{cfg.recipients + 1}, reserving one start per full broadcast. "
                )
            reason += "Subtract broadcast starts and other writes; each start costs one leaf. Do not add a slower swarm-only daily cap. "
        if name == "writes_per_minute_per_key" and candidate is not None and candidate * 1440 < 1000:
            status = "below_swarm_floor"
            reason += "Below SWARMS R36's 1,000 accepted writes/key/day floor; reduce admitted keys or increase measured capacity, never inflate evidence. "
        reason += (
            "An offered-load result is a sustainable observed rate, not proof of the saturation ceiling."
        )
        rows.append(
            dict(
                limit=name,
                candidate=candidate,
                recommended=candidate if status == "provisional" else None,
                status=status,
                reasoning=reason,
            )
        )
    return rows


def build_report(runner, scenario, mode):
    measurement = [r for r in runner.records if r.phase == "measurement"]
    elapsed = runner.phase_durations.get("measurement", 0.0)
    metrics = summarize(measurement, elapsed)
    # Include idle seconds in this series and in the total rate denominator.
    bins = []
    offset = runner.phase_durations.get("setup", 0)
    by_second = {}
    for record in measurement:
        by_second.setdefault(int(record.finished - offset), []).append(record)
    for second in range(math.ceil(elapsed)):
        rows = by_second.get(second, [])
        width = min(1.0, elapsed - second)
        bins.append(
            dict(
                second=second,
                seconds=width,
                writes=sum(r.writes for r in rows),
                leaves=sum(r.leaves for r in rows),
                errors=sum(not r.success for r in rows),
            )
        )
    return dict(
        schema_version=1,
        mode=mode,
        scenario=scenario,
        config=runner.config_dict(),
        stop_reason=runner.stop_reason or "workload_completed",
        peak_in_flight=runner.peak_in_flight,
        measurement=metrics,
        setup=summarize(
            [r for r in runner.records if r.phase == "setup"], runner.phase_durations.get("setup", 0.0)
        ),
        operations={
            op: summarize([r for r in measurement if r.operation == op], elapsed)
            for op in sorted({r.operation for r in measurement})
        },
        per_second=bins,
        recommendations=recommendations(runner, metrics, mode),
        details=runner.details,
        requests=[asdict(r) for r in runner.records],
        limitations=[
            "Local fake results cannot size a 2 vCPU / 4 GB VPS.",
            "Rates count receipted write/refusal leaves, not independently observed durable inclusion for every write.",
            "No retries. Missing/uncertain outcomes require operator investigation before a new run.",
            "One writer process only. Limits compete for the same serial append/commit path.",
            "Registration and delivery candidates are projections, not additional capacity budgets.",
        ],
    )


def markdown(report):
    m = report["measurement"]
    rate = m["rates_per_second"]
    lines = [
        f"# AICS capacity: {report['scenario']}",
        "",
        f"Mode: **{report['mode']}**. Stop: **{report['stop_reason']}**. "
        f"Measured {m['elapsed_seconds']:.3f}s; {m['requests']} requests, {m['errors']} errors.",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key, value in m["latency_ms"].items():
        lines.append(
            f"| {key} request latency (ms) | {value:.3f} |"
            if value is not None
            else f"| {key} latency | n/a |"
        )
    for key in ("writes", "leaves", "gate_sessions", "registrations", "deliveries"):
        lines.append(f"| {key}/s | {rate[key]:.6f} |")
    lines += [
        "",
        "Gate sessions count completed ceremonies. Request latency excludes queue time; "
        "JSON includes queue latency, setup, per-operation percentiles and every request.",
        "",
        "## Card recommendation candidates",
        "",
        "| Limit | Candidate | Publishable recommendation | Status |",
        "| --- | ---: | ---: | --- |",
    ]
    for row in report["recommendations"]:
        lines.append(f"| {row['limit']} | {row['candidate']} | {row['recommended']} | {row['status']} |")
    for row in report["recommendations"]:
        lines += ["", f"**{row['limit']}**: {row['reasoning']}"]
    lines += [
        "",
        "## Refusals",
        "",
        json.dumps(m["refusals_by_reason"], sort_keys=True),
        "",
        "## Limits of this measurement",
        "",
    ]
    lines.extend(f"- {text}" for text in report["limitations"])
    if "broadcast" in report["details"]:
        p = report["details"]["broadcast"]
        lines += [
            "",
            f"Broadcast: {p['delivered']} delivered, {p['remaining']} remaining, "
            f"{p['excluded']} excluded; complete={p['complete']}.",
        ]
    return "\n".join(lines) + "\n"


def write_report(report, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_suffix(".json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    output.with_suffix(".md").write_text(markdown(report))
