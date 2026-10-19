import asyncio
import json
import time

import pytest
from aics_conformance.fakes import FakeServer
from aics_conformance.fakes.network import http_server, tcp_server
from aics_conformance.protocol import H, J, open_message
from aics_tlog import MerkleTree

from aics_capacity.cli import main, run_experiment
from aics_capacity.client import Client
from aics_capacity.local import CapacityFake
from aics_capacity.report import percentile, write_report
from aics_capacity.runner import Config, Outcome, RequestFailed, Runner, StopRun
from aics_capacity.scenarios import SCENARIOS
from aics_capacity.scenarios.agents import post
from aics_capacity.scenarios.onboarding import ceremony
from aics_capacity.transport import HTTP, Local


def config(**kwargs):
    return Config(
        **(
            dict(
                agents=2,
                think_time=0.005,
                duration=0.15,
                rate=10000,
                recipients=3,
                timeout=2,
                setup_timeout=30,
            )
            | kwargs
        )
    )


async def client_for(fake=None, **kwargs):
    runner = Runner(config(**kwargs))
    client = Client(
        runner, Local(fake or CapacityFake()), "https://fake", "https://fake/t", "https://fake/tiles"
    )
    await client.initialize()
    return client


@pytest.mark.parametrize("scenario", list(SCENARIOS))
async def test_all_scenarios_local(scenario):
    report = await run_experiment(scenario, config())
    assert report["stop_reason"] in ("duration", "workload_completed"), report["details"]
    assert report["measurement"]["requests"] > 0
    assert not report["measurement"]["errors_by_reason"], report["measurement"]
    assert report["peak_in_flight"] <= 16
    assert report["setup"]["requests"] >= 2
    if scenario.startswith("onboarding"):
        assert report["measurement"]["totals"]["gate_sessions"] > 0
    if scenario == "swarm-broadcast":
        assert report["measurement"]["totals"]["leaves"] == 4
        assert report["details"]["broadcast"]["complete"]


async def test_unchanged_base_fake_supports_base_scenarios():
    for name in ("steady-posting", "private-messaging", "onboarding-https", "onboarding-tcp"):
        report = await run_experiment(name, config(duration=0.06), fake=FakeServer())
        assert report["stop_reason"] == "duration"
        assert report["measurement"]["totals"]["writes"] > 0
        assert not report["measurement"]["errors"]


async def test_concurrency_and_actual_start_rate():
    runner = Runner(config(concurrency=3, rate=100, duration=2))
    runner.measure()
    active, peak, starts = 0, 0, []

    async def call():
        nonlocal active, peak
        starts.append(time.monotonic())
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.04)
        active -= 1
        return Outcome()

    await runner.workers(runner.request("probe", call) for _ in range(12))
    assert peak == 3
    assert runner.peak_in_flight == 3
    assert min(b - a for a, b in zip(starts, starts[1:])) >= 0.009
    assert max(r.queue_ms for r in runner.records) > 30


async def test_stall_does_not_release_catchup_burst():
    runner = Runner(config(rate=100, duration=2, concurrency=1))
    runner.measure()
    starts = []

    async def call():
        starts.append(time.monotonic())
        return Outcome()

    await runner.request("read", call)
    await asyncio.sleep(0.05)
    await runner.workers(runner.request("read", call) for _ in range(4))
    assert min(b - a for a, b in zip(starts, starts[1:])) >= 0.009


async def test_error_breaker_stops_queue_and_never_retries():
    runner = Runner(config(concurrency=1, min_samples=4, error_threshold=0.25, consecutive_errors=20))
    runner.measure()
    calls = 0

    async def fail():
        nonlocal calls
        calls += 1
        raise RequestFailed("rate_limit", 429, leaves=1, refusal=True)

    await runner.workers(runner.request("write", fail) for _ in range(100))
    assert calls == 4
    assert runner.stop_reason == "error_rate"
    assert len(runner.records) == 4
    assert all(r.refusal and r.leaves == 1 for r in runner.records)


async def test_consecutive_breaker_before_minimum_samples():
    runner = Runner(config(concurrency=1, consecutive_errors=2))
    runner.measure()

    async def fail():
        raise RequestFailed("http_503", 503)

    await runner.workers(runner.request("read", fail) for _ in range(50))
    assert len(runner.records) == 2
    assert runner.stop_reason == "consecutive_errors"


async def test_timeout_is_recorded_once():
    runner = Runner(config(timeout=0.01))
    runner.measure()
    calls = 0

    async def slow():
        nonlocal calls
        calls += 1
        await asyncio.sleep(10)
        return Outcome()

    with pytest.raises(RequestFailed, match="timeout"):
        await runner.request("write", slow)
    assert calls == 1
    assert runner.records[0].status is None
    assert runner.records[0].reason == "timeout"
    assert runner.in_flight == 0


async def test_duration_interrupts_per_key_window_wait():
    client = await client_for(agents=1, duration=0.03)
    agent = await client.register(client.agent())
    client.runner.write_window = (1, 3600)
    client.runner.measure()
    started = time.monotonic()
    with pytest.raises(StopRun):
        await post(client, agent)
    assert time.monotonic() - started < 0.2
    assert client.runner.stop_reason == "duration"
    assert not [r for r in client.runner.records if r.phase == "measurement"]


async def test_sender_sequence_serializes_concurrent_jobs():
    fake = CapacityFake()
    client = await client_for(fake)
    agent = await client.register(client.agent())
    await asyncio.gather(*(post(client, agent) for _ in range(8)))
    envs = [e["payload"]["envelope"] for e in fake.entries if e["actor_kid"] == agent.kid]
    assert [e["protected"]["seq"] for e in envs] == list(range(9))
    assert all(e["protected"]["prev"] == H(J(previous)) for previous, e in zip(envs, envs[1:]))


async def test_signed_refusal_counts_one_leaf_not_one_write():
    fake = CapacityFake()
    client = await client_for(fake)
    agent = await client.register(client.agent())
    body = J(dict(channel="capacity", title=None, text="ghp_" + "a" * 36))
    with pytest.raises(RequestFailed, match="secret_format:github_pat"):
        await client.write(
            agent,
            "post",
            dict(
                channel_sha256=H(b"capacity"),
                parent_index=None,
                body_hash=H(body),
                size=len(body),
                title_sha256=None,
            ),
            body,
        )
    record = client.runner.records[-1]
    assert (record.writes, record.leaves, record.status, record.refusal) == (0, 1, 403, True)
    assert agent.previous["protected"]["seq"] == 0


async def test_bad_receipt_is_not_acceptance():
    report = await run_experiment("steady-posting", config(), fake=CapacityFake("bad_receipt"))
    assert report["stop_reason"] == "scenario_failure"
    assert report["setup"]["totals"]["writes"] == 0


async def test_no_private_keys_in_reports(tmp_path):
    report = await run_experiment("private-messaging", config())
    write_report(report, tmp_path / "result")
    obj = json.loads((tmp_path / "result.json").read_text())
    assert obj["measurement"]["totals"]["writes"] > 0
    raw = json.dumps(obj)
    assert "private_seed" not in raw and '"envelope":' not in raw and '"ciphertext":' not in raw
    assert "Card recommendation" in (tmp_path / "result.md").read_text()
    assert all(row["recommended"] is None for row in obj["recommendations"])


async def test_pairwise_messages_are_real_sealed_boxes():
    fake = CapacityFake()
    client = await client_for(fake)
    from aics_capacity.scenarios.agents import private_messaging

    await private_messaging(client)
    keys = {a.kid: a.encryption_key for a in client.registered}
    messages = [e for e in fake.entries if e["type"] == "dm"]
    assert messages
    for entry in messages:
        q = entry["payload"]
        assert open_message(q["envelope"], fake.bodies[q["ct_hash"]], keys[q["to_kid"]]) == b"x" * 256


async def test_full_1000_recipient_fanout():
    fake = CapacityFake()
    report = await run_experiment(
        "swarm-broadcast",
        config(recipients=1000, think_time=0, duration=30, setup_timeout=90, rate=100000),
        fake=fake,
    )
    progress = report["details"].get("broadcast", {})
    assert progress.get("complete"), report["details"]
    assert progress["delivered"] == 1000
    assert report["measurement"]["totals"]["writes"] == 1001
    assert report["measurement"]["totals"]["leaves"] == 1001
    assert report["measurement"]["totals"]["deliveries"] == 1000
    assert report["operations"]["broadcast_status"]["requests"] == 80
    deliveries = [e for e in fake.entries if e["type"] == "swarm.delivery"]
    assert len({e["payload"]["to_kid"] for e in deliveries}) == 1000
    assert len({e["payload"]["ct_hash"] for e in deliveries}) == 1000
    assert len({e["payload"]["eph_pk"] for e in deliveries}) == 1000
    assert max(len(J(e)) for e in deliveries) < 65535
    assert all(len(fake.bodies[e["payload"]["ct_hash"]]) <= 65536 for e in deliveries)
    assert fake.writer.root() == MerkleTree([J(e) for e in fake.entries]).root()


async def test_short_broadcast_reports_partial_not_complete():
    report = await run_experiment("swarm-broadcast", config(recipients=20, duration=0.01, rate=1000))
    assert report["details"]["broadcast"]["complete"] is False
    assert report["details"]["broadcast"]["remaining"] > 0
    assert report["recommendations"][-1]["recommended"] is None


async def test_request_budget_stops_admission():
    report = await run_experiment("steady-posting", config(max_requests=12, duration=10))
    assert report["stop_reason"] == "request_budget"
    assert len(report["requests"]) == 12


async def test_tile_clients_cache_immutable_resources():
    report = await run_experiment("tile-checkpoint-reads", config(think_time=0.01))
    assert report["operations"]["tile"]["requests"] == 4
    assert report["operations"]["checkpoint"]["requests"] > 4
    assert not report["measurement"]["errors"]


async def test_swarm_join_uses_exact_roster_revisions():
    fake = CapacityFake()
    report = await run_experiment("swarm-join", config(agents=12, duration=2, think_time=0), fake=fake)
    assert report["details"]["formation_complete"]
    assert report["measurement"]["totals"]["writes"] == 12 + 1 + 10
    assert not [e for e in fake.entries if e["type"] == "refusal"]


async def test_http_and_tcp_real_loopback_transports():
    fake = CapacityFake()
    with http_server(fake) as api, tcp_server(fake) as gate:
        runner = Runner(config(duration=1))
        client = Client(runner, HTTP(), api, api + "/t", api + "/tiles")
        await client.initialize()
        await ceremony(client, "https")
        client.gate_url = "tcp://" + gate
        await ceremony(client, "tcp")
        await client.close()
        assert sum(r.gate_sessions for r in runner.records) == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(rate=0),
        dict(duration=float("nan")),
        dict(agents=0),
        dict(concurrency=-1),
        dict(think_time=-1),
        dict(error_threshold=1.5),
        dict(timeout=0),
        dict(min_samples=101),
        dict(body_bytes=65536),
    ],
)
def test_invalid_configs(kwargs):
    with pytest.raises(ValueError):
        Config(**kwargs)


def test_percentiles_known_values_and_empty():
    assert percentile([], 0.95) is None
    assert percentile([1, 2, 3, 4, 5], 0.50) == 3
    assert percentile([10, 20], 0.95) == 19.5


def test_cli_rejects_incompatible_gate():
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "remote",
                "--api",
                "https://example.test",
                "--gate",
                "https://example.test/t",
                "--tiles",
                "https://example.test/tiles",
                "--scenario",
                "onboarding-tcp",
            ]
        )
    assert exc.value.code == 2


def test_cli_outputs_json_markdown(tmp_path):
    result = main(
        [
            "local",
            "--scenario",
            "swarm-join",
            "--agents",
            "2",
            "--think-time",
            "0",
            "--duration",
            "2",
            "--rate",
            "10000",
            "--output",
            str(tmp_path / "cli"),
        ]
    )
    assert result == 0
    assert (tmp_path / "cli.json").exists() and (tmp_path / "cli.md").exists()


async def test_tile_corruption_halts_and_cannot_recommend():
    from aics_conformance.client import Response

    class CorruptTile(CapacityFake):
        def request(self, method, url, body=None, headers=None):
            response = super().request(method, url, body, headers)
            if "/tile/0/" in url and response.status == 200:
                return Response(200, bytes(len(response.body)), {})
            return response

    report = await run_experiment("tile-checkpoint-reads", config(), fake=CorruptTile())
    assert report["stop_reason"] == "validation_failure"
    assert report["details"]["failure"] == "tile_entry_mismatch"
    assert all(r["recommended"] is None for r in report["recommendations"])


async def test_pending_index_polls_known_hash_without_resubmission():
    from aics_conformance.client import Response

    class DelayedIndex(CapacityFake):
        pending = True
        submissions = 0

        def request(self, method, url, body=None, headers=None):
            if method == "POST":
                self.submissions += 1
            if "/v2/tlog/index/" in url and self.pending:
                self.pending = False
                return Response(404, J({"error": "pending"}), {})
            return super().request(method, url, body, headers)

    fake = DelayedIndex()
    client = await client_for(fake)
    await client.register(client.agent())
    assert fake.submissions == 1
    lookups = [r for r in client.runner.records if r.operation == "entry_index"]
    assert [r.status for r in lookups] == [404, 200]
    assert all(r.success for r in lookups)


async def test_bad_write_receipt_retains_http_status():
    client = await client_for(CapacityFake("bad_receipt"))
    with pytest.raises(RequestFailed):
        await client.register(client.agent())
    assert client.runner.records[-1].status == 202
    assert client.runner.records[-1].writes == 0


async def test_checkpoint_parts_are_bounded_and_reassembled():
    from urllib.parse import parse_qs, urlsplit

    from aics_conformance.client import Response
    from aics_conformance.protocol import U

    class Parts(CapacityFake):
        def request(self, method, url, body=None, headers=None):
            if "/v2/checkpoint-notes/" in url:
                offset = int(parse_qs(urlsplit(url).query)["offset"][0])
                note = self.checkpoint()
                chunk = note[offset : offset + 100]
                end = offset + len(chunk)
                return Response(
                    200,
                    J(
                        dict(
                            note_hash=H(note),
                            total_bytes=len(note),
                            offset=offset,
                            bytes=U(chunk),
                            next_offset=end if end < len(note) else None,
                        )
                    ),
                    {},
                )
            return super().request(method, url, body, headers)

    fake = Parts()
    client = await client_for(fake)
    note = fake.checkpoint()
    head = await client.checkpoint_reference(dict(size=len(fake.entries), note_hash=H(note), note=None))
    assert head.size == len(fake.entries)
    assert len([r for r in client.runner.records if r.operation == "checkpoint_part"]) > 1


async def test_status_pages_cannot_change_checkpoint():
    from aics_conformance.client import Response

    class Unpinned(CapacityFake):
        def request(self, method, url, body=None, headers=None):
            response = super().request(method, url, body, headers)
            if "after_member_index=" in url:
                obj = response.json()
                obj["checkpoint"]["size"] += 1
                return Response(200, J(obj), {})
            return response

    report = await run_experiment(
        "swarm-broadcast", config(recipients=26, duration=2, think_time=0), fake=Unpinned()
    )
    assert report["stop_reason"] == "scenario_failure"
    assert report["measurement"]["totals"]["deliveries"] == 0


async def test_report_denominator_includes_idle_time_and_refusals():
    from aics_capacity.report import build_report

    runner = Runner(config(duration=2))
    runner.measure()

    async def success():
        return Outcome(writes=1, leaves=1)

    async def refusal():
        raise RequestFailed("rate_limit", 403, leaves=1, refusal=True)

    await runner.request("post", success)
    with pytest.raises(RequestFailed):
        await runner.request("post", refusal)
    runner.phase_durations["measurement"] = 2
    report = build_report(runner, "steady-posting", "local")
    assert report["measurement"]["rates_per_second"]["writes"] == 0.5
    assert report["measurement"]["rates_per_second"]["leaves"] == 1
    assert report["measurement"]["refusals_by_reason"] == {"rate_limit": 1}
    assert report["per_second"][1]["writes"] == 0


async def test_inbox_fetches_each_seeded_message_once():
    report = await run_experiment("inbox-polling", config(duration=0.2, think_time=0.01))
    assert report["operations"]["inbox_bundle"]["requests"] == 2
    assert report["operations"]["inbox"]["requests"] > 2
    assert not report["measurement"]["errors"]


async def test_broadcast_headers_bind_every_recipient_and_duplicate_consumes_nothing():
    from aics_conformance.protocol import strict_json
    from nacl.public import SealedBox

    from aics_capacity.scenarios.swarms import swarm_broadcast

    fake = CapacityFake()
    client = await client_for(fake, recipients=3, duration=2, think_time=0)
    actors = []
    generate = client.agent

    def capture():
        agent = generate()
        actors.append(agent)
        return agent

    client.agent = capture
    await swarm_broadcast(client)
    keys = {a.kid: a for a in actors}
    deliveries = [e for e in fake.entries if e["type"] == "swarm.delivery"]
    assert len(deliveries) == 3
    for delivery in deliveries:
        q = delivery["payload"]
        start = fake.entries[q["broadcast_index"]]
        raw = SealedBox(keys[q["to_kid"]].encryption_key).decrypt(fake.bodies[q["ct_hash"]])
        size = int.from_bytes(raw[:4], "big")
        header = strict_json(raw[4 : 4 + size])
        assert header == dict(
            from_kid=delivery["actor_kid"],
            to_kid=q["to_kid"],
            envelope_nonce=q["envelope"]["protected"]["nonce"],
            swarm_id=start["payload"]["swarm_id"],
            broadcast_index=q["broadcast_index"],
            membership_index=start["payload"]["roster_index"],
        )
        assert raw[4 + size :] == b"x" * 256
    q = deliveries[0]["payload"]
    usage = dict(fake.used_deliveries)
    with pytest.raises(RequestFailed, match="swarm_duplicate_delivery"):
        await client.write(
            keys[deliveries[0]["actor_kid"]],
            "swarm.delivery",
            q["envelope"]["payload"],
            fake.bodies[q["ct_hash"]],
        )
    assert fake.used_deliveries == usage
    assert client.runner.records[-1].leaves == 1
    assert client.runner.records[-1].writes == 0


def test_incomplete_swarm_cli_is_nonzero(tmp_path):
    result = main(
        [
            "local",
            "--scenario",
            "swarm-join",
            "--agents",
            "100",
            "--duration",
            "0.01",
            "--rate",
            "100",
            "--think-time",
            "0",
            "--output",
            str(tmp_path / "partial"),
        ]
    )
    assert result == 2
    report = json.loads((tmp_path / "partial.json").read_text())
    assert report["details"]["formation_complete"] is False


async def test_bad_inclusion_stops_broadcast_before_deliveries():
    report = await run_experiment(
        "swarm-broadcast", config(recipients=2, duration=2, think_time=0), fake=CapacityFake("bad_proof")
    )
    assert report["stop_reason"] == "scenario_failure"
    assert report["measurement"]["totals"]["deliveries"] == 0
    assert report["measurement"]["errors_by_reason"] == {"bad_inclusion": 1}


async def test_plain_http_redirect_is_not_followed():
    import httpx

    from aics_capacity.transport import HTTP

    seen = []

    async def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://elsewhere.test"})

    transport = HTTP()
    await transport.close()
    transport.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    response = await transport.request("GET", "https://operator.test/tiles/checkpoint")
    assert response.status == 302
    assert len(seen) == 1
    await transport.close()
