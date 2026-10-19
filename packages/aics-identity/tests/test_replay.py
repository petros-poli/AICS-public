"""ReplayCache as a replay_check hook."""

from __future__ import annotations

import threading

from aics_identity.replay import ReplayCache


def test_hook_form_records_until_retain_until():
    cache = ReplayCache()
    assert cache("kid", "n", 100, 50) is True
    assert cache("kid", "n", 100, 99) is False
    assert cache("kid", "n", 100, 100) is True  # the record lapsed at retain_until
    assert cache("kid", "m", 100, 50) is True
    assert cache("other", "n", 200, 101) is True


def test_hook_form_without_bound_keeps_until_evicted():
    cache = ReplayCache(max_entries=2)
    assert cache("k", "forever", None, 0) is True
    assert cache("k", "forever", None, 10**12) is False
    cache("k", "a", 10, 1)
    cache("k", "b", 20, 1)  # over capacity: the entry closest to expiry goes first
    assert cache.seen("k", "a", now=1) is False
    assert cache.seen("k", "forever", now=1) is True
    assert len(cache) == 2


def test_concurrent_calls_accept_a_pair_once():
    cache = ReplayCache()
    results: list[bool] = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        results.append(cache("kid", "same-nonce", 10**10, 0))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1 and results.count(False) == 15
