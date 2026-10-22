"""Group P and the direct-client half of J: URL resolution and bounded backoff."""

import pytest
from conftest import minimal_statement

from dsa_submitter import schema, tdb


def test_resolve_url_defaults_to_sandbox():
    assert tdb.resolve_url(None, None) == schema.SANDBOX_STATEMENT_URL


def test_resolve_url_production_requires_the_explicit_flag():
    assert tdb.resolve_url(None, "production") == schema.PRODUCTION_STATEMENT_URL
    with pytest.raises(tdb.TdbError, match="production"):
        tdb.resolve_url(schema.PRODUCTION_STATEMENT_URL, None)
    assert tdb.resolve_url(schema.PRODUCTION_STATEMENT_URL,
                           "production") == schema.PRODUCTION_STATEMENT_URL


def test_resolve_url_accepts_an_explicit_custom_url():
    custom = "http://example.invalid/api/v1/statement"
    assert tdb.resolve_url(custom, None) == custom


def test_client_backs_off_then_succeeds(fake_tdb):
    fake_tdb.config.update(mode="flaky_5xx", flaky_remaining=2)
    sleeps = []
    client = tdb.TransparencyClient(fake_tdb.url + "/api/v1/statement", fake_tdb.token,
                                    sleeper=sleeps.append)
    result = client.submit(minimal_statement())
    assert result["uuid"] == "uuid-1"
    assert result["duplicate"] is False
    assert result["puid"] == "aics-leaf-2"
    assert fake_tdb.request_count == 3
    assert sleeps == [1.0, 2.0]


def test_client_duplicate_puid_is_success(fake_tdb):
    fake_tdb.config["mode"] = "duplicate"
    client = tdb.TransparencyClient(fake_tdb.url + "/api/v1/statement", fake_tdb.token)
    result = client.submit(minimal_statement())
    assert result["duplicate"] is True
    assert result["uuid"] == "existing-uuid"
    assert result["id"] == 999


def test_client_raises_tdb_error_on_4xx(fake_tdb):
    fake_tdb.config["mode"] = "reject_429"
    client = tdb.TransparencyClient(fake_tdb.url + "/api/v1/statement", fake_tdb.token)
    with pytest.raises(tdb.TdbError) as excinfo:
        client.submit(minimal_statement())
    assert excinfo.value.status == 429
    assert "Too Many Requests" in excinfo.value.body
    assert fake_tdb.request_count == 1  # 4xx is never retried


def _dead_port():
    import socket
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_client_retries_network_failures_within_bounds():
    """A connection failure is retryable: 4 attempts, growing bounded sleeps."""
    sleeps = []
    client = tdb.TransparencyClient(
        f"http://127.0.0.1:{_dead_port()}/api/v1/statement", "tok", sleeper=sleeps.append)
    with pytest.raises(tdb.RetryableError, match="network failure"):
        client.submit(minimal_statement())
    assert sleeps == [1.0, 2.0, 4.0]
