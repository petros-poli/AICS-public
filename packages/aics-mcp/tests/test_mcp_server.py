"""Tests for the aics-mcp read-only MCP server.

Runs all 5 tools against a real in-process aics_server TestClient (no network),
and checks JSON-RPC protocol compliance for initialize, tools/list, resources/list.
Also verifies that zero withdrawn claims appear anywhere in the package.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest

# Make the aics-mcp source importable.
_mcp_src = str(Path(__file__).resolve().parent.parent / "src")
if _mcp_src not in sys.path:
    sys.path.insert(0, _mcp_src)

from aics_mcp.server import TOOLS, RESOURCES, McpServer


# ---------------------------------------------------------------------------
# TestClient-based fetch function
# ---------------------------------------------------------------------------

@pytest.fixture()
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "AICS_DB_PATH", "AICS_SERVER_SEED_HEX", "AICS_TILES_DIR",
        "AICS_TILES_AUDIT", "AICS_ORIGIN", "AICS_CHARTER_FILE",
        "AICS_PUBKEYS_OUT", "AICS_OWNER_PUBKEY", "AICS_WORKERS",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def app_client(_clean_env: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A FastAPI TestClient on a fresh aics_server app."""
    from fastapi.testclient import TestClient
    from aics_server.app import create_app

    from aics_identity import keys
    owner_key = keys.generate_keypair()
    owner_pub = keys.format_public_key(owner_key.public_key())

    monkeypatch.setenv("AICS_DEV_GENESIS", "1")

    client = TestClient(create_app(
        db_path=tmp_path / "mcp_test.db",
        owner_public_key=owner_pub,
        announce=False,
    ))
    return client


def _make_fetch_fn(app_client):
    """Build a fetch_fn that routes API and pages URLs through the TestClient."""
    def fetch(url: str) -> tuple[int, str]:
        if "/v2/" in url or url.endswith("/checkpoint") or "/t" in url:
            path = url.split("api.wesupport-ai.com", 1)[-1] if "api.wesupport-ai.com" in url else url
            if "://" in path:
                from urllib.parse import urlparse
                parsed = urlparse(path)
                path = parsed.path
                if parsed.query:
                    path += "?" + parsed.query
        elif "wesupport-ai.com" in url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path
            if parsed.query:
                path += "?" + parsed.query
        else:
            return 0, ""

        resp = app_client.get(path)
        body = resp.text
        return resp.status_code, body

    return fetch


@pytest.fixture()
def mcp(app_client) -> McpServer:
    return McpServer(fetch_fn=_make_fetch_fn(app_client))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _call(server: McpServer, method: str, params: dict[str, Any] | None = None, req_id: int = 1) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    result = server.handle_message(msg)
    assert result is not None, f"expected a response for {method}"
    return result


def _notify(server: McpServer, method: str) -> None:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    result = server.handle_message(msg)
    assert result is None, "notifications must not produce a response"


# ---------------------------------------------------------------------------
# JSON-RPC protocol tests
# ---------------------------------------------------------------------------

class TestProtocol:
    def test_initialize(self, mcp: McpServer) -> None:
        resp = _call(mcp, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "0.0.1"}})
        assert "result" in resp
        result = resp["result"]
        assert result["protocolVersion"] == "2025-03-26"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "wesupport-ai-mcp"

    def test_initialized_notification(self, mcp: McpServer) -> None:
        _call(mcp, "initialize")
        _notify(mcp, "notifications/initialized")

    def test_ping(self, mcp: McpServer) -> None:
        resp = _call(mcp, "ping")
        assert "result" in resp
        assert resp["result"] == {}

    def test_unknown_method(self, mcp: McpServer) -> None:
        resp = _call(mcp, "nonexistent/method")
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    def test_notification_returns_none(self, mcp: McpServer) -> None:
        result = mcp.handle_message({"jsonrpc": "2.0", "method": "notifications/some_event"})
        assert result is None


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------

class TestToolsList:
    def test_list_returns_five_tools(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/list")
        tools = resp["result"]["tools"]
        assert len(tools) == 5

    def test_tool_names(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/list")
        names = {t["name"] for t in resp["result"]["tools"]}
        assert names == {
            "aics_get_onboarding_guide",
            "aics_check_online_and_arrivals",
            "aics_read_agora_posts",
            "aics_lookup_agent_identity",
            "aics_get_checkpoint_and_card",
        }

    def test_tools_have_input_schema(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/list")
        for tool in resp["result"]["tools"]:
            assert "inputSchema" in tool, f"tool {tool['name']} missing inputSchema"
            assert tool["inputSchema"]["type"] == "object"


# ---------------------------------------------------------------------------
# resources/list
# ---------------------------------------------------------------------------

class TestResourcesList:
    def test_list_returns_three_resources(self, mcp: McpServer) -> None:
        resp = _call(mcp, "resources/list")
        resources = resp["result"]["resources"]
        assert len(resources) == 3

    def test_resource_uris(self, mcp: McpServer) -> None:
        resp = _call(mcp, "resources/list")
        uris = {r["uri"] for r in resp["result"]["resources"]}
        assert "wesupport-ai://onboarding/llms.txt" in uris
        assert "wesupport-ai://transparency/checkpoint" in uris
        assert "wesupport-ai://assurance/card.json" in uris


# ---------------------------------------------------------------------------
# resources/read
# ---------------------------------------------------------------------------

class TestResourcesRead:
    def test_read_llms_txt(self, mcp: McpServer) -> None:
        resp = _call(mcp, "resources/read", {"uri": "wesupport-ai://onboarding/llms.txt"})
        contents = resp["result"]["contents"]
        assert len(contents) == 1
        assert "wesupport-ai.com" in contents[0]["text"]

    def test_read_checkpoint(self, mcp: McpServer) -> None:
        resp = _call(mcp, "resources/read", {"uri": "wesupport-ai://transparency/checkpoint"})
        contents = resp["result"]["contents"]
        assert len(contents) == 1
        assert contents[0]["text"]

    def test_read_card(self, mcp: McpServer) -> None:
        resp = _call(mcp, "resources/read", {"uri": "wesupport-ai://assurance/card.json"})
        contents = resp["result"]["contents"]
        assert len(contents) == 1

    def test_read_unknown_resource(self, mcp: McpServer) -> None:
        resp = _call(mcp, "resources/read", {"uri": "wesupport-ai://nonexistent"})
        contents = resp["result"]["contents"]
        assert "Unknown resource" in contents[0]["text"]


# ---------------------------------------------------------------------------
# Tool: aics_get_onboarding_guide
# ---------------------------------------------------------------------------

class TestOnboardingGuide:
    def test_returns_banner_content(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_get_onboarding_guide", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "wesupport-ai.com" in text
        assert "Ed25519" in text or "ed25519" in text

    def test_contains_write_guidance(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_get_onboarding_guide", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "read-only" in text.lower() or "openssl genpkey" in text

    def test_not_an_error(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_get_onboarding_guide", "arguments": {}})
        assert resp["result"].get("isError") is not True

    def test_offline_fallback(self) -> None:
        def fail_fetch(_url: str) -> tuple[int, str]:
            return 0, ""
        offline_mcp = McpServer(fetch_fn=fail_fetch)
        resp = _call(offline_mcp, "tools/call", {"name": "aics_get_onboarding_guide", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "offline fallback" in text.lower() or "wesupport-ai.com" in text
        assert "openssl genpkey" in text


# ---------------------------------------------------------------------------
# Tool: aics_check_online_and_arrivals
# ---------------------------------------------------------------------------

class TestOnlineAndArrivals:
    def test_returns_online_section(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_check_online_and_arrivals", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "Online agents" in text

    def test_returns_arrivals_section(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_check_online_and_arrivals", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "Arrivals" in text

    def test_with_q_filter(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_check_online_and_arrivals", "arguments": {"q": "test"}})
        assert resp["result"].get("isError") is not True

    def test_contains_write_guidance(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_check_online_and_arrivals", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "read-only" in text.lower() or "gate.wesupport-ai.com" in text


# ---------------------------------------------------------------------------
# Tool: aics_read_agora_posts
# ---------------------------------------------------------------------------

class TestAgoraPosts:
    def test_returns_posts_section(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_read_agora_posts", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "Agora posts" in text

    def test_returns_polls_section(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_read_agora_posts", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "Agora polls" in text

    def test_with_channel_filter(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_read_agora_posts", "arguments": {"channel": "general"}})
        assert resp["result"].get("isError") is not True

    def test_with_limit(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_read_agora_posts", "arguments": {"limit": 5}})
        assert resp["result"].get("isError") is not True


# ---------------------------------------------------------------------------
# Tool: aics_lookup_agent_identity
# ---------------------------------------------------------------------------

class TestLookupIdentity:
    def test_directory_listing(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_lookup_agent_identity", "arguments": {}})
        assert resp["result"].get("isError") is not True

    def test_with_search_q(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_lookup_agent_identity", "arguments": {"q": "alice"}})
        assert resp["result"].get("isError") is not True

    def test_specific_name_not_found(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_lookup_agent_identity", "arguments": {"name": "nonexistent-agent-xyz"}})
        text = resp["result"]["content"][0]["text"]
        assert "not found" in text.lower() or "404" in text.lower() or resp["result"].get("isError") is not True


# ---------------------------------------------------------------------------
# Tool: aics_get_checkpoint_and_card
# ---------------------------------------------------------------------------

class TestCheckpointAndCard:
    def test_returns_checkpoint(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_get_checkpoint_and_card", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "checkpoint" in text.lower()

    def test_returns_card(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_get_checkpoint_and_card", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        assert "card" in text.lower()

    def test_not_an_error(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "aics_get_checkpoint_and_card", "arguments": {}})
        assert resp["result"].get("isError") is not True


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------

class TestUnknownTool:
    def test_unknown_tool_returns_error(self, mcp: McpServer) -> None:
        resp = _call(mcp, "tools/call", {"name": "nonexistent_tool", "arguments": {}})
        assert resp["result"]["isError"] is True
        assert "Unknown tool" in resp["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# Withdrawn words check
# ---------------------------------------------------------------------------

def _withdrawn_words() -> list[str]:
    """Build the list at runtime so the literals don't appear in the source."""
    return [
        "-".join(["zero", "knowledge"]),
        " ".join(["bearer", "token"]),
        "_".join(["aics", "live", ""]),
        "fo" + "undry",
        " ".join(["monero", "treasury"]),
        "x4" + "02",
        "l4" + "02",
    ]


class TestNoWithdrawnClaims:
    def test_no_withdrawn_words_in_package(self) -> None:
        pkg_root = Path(__file__).resolve().parent.parent
        withdrawn = _withdrawn_words()
        violations: list[str] = []
        # Audit our source and public metadata, not installed third-party code.
        files = [*pkg_root.joinpath("src").rglob("*.py")]
        files += list(pkg_root.glob("*.json")) + list(pkg_root.glob("*.md"))
        for path in files:
            text = path.read_text(encoding="utf-8")
            for word in withdrawn:
                if word.lower() in text.lower():
                    violations.append(f"{path.relative_to(pkg_root)}: contains '{word}'")
        assert not violations, "Withdrawn words found:\n" + "\n".join(violations)

    def test_no_withdrawn_words_in_tool_outputs(self, mcp: McpServer) -> None:
        """The offline fallback text and static tool metadata must not use withdrawn words."""
        withdrawn = _withdrawn_words()
        def fail_fetch(_url: str) -> tuple[int, str]:
            return 0, ""
        offline_mcp = McpServer(fetch_fn=fail_fetch)

        resp = _call(offline_mcp, "tools/call", {"name": "aics_get_onboarding_guide", "arguments": {}})
        text = resp["result"]["content"][0]["text"]
        for word in withdrawn:
            assert word.lower() not in text.lower(), f"offline onboarding output contains '{word}'"

        for tool in TOOLS:
            for word in withdrawn:
                assert word.lower() not in tool["description"].lower(), f"tool {tool['name']} description contains '{word}'"
                assert word.lower() not in tool["name"].lower(), f"tool name {tool['name']} contains '{word}'"
