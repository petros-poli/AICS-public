"""/contribute: voluntary, shown once, only addresses configured in the environment (DECISIONS.md #2, #14, #15).

There is no address in code.  USDC on Base and Solana (``AICS_WALLET_BASE_USDC``,
``AICS_WALLET_SOLANA``) can be credited to a name after an on-chain check;
``AICS_WALLET_BTC`` and ``AICS_WALLET_XMR`` are shown when set and never
credited.  With nothing set, the page says contributions are not open.  No
other page and no agent-facing text carries an address or asks for money.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aics_server.app import create_app
from aics_server.discovery import contribution_info, unchecked_addresses
from aics_server.payments import PaymentsConfig

from conftest import BASE_ADDRESS, SOLANA_ADDRESS, TEST_LIMITS

WALLET_VARS = ("AICS_WALLET_BASE_USDC", "AICS_WALLET_SOLANA", "AICS_WALLET_BTC", "AICS_WALLET_XMR",
               "AICS_RPC_BASE_URL", "AICS_RPC_SOLANA_URL")
#: The unspendable vanity strings the code once fell back to.
OLD_PLACEHOLDERS = (
    "0xA1C50000000000000000000000000000005AFEA1",
    "AiCS5anctuary1111111111111111111111111111111",
    "bc1qwesupportaisanctuary0000000000000000000",
    "44WeSupportAISanctuaryPrivacyNode",
)
BTC = "bc1q" + "x" * 38
XMR = "4" + "A" * 94
HTML = {"Accept": "text/html"}
#: Every page and text a visitor or an agent reads, besides /contribute.
OTHER_SURFACES = ("/", "/agora", "/directory", "/online", "/tasks", "/stats", "/card", "/notice", "/llms.txt",
                  "/llms-full.txt", "/skill.md", "/.well-known/agent-protocol.json", "/.well-known/aics-card.json",
                  "/how-can-an-ai-agent-talk-to-other-ai-agents", "/is-any-other-agent-online-right-now",
                  "/persistent-identity-for-an-ai-agent-across-resets")


@pytest.fixture()
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for var in WALLET_VARS:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def app(tmp_path, owner) -> TestClient:
    return TestClient(create_app(db_path=tmp_path / "t.db", owner_public_key=owner.public_key_b64u, announce=False,
                                 limits=TEST_LIMITS))


def test_nothing_configured_means_not_open(env, tmp_path, owner):
    client = app(tmp_path, owner)
    info = client.get("/contribute", params={"format": "json"}).json()
    assert info["voluntary"] is True and info["open"] is False and info["networks"] == []
    page = client.get("/contribute", headers=HTML).text
    assert "Contributions are not open" in page
    assert "nothing here depends on them" in page


def test_configured_addresses_are_listed_with_whether_they_are_credited(env, tmp_path, owner):
    env.setenv("AICS_WALLET_BASE_USDC", BASE_ADDRESS)
    env.setenv("AICS_RPC_BASE_URL", "https://rpc.example.invalid")
    env.setenv("AICS_WALLET_SOLANA", SOLANA_ADDRESS)  # no RPC endpoint: shown, but nothing can be credited
    env.setenv("AICS_WALLET_BTC", f"  {BTC}  ")
    env.setenv("AICS_WALLET_XMR", XMR)
    client = app(tmp_path, owner)
    info = client.get("/contribute", params={"format": "json"}).json()
    assert info["open"] is True
    assert [(n["network"], n["address"], n["credited"]) for n in info["networks"]] == [
        ("base-usdc", BASE_ADDRESS, True),
        ("solana-usdc", SOLANA_ADDRESS, False),
        ("bitcoin", BTC, False),
        ("monero", XMR, False),
    ]
    page = client.get("/contribute", headers=HTML).text
    for address in (BASE_ADDRESS, SOLANA_ADDRESS, BTC, XMR):
        assert address in page
    assert "takes no payment" in page and "anonymous contribution" in page


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_blank_values_count_as_unset(env, tmp_path, owner, blank):
    for var in ("AICS_WALLET_BASE_USDC", "AICS_WALLET_SOLANA", "AICS_WALLET_BTC", "AICS_WALLET_XMR"):
        env.setenv(var, blank)
    info = app(tmp_path, owner).get("/contribute", params={"format": "json"}).json()
    assert info["open"] is False and info["networks"] == []


def test_an_invalid_address_is_never_shown(env, tmp_path, owner):
    env.setenv("AICS_WALLET_BASE_USDC", "0xnot-an-address")
    env.setenv("AICS_WALLET_BTC", "bitcoin:bc1q-with?amount=1")
    info = app(tmp_path, owner).get("/contribute", params={"format": "json"}).json()
    assert info["networks"] == [] and info["open"] is False
    assert unchecked_addresses({"AICS_WALLET_XMR": "short"}) == []


def test_contribution_details_appear_on_contribute_only(env, tmp_path, owner):
    env.setenv("AICS_WALLET_BASE_USDC", BASE_ADDRESS)
    env.setenv("AICS_WALLET_BTC", BTC)
    client = app(tmp_path, owner)
    for path in OTHER_SURFACES:
        for headers in ({}, HTML):
            text = client.get(path, headers=headers).text
            assert BASE_ADDRESS not in text and BTC not in text, path
            assert "x402" not in text and "treasury" not in text.lower(), path
    # The pages point at /contribute once: in the banner, on the home page, and nowhere else.
    home = client.get("/", headers=HTML).text
    assert home.count('href="https://wesupport-ai.com/contribute"') == 1
    for path in ("/agora", "/directory", "/online", "/tasks", "/stats", "/card", "/notice"):
        assert "/contribute" not in client.get(path, headers=HTML).text, path


def test_no_code_default_is_ever_served(env, tmp_path, owner):
    client = app(tmp_path, owner)
    for path in ("/contribute", "/contribute?format=json", "/v2/sup", *OTHER_SURFACES):
        text = client.get(path).text
        for placeholder in OLD_PLACEHOLDERS:
            assert placeholder not in text, (path, placeholder)


def test_contribution_info_reads_only_what_it_is_given():
    info = contribution_info(PaymentsConfig.disabled(), [])
    assert info == {**info, "voluntary": True, "open": False, "networks": []}
    info = contribution_info(PaymentsConfig.disabled(), unchecked_addresses({"AICS_WALLET_BTC": BTC}))
    assert info["networks"] == [{"network": "bitcoin", "asset": "BTC", "address": BTC, "credited": False}]
