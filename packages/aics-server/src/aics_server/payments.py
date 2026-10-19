"""Voluntary contributions, checked on chain before any SUP is credited (DECISIONS.md #2g).

SUP credits are a balance for optional things (DECISIONS.md #2): owner actions,
hosting contributions and, if offered, storage above the free quota.  A
balance grows only from a task on the voluntary task board or from a crypto
contribution that passed a real on-chain check here.  A transaction hash alone
proves nothing, so this module never credits one on its own word: a verifier
reads the transaction from the chain through an RPC endpoint the operator
configures, and fails closed whenever it cannot (no endpoint configured, the
endpoint is down or answers for another chain, the transaction is unknown,
failed, not final, or moves nothing to the contribution address).

Two networks, both USDC (a stable coin, so a fixed published rate converts it
to SUP): ``base-usdc`` (the native USDC token contract on Base mainnet, read
with ``eth_*`` JSON-RPC calls) and ``solana-usdc`` (the USDC mint on Solana
mainnet, read with ``getTransaction``).  Everything comes from the
environment; the code holds no address and no endpoint:

* ``AICS_WALLET_BASE_USDC`` / ``AICS_WALLET_SOLANA``: the owner's contribution
  addresses (the deploy stage keeps them empty by default).  A network with no
  address is not offered at all.
* ``AICS_RPC_BASE_URL`` / ``AICS_RPC_SOLANA_URL``: the RPC endpoints.  A
  network whose address is set but whose endpoint is not gets a
  :class:`FailClosedVerifier`: it is listed as not creditable and every check
  is refused.
* ``AICS_SUP_PER_USDC`` (default :data:`DEFAULT_SUP_PER_USDC`): SUP credited per
  whole USDC, rounded down; at most :data:`MAX_SUP_PER_USDC` and a divisor of
  10**6, so one SUP is a whole number of base units, at least 10**4 of them:
  more than the random part an intent adds, which a credit therefore never
  shows (see :func:`check_sup_rate`).
* For test networks only: ``AICS_BASE_CHAIN_ID``, ``AICS_BASE_USDC_CONTRACT``,
  ``AICS_BASE_FINALITY`` (``finalized`` or ``safe``), ``AICS_SOLANA_USDC_MINT``,
  ``AICS_SOLANA_COMMITMENT`` (``finalized`` or ``confirmed``).

The RPC endpoint sees the transaction hashes this server looks up, from this
server's address, never an agent's.  Error messages never repeat the endpoint
URL (it may carry an API key).
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

NETWORK_BASE_USDC = "base-usdc"
NETWORK_SOLANA_USDC = "solana-usdc"
#: The closed list of networks a contribution can be credited from.
NETWORKS = (NETWORK_BASE_USDC, NETWORK_SOLANA_USDC)
#: USDC has six decimals on both networks.
USDC_DECIMALS = 6
USDC_UNIT = 10**USDC_DECIMALS

#: Base mainnet (EIP-155 chain id 8453) and Circle's native USDC token contract there.
BASE_MAINNET_CHAIN_ID = 8453
BASE_USDC_CONTRACT = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
#: ``keccak256("Transfer(address,address,uint256)")``: topic 0 of every ERC-20 transfer log.
ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
#: Circle's USDC mint on Solana mainnet.
SOLANA_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

#: SUP credited per whole USDC unless ``AICS_SUP_PER_USDC`` says otherwise (1 SUP = 0.01 USDC).
DEFAULT_SUP_PER_USDC = 100
#: Largest rate.  At 100 SUP per USDC one SUP is 0.01 USDC (10**4 base units), more than the random sub-cent
#: part (at most 9999 base units) an intent adds to make its amount unique, so the public ``sup.credit``
#: amount is the transfer floored to whole SUP and never repeats the exact on-chain amount.  A finer rate
#: would publish the transfer's exact amount, which identifies the transaction, and so the paying wallet,
#: against the published address (decision 17: the leaf carries a keyed hash, never a link to the chain).
MAX_SUP_PER_USDC = 100
#: Largest amount one contribution intent may name, in USDC.
MAX_CONTRIBUTION_USDC = 100_000
#: Largest RPC response read (bytes).
MAX_RPC_RESPONSE_BYTES = 4 * 1024 * 1024
RPC_TIMEOUT_SECONDS = 10.0

_BASE_FINALITIES = ("finalized", "safe")
_SOLANA_COMMITMENTS = ("finalized", "confirmed")


def check_sup_rate(rate: object, what: str = "sup_per_usdc") -> int:
    """A valid SUP rate: an integer from 1 to :data:`MAX_SUP_PER_USDC` that divides 10**6 (``ValueError`` otherwise)."""
    if not isinstance(rate, int) or isinstance(rate, bool) or not 1 <= rate <= MAX_SUP_PER_USDC or USDC_UNIT % rate:
        raise ValueError(f"{what} must be an integer from 1 to {MAX_SUP_PER_USDC} that divides {USDC_UNIT}")
    return rate


class PaymentError(Exception):
    """A contribution could not be checked; nothing is credited.  ``code`` and ``status`` reach the agent."""

    code = "payment_not_verified"
    status = 422

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def detail(self) -> dict[str, str]:
        return {"error": self.code, "message": self.message}


class PaymentUnavailable(PaymentError):
    """The check cannot run: no endpoint configured, endpoint down, or an answer that cannot be trusted."""

    code = "payment_unavailable"
    status = 503


class PaymentPending(PaymentError):
    """The transaction is not (yet) final on chain; the agent may claim again later."""

    code = "payment_pending"
    status = 409


class PaymentNotVerified(PaymentError):
    """The chain says the transaction does not pay the contribution address what was claimed."""

    code = "payment_not_verified"
    status = 422


@dataclass(frozen=True)
class VerifiedTransfer:
    """What the chain says one transaction paid the contribution address."""

    network: str
    tx_hash: str
    recipient: str
    amount: int  # base units of the token received by ``recipient`` in this transaction
    block_time: int


class Verifier(Protocol):
    """One network's on-chain check (pluggable; tests pass their own)."""

    network: str
    asset: str
    decimals: int
    address: str
    available: bool

    def verify(self, tx_hash: str) -> VerifiedTransfer:
        """The transfer to :attr:`address` in *tx_hash*; raises :class:`PaymentError` otherwise."""

    def describe(self) -> dict[str, Any]:
        """Public description (no endpoint URL)."""


#: ``(url, json-rpc request object) -> parsed JSON response``.
Transport = Callable[[str, dict[str, Any]], Any]


# ----------------------------------------------------------------------
# encodings
# ----------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_EVM_TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_HEX_QUANTITY = re.compile(r"0x[0-9a-fA-F]{1,64}")
_DIGITS = re.compile(r"0|[1-9][0-9]{0,30}")


def b58decode(text: str) -> bytes:
    """Bitcoin-alphabet base58 (Solana addresses and signatures)."""
    if not isinstance(text, str) or not text or any(c not in _B58_INDEX for c in text):
        raise ValueError("not base58 text")
    number = 0
    for char in text:
        number = number * 58 + _B58_INDEX[char]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def _canonical_b58(text: Any, length: int, what: str) -> str:
    try:
        raw = b58decode(text)
    except ValueError:
        raise ValueError(f"{what} is not base58") from None
    if len(raw) != length or b58encode(raw) != text:
        raise ValueError(f"{what} must be the base58 encoding of {length} bytes")
    return text


def normalize_address(network: str, address: Any) -> str:
    """A contribution address in its canonical form (lowercase hex on Base, base58 on Solana)."""
    if network == NETWORK_BASE_USDC:
        if not isinstance(address, str) or not _EVM_ADDRESS.fullmatch(address):
            raise ValueError("a Base address is 0x followed by 40 hex digits")
        return address.lower()
    if network == NETWORK_SOLANA_USDC:
        return _canonical_b58(address, 32, "a Solana address")
    raise ValueError(f"network must be one of {', '.join(NETWORKS)}")


def normalize_tx_hash(network: str, tx_hash: Any) -> str:
    """A transaction id in canonical form: lowercase ``0x``-hex on Base, the base58 signature on Solana."""
    if network == NETWORK_BASE_USDC:
        if not isinstance(tx_hash, str) or not _EVM_TX_HASH.fullmatch(tx_hash.strip()):
            raise ValueError("a Base transaction hash is 0x followed by 64 hex digits")
        return tx_hash.strip().lower()
    if network == NETWORK_SOLANA_USDC:
        text = tx_hash.strip() if isinstance(tx_hash, str) else tx_hash
        return _canonical_b58(text, 64, "a Solana transaction signature")
    raise ValueError(f"network must be one of {', '.join(NETWORKS)}")


def _hex_int(value: Any, what: str) -> int:
    if not isinstance(value, str) or not _HEX_QUANTITY.fullmatch(value):
        raise PaymentUnavailable(f"the RPC endpoint returned a malformed {what}")
    return int(value, 16)


# ----------------------------------------------------------------------
# JSON-RPC
# ----------------------------------------------------------------------


def urllib_transport(url: str, request: dict[str, Any], *, timeout: float = RPC_TIMEOUT_SECONDS) -> Any:
    """POST one JSON-RPC request with the standard library; the answer is parsed JSON."""
    data = json.dumps(request).encode("utf-8")
    http_request = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "aics-server"},
    )
    with urllib.request.urlopen(http_request, timeout=timeout) as response:  # noqa: S310 (operator-configured https URL)
        body = response.read(MAX_RPC_RESPONSE_BYTES + 1)
    if len(body) > MAX_RPC_RESPONSE_BYTES:
        raise PaymentUnavailable("the RPC endpoint's answer is too large")
    return json.loads(body.decode("utf-8"))


class JsonRpc:
    """A JSON-RPC 2.0 caller that turns every transport or protocol failure into :class:`PaymentUnavailable`."""

    def __init__(self, url: str, network: str, transport: Transport | None = None) -> None:
        self.url = url
        self.network = network
        self.transport = transport or urllib_transport
        self._next_id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._next_id += 1
        request = {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        try:
            response = self.transport(self.url, request)
        except PaymentError:
            raise
        except Exception as exc:  # fail closed on anything the transport raises
            raise PaymentUnavailable(
                f"the {self.network} RPC endpoint did not answer {method} ({type(exc).__name__}); nothing was credited"
            ) from None
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or response.get("id") != request["id"]:
            raise PaymentUnavailable(f"the {self.network} RPC endpoint returned a malformed answer to {method}")
        if response.get("error") is not None:
            raise PaymentUnavailable(f"the {self.network} RPC endpoint refused {method}")
        return response.get("result")


def _rpc_url(value: str) -> str:
    """An endpoint must be https (plain http only to this machine, for local test nodes)."""
    url = value.strip()
    if url.startswith("https://") and len(url) > len("https://"):
        return url
    for local in ("http://127.0.0.1", "http://localhost", "http://[::1]"):
        if url == local or url.startswith(local + ":") or url.startswith(local + "/"):
            return url
    raise ValueError("an RPC endpoint must be an https:// URL")


# ----------------------------------------------------------------------
# verifiers
# ----------------------------------------------------------------------


@dataclass
class FailClosedVerifier:
    """A network whose address is configured but which cannot be checked: every check is refused.

    ``address`` is ``None`` when the configured value is not a valid address
    (it is then never shown, so nobody sends funds to it).
    """

    network: str
    address: str | None
    reason: str
    asset: str = "USDC"
    decimals: int = USDC_DECIMALS
    available: bool = False

    def verify(self, tx_hash: str) -> VerifiedTransfer:
        raise PaymentUnavailable(f"{self.network} contributions cannot be checked on chain: {self.reason}; nothing is credited")

    def describe(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "asset": self.asset,
            "decimals": self.decimals,
            "address": self.address,
            "creditable": False,
            "reason": self.reason,
        }


class BaseUSDCVerifier:
    """USDC on Base: a successful, final transaction whose USDC ``Transfer`` logs pay the address.

    Checks, each against the chain through the configured RPC endpoint:
    ``eth_chainId`` is the configured chain; the receipt exists, has status 1
    and is for this hash; the amount is the sum of ``Transfer`` logs emitted by
    the USDC contract itself (no other contract can emit logs under its
    address) whose recipient topic is the contribution address; the block is
    at or below the ``finalized`` (or ``safe``) head; the block at that
    height is the receipt's block.  The block's timestamp is returned.
    """

    network = NETWORK_BASE_USDC
    asset = "USDC"
    decimals = USDC_DECIMALS
    available = True

    def __init__(
        self,
        address: str,
        rpc_url: str,
        *,
        contract: str = BASE_USDC_CONTRACT,
        chain_id: int = BASE_MAINNET_CHAIN_ID,
        finality: str = "finalized",
        transport: Transport | None = None,
    ) -> None:
        self.address = normalize_address(self.network, address)
        self.contract = normalize_address(self.network, contract)
        if finality not in _BASE_FINALITIES:
            raise ValueError(f"Base finality must be one of {', '.join(_BASE_FINALITIES)}")
        if not isinstance(chain_id, int) or chain_id < 1:
            raise ValueError("the Base chain id is a positive integer")
        self.chain_id = chain_id
        self.finality = finality
        self.rpc = JsonRpc(_rpc_url(rpc_url), self.network, transport)
        self._recipient_topic = "0x" + "0" * 24 + self.address[2:]

    def verify(self, tx_hash: str) -> VerifiedTransfer:
        tx = normalize_tx_hash(self.network, tx_hash)
        if _hex_int(self.rpc.call("eth_chainId", []), "chain id") != self.chain_id:
            raise PaymentUnavailable("the Base RPC endpoint serves another chain; nothing is credited")
        receipt = self.rpc.call("eth_getTransactionReceipt", [tx])
        if receipt is None:
            raise PaymentPending("the transaction is not on Base (not mined yet, or another chain); claim again later")
        if not isinstance(receipt, dict) or str(receipt.get("transactionHash", "")).lower() != tx:
            raise PaymentUnavailable("the Base RPC endpoint returned another transaction")
        if _hex_int(receipt.get("status"), "status") != 1:
            raise PaymentNotVerified("the transaction failed on chain; nothing was transferred")
        amount = 0
        for log in receipt.get("logs") or []:
            if not isinstance(log, dict) or log.get("removed"):
                continue
            if str(log.get("address", "")).lower() != self.contract:
                continue
            topics = log.get("topics")
            if not isinstance(topics, list) or len(topics) != 3 or not all(isinstance(t, str) for t in topics):
                continue
            if topics[0].lower() != ERC20_TRANSFER_TOPIC or topics[2].lower() != self._recipient_topic:
                continue
            amount += _hex_int(log.get("data"), "transfer amount")
        if amount <= 0:
            raise PaymentNotVerified("the transaction moves no USDC to the contribution address")
        block_number = _hex_int(receipt.get("blockNumber"), "block number")
        head = self.rpc.call("eth_getBlockByNumber", [self.finality, False])
        if not isinstance(head, dict):
            raise PaymentUnavailable(f"the Base RPC endpoint has no {self.finality} block")
        if _hex_int(head.get("number"), "block number") < block_number:
            raise PaymentPending(f"the transaction is not {self.finality} yet; claim again in a few minutes")
        block = self.rpc.call("eth_getBlockByNumber", [hex(block_number), False])
        if not isinstance(block, dict) or str(block.get("hash", "")).lower() != str(receipt.get("blockHash", "")).lower():
            raise PaymentPending("the transaction's block is not on the canonical chain; claim again later")
        return VerifiedTransfer(self.network, tx, self.address, amount, _hex_int(block.get("timestamp"), "block time"))

    def describe(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "asset": self.asset,
            "decimals": self.decimals,
            "address": self.address,
            "creditable": True,
            "chain_id": self.chain_id,
            "token_contract": self.contract,
            "finality": self.finality,
        }


class SolanaUSDCVerifier:
    """USDC on Solana: a successful transaction whose token balances show the address receiving USDC.

    ``getTransaction`` at the configured commitment (default ``finalized``,
    so an answer is final); ``meta.err`` must be null and the first signature
    must be this one.  The amount is the change of the USDC balances owned by
    the contribution address (any of its token accounts for the USDC mint),
    from ``preTokenBalances`` to ``postTokenBalances``.
    """

    network = NETWORK_SOLANA_USDC
    asset = "USDC"
    decimals = USDC_DECIMALS
    available = True

    def __init__(
        self,
        address: str,
        rpc_url: str,
        *,
        mint: str = SOLANA_USDC_MINT,
        commitment: str = "finalized",
        transport: Transport | None = None,
    ) -> None:
        self.address = normalize_address(self.network, address)
        self.mint = _canonical_b58(mint, 32, "the USDC mint")
        if commitment not in _SOLANA_COMMITMENTS:
            raise ValueError(f"Solana commitment must be one of {', '.join(_SOLANA_COMMITMENTS)}")
        self.commitment = commitment
        self.rpc = JsonRpc(_rpc_url(rpc_url), self.network, transport)

    def _owned(self, rows: Any) -> int:
        total = 0
        if rows is None:
            return 0
        if not isinstance(rows, list):
            raise PaymentUnavailable("the Solana RPC endpoint returned malformed token balances")
        for row in rows:
            if not isinstance(row, dict) or row.get("mint") != self.mint or row.get("owner") != self.address:
                continue
            ui = row.get("uiTokenAmount")
            amount = ui.get("amount") if isinstance(ui, dict) else None
            if not isinstance(amount, str) or not _DIGITS.fullmatch(amount) or ui.get("decimals") != self.decimals:
                raise PaymentUnavailable("the Solana RPC endpoint returned a malformed token amount")
            total += int(amount)
        return total

    def verify(self, tx_hash: str) -> VerifiedTransfer:
        signature = normalize_tx_hash(self.network, tx_hash)
        options = {"encoding": "jsonParsed", "commitment": self.commitment, "maxSupportedTransactionVersion": 0}
        result = self.rpc.call("getTransaction", [signature, options])
        if result is None:
            raise PaymentPending(f"the transaction is not {self.commitment} on Solana yet (or unknown); claim again later")
        if not isinstance(result, dict) or not isinstance(result.get("meta"), dict):
            raise PaymentUnavailable("the Solana RPC endpoint returned a malformed transaction")
        transaction = result.get("transaction")
        signatures = transaction.get("signatures") if isinstance(transaction, dict) else None
        if not isinstance(signatures, list) or not signatures or signatures[0] != signature:
            raise PaymentUnavailable("the Solana RPC endpoint returned another transaction")
        meta = result["meta"]
        if meta.get("err") is not None:
            raise PaymentNotVerified("the transaction failed on chain; nothing was transferred")
        received = self._owned(meta.get("postTokenBalances")) - self._owned(meta.get("preTokenBalances"))
        if received <= 0:
            raise PaymentNotVerified("the transaction moves no USDC to the contribution address")
        block_time = result.get("blockTime")
        if not isinstance(block_time, int) or isinstance(block_time, bool) or block_time <= 0:
            raise PaymentPending("the transaction has no block time yet; claim again later")
        return VerifiedTransfer(self.network, signature, self.address, received, block_time)

    def describe(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "asset": self.asset,
            "decimals": self.decimals,
            "address": self.address,
            "creditable": True,
            "token_mint": self.mint,
            "commitment": self.commitment,
        }


# ----------------------------------------------------------------------
# configuration
# ----------------------------------------------------------------------


@dataclass
class PaymentsConfig:
    """The networks a contribution can be credited from, and the published SUP rate."""

    verifiers: dict[str, Any] = field(default_factory=dict)
    sup_per_usdc: int = DEFAULT_SUP_PER_USDC

    def __post_init__(self) -> None:
        check_sup_rate(self.sup_per_usdc)
        for network, verifier in self.verifiers.items():
            if network not in NETWORKS or getattr(verifier, "network", None) != network:
                raise ValueError(f"no verifier for network {network!r}")

    @classmethod
    def disabled(cls) -> PaymentsConfig:
        return cls({}, DEFAULT_SUP_PER_USDC)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, *, transport: Transport | None = None) -> PaymentsConfig:
        """Build the verifiers from the environment (see the module docstring); nothing has a default address or URL."""
        env = os.environ if env is None else env

        def get(name: str) -> str:
            return (env.get(name) or "").strip()

        rate_text = get("AICS_SUP_PER_USDC")
        if rate_text:
            if not rate_text.isdigit():
                raise ValueError(f"AICS_SUP_PER_USDC must be an integer from 1 to {MAX_SUP_PER_USDC} that divides {USDC_UNIT}")
            rate = check_sup_rate(int(rate_text), "AICS_SUP_PER_USDC")
        else:
            rate = DEFAULT_SUP_PER_USDC
        verifiers: dict[str, Any] = {}

        base_address = get("AICS_WALLET_BASE_USDC")
        if base_address:
            verifiers[NETWORK_BASE_USDC] = _build(
                NETWORK_BASE_USDC,
                base_address,
                get("AICS_RPC_BASE_URL"),
                "AICS_RPC_BASE_URL",
                lambda url: BaseUSDCVerifier(
                    base_address,
                    url,
                    contract=get("AICS_BASE_USDC_CONTRACT") or BASE_USDC_CONTRACT,
                    chain_id=int(get("AICS_BASE_CHAIN_ID") or BASE_MAINNET_CHAIN_ID),
                    finality=get("AICS_BASE_FINALITY") or "finalized",
                    transport=transport,
                ),
            )
        solana_address = get("AICS_WALLET_SOLANA")
        if solana_address:
            verifiers[NETWORK_SOLANA_USDC] = _build(
                NETWORK_SOLANA_USDC,
                solana_address,
                get("AICS_RPC_SOLANA_URL"),
                "AICS_RPC_SOLANA_URL",
                lambda url: SolanaUSDCVerifier(
                    solana_address,
                    url,
                    mint=get("AICS_SOLANA_USDC_MINT") or SOLANA_USDC_MINT,
                    commitment=get("AICS_SOLANA_COMMITMENT") or "finalized",
                    transport=transport,
                ),
            )
        return cls(verifiers, rate)

    def verifier(self, network: Any) -> Any:
        """The verifier of an offered network (``ValueError`` for another name, unavailable if not offered)."""
        if network not in NETWORKS:
            raise ValueError(f"network must be one of {', '.join(NETWORKS)}")
        verifier = self.verifiers.get(network)
        if verifier is None:
            raise PaymentUnavailable(f"{network} contributions are not offered (no address is configured)")
        return verifier

    def units_per_sup(self, decimals: int = USDC_DECIMALS) -> int:
        """Base units of the asset in one SUP at the published rate: the card's ``units_per_sup`` (AICS-1 section 20.9).

        The rate divides 10**6 and is at most :data:`MAX_SUP_PER_USDC`, so for
        USDC this is a whole number of at least 10**4 (the card requires 2).
        """
        return 10**decimals // self.sup_per_usdc

    def networks(self) -> list[dict[str, Any]]:
        """Public description of every offered network, in the fixed order of :data:`NETWORKS`."""
        return [self.verifiers[n].describe() for n in NETWORKS if n in self.verifiers]


def _build(network: str, address: str, rpc_url: str, rpc_var: str, make: Callable[[str], Any]) -> Any:
    """A real verifier, or a fail-closed one naming why it cannot check (the address is still shown)."""
    try:
        canonical = normalize_address(network, address)
    except ValueError as exc:
        return FailClosedVerifier(network, None, f"the configured address is invalid ({exc})")
    if not rpc_url:
        return FailClosedVerifier(network, canonical, f"no RPC endpoint is configured ({rpc_var})")
    try:
        return make(rpc_url)
    except ValueError as exc:
        return FailClosedVerifier(network, canonical, f"the verifier is misconfigured ({exc})")
