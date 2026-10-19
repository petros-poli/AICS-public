"""Configuration: log vkeys, per-log options, and Ed25519 key checks."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import EMPTY_HASH, VKey, cosignature_vkey, format_vkey, key_hash, vkey_from_ed25519
from aics_witness.config import ConfigError, LogConfig, load_config, new_config, parse_log_vkey, write_config
from aics_witness.protocol import ed25519_public_key_problem

from conftest import InProcessLog

# The eight small-order points of edwards25519 (RFC 8032 encodings).
SMALL_ORDER = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]
# Encodings whose y-coordinate (low 255 bits) is not below p = 2^255 - 19.
NON_CANONICAL = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p + 1
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]


@pytest.mark.parametrize("hex_key", SMALL_ORDER)
def test_small_order_keys_are_flagged(hex_key):
    assert "small-order" in ed25519_public_key_problem(bytes.fromhex(hex_key))


@pytest.mark.parametrize("hex_key", NON_CANONICAL)
def test_non_canonical_keys_are_flagged(hex_key):
    assert "canonical" in ed25519_public_key_problem(bytes.fromhex(hex_key))


def test_negative_zero_encodings_are_flagged():
    for y in ("01" + "00" * 31, "ec" + "ff" * 30 + "7f"):
        key = bytearray(bytes.fromhex(y))
        key[31] |= 0x80
        assert ed25519_public_key_problem(bytes(key)) is not None


def test_ordinary_keys_pass():
    for _ in range(50):
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        assert ed25519_public_key_problem(pub) is None
    assert ed25519_public_key_problem(b"\x01" * 31) is not None  # wrong length


def _vkey_text(name: str, key_type: int, key: bytes) -> str:
    return f"{name}+{key_hash(name, key_type, key).hex()}+{base64.b64encode(bytes([key_type]) + key).decode()}"


@pytest.mark.parametrize("hex_key", SMALL_ORDER[:3] + NON_CANONICAL[:1])
def test_weak_log_vkeys_are_refused(hex_key):
    key = bytes.fromhex(hex_key)
    with pytest.raises(ConfigError, match="small-order|canonical"):
        parse_log_vkey(_vkey_text("weak.example/log", 0x01, key))
    weak = VKey("weak.example/log", key_hash("weak.example/log", 0x04, key), 0x04, key)
    with pytest.raises(ConfigError, match="small-order|canonical"):
        LogConfig("weak.example/log", (weak,))


def test_identity_key_cannot_be_added_to_a_config_file(tmp_path):
    cfg = tmp_path / "w.json"
    doc = new_config("witness.example.test/c")
    doc["logs"] = [{"origin": "weak.example/log",
                    "vkeys": [_vkey_text("weak.example/log", 0x01, bytes([1]) + bytes(31))]}]
    write_config(cfg, doc)
    with pytest.raises(ConfigError, match="small-order"):
        load_config(cfg)


def test_per_log_options_round_trip(tmp_path):
    log = InProcessLog()
    log.append(9)
    root = log.tree.root(5)
    cfg = tmp_path / "w.json"
    doc = new_config("witness.example.test/c")
    doc["logs"] = [{"origin": log.origin, "vkeys": [format_vkey(log.vkey)],
                    "extension_lines": True,
                    "initial": {"size": 5, "root": base64.b64encode(root).decode()}}]
    write_config(cfg, doc)
    [lc] = load_config(cfg).logs
    assert lc.extension_lines is True and lc.initial == (5, root)
    assert lc.initial_document() == {"size": 5, "root": base64.b64encode(root).decode()}
    doc["logs"][0].pop("extension_lines")
    doc["logs"][0].pop("initial")
    write_config(cfg, doc)
    [lc] = load_config(cfg).logs
    assert lc.extension_lines is False and lc.initial is None  # the defaults


@pytest.mark.parametrize(
    "option",
    [
        {"extension_lines": "yes"},
        {"initial": {"size": 0, "root": base64.b64encode(EMPTY_HASH).decode()}},
        {"initial": {"size": 3}},
        {"initial": {"size": 3, "root": "not base64!"}},
        {"initial": {"size": 3, "root": base64.b64encode(b"\x01" * 31).decode()}},
        {"initial": {"size": True, "root": base64.b64encode(b"\x01" * 32).decode()}},
        {"initial": {"size": 3, "root": base64.b64encode(b"\x01" * 32).decode(), "x": 1}},
        {"initail": {"size": 3}},  # typo: unknown field
    ],
)
def test_bad_per_log_options_are_refused(tmp_path, option):
    log = InProcessLog()
    cfg = tmp_path / "w.json"
    doc = new_config("witness.example.test/c")
    doc["logs"] = [{"origin": log.origin, "vkeys": [format_vkey(log.vkey)], **option}]
    cfg.write_text(json.dumps(doc))
    with pytest.raises(ConfigError):
        load_config(cfg)


def test_mixed_key_types_in_one_log():
    origin = "log.example.test/mixed"
    note_key = vkey_from_ed25519(origin, Ed25519PrivateKey.generate().public_key())
    cos_key = cosignature_vkey(origin, Ed25519PrivateKey.generate().public_key())
    lc = LogConfig(origin, (note_key, cos_key))
    assert [k.key_type for k in lc.vkeys] == [0x01, 0x04]
    with pytest.raises(ConfigError, match="listed twice"):
        LogConfig(origin, (note_key, note_key))
