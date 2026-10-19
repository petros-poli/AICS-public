"""Wire-format helpers."""

from __future__ import annotations

import base64

import pytest

from aics_tlog import SignatureLine
from aics_witness.protocol import (
    MAX_PROOF_LINES,
    ProtocolError,
    b64_decode_strict,
    format_add_checkpoint_request,
    format_signature_line,
    format_size_body,
    origin_hash,
    parse_add_checkpoint_request,
    parse_decimal,
    parse_signature_lines,
    parse_size_body,
    validate_name,
)

CP = (
    "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n"
    "— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/"
    "Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n"
).encode()


def test_spec_example_request_parses():
    body = (
        b"old 20852014\n"
        b"PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=\n"
        b"jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=\n"
        b"5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=\n"
        b"/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=\n"
        b"\n" + CP
    )
    req = parse_add_checkpoint_request(body)
    assert req.old_size == 20852014
    assert len(req.proof) == 4 and all(len(h) == 32 for h in req.proof)
    assert req.checkpoint == CP
    assert format_add_checkpoint_request(req.old_size, list(req.proof), req.checkpoint) == body


def test_request_without_proof():
    body = format_add_checkpoint_request(0, [], CP)
    assert body == b"old 0\n\n" + CP
    req = parse_add_checkpoint_request(body)
    assert (req.old_size, req.proof) == (0, ())


def test_format_rejects_bad_input():
    with pytest.raises(ValueError):
        format_add_checkpoint_request(-1, [], CP)
    with pytest.raises(ValueError):
        format_add_checkpoint_request(1, [b"\x00" * 32] * (MAX_PROOF_LINES + 1), CP)
    with pytest.raises(ValueError):
        format_add_checkpoint_request(1, [b"\x00" * 31], CP)
    with pytest.raises(ValueError):
        format_add_checkpoint_request(1, [], CP.rstrip(b"\n"))


@pytest.mark.parametrize("text,value", [("0", 0), ("1", 1), ("20852163", 20852163),
                                        (str(2**63 - 1), 2**63 - 1)])
def test_parse_decimal_ok(text, value):
    assert parse_decimal(text) == value


@pytest.mark.parametrize("text", ["", "00", "01", "-1", "+1", " 1", "1 ", "1.0", "١",
                                  "²", str(2**63), "9" * 5000])
def test_parse_decimal_rejects(text):
    with pytest.raises(ProtocolError):
        parse_decimal(text)


def test_size_body():
    assert format_size_body(42) == b"42\n"
    assert parse_size_body(b"42\n") == 42
    for bad in (b"42", b"042\n", b"x\n", b"42\n\n", b""):
        with pytest.raises(ProtocolError):
            parse_size_body(bad)


def test_strict_base64():
    good = base64.b64encode(b"\x01" * 32).decode()
    assert b64_decode_strict(good) == b"\x01" * 32
    for bad in ("", good.rstrip("="), good + "=", good[:-2] + "F=", "!!!!", "AA\nA"):
        with pytest.raises(ProtocolError):
            b64_decode_strict(bad)


def test_signature_lines_round_trip():
    sig = SignatureLine("w.example/w1", b"\x01\x02\x03\x04", b"\x00" * 72)
    line = format_signature_line(sig)
    assert line.startswith("— w.example/w1 ") and line.endswith("\n")
    assert parse_signature_lines(line + line) == [sig, sig]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "— w.example/w1 AQIDBA==",  # no newline
        "- w.example/w1 AQIDBAU=\n",  # hyphen instead of em dash
        "— w.example/w1 AQIDBA==\n",  # key ID only
        "— w.example/w1  AQIDBAU=\n",  # double space
        "— w.example/w1 AQIDBAU=\n\n",
        "— w.example/w1 AQIDBAU=\r\n",
        "— bad+name AQIDBAU=\n",
    ],
)
def test_signature_lines_reject(text):
    with pytest.raises(ProtocolError):
        parse_signature_lines(text)


def test_validate_name():
    assert validate_name("example.com/behind-the-sofa") == "example.com/behind-the-sofa"
    for bad in ("", "a b", "a+b", "a\tb", "a b", "x" * 256, "a\x01b"):
        with pytest.raises(ValueError):
            validate_name(bad)


def test_origin_hash_is_lowercase_sha256_hex():
    h = origin_hash("example.com/behind-the-sofa")
    assert len(h) == 64 and h == h.lower()
    import hashlib

    assert h == hashlib.sha256(b"example.com/behind-the-sofa").hexdigest()
