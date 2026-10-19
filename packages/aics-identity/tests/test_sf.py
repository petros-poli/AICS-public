"""Structured fields subset: correctness against RFC 8941 examples and http-sfv."""

from __future__ import annotations

import http_sfv
import pytest

from aics_identity import sf


def test_parse_dictionary_inner_list_and_params():
    parsed = sf.parse_dictionary(
        'sig1=("@method" "@path");created=1618884473;keyid="test-key"'
    )
    assert list(parsed) == ["sig1"]
    inner = parsed["sig1"]
    assert [m.value for m in inner] == ["@method", "@path"]
    params = sf.params_to_dict(inner.params)
    assert params == {"created": 1618884473, "keyid": "test-key"}


def test_parse_dictionary_byte_sequence():
    parsed = sf.parse_dictionary("sig1=:AQIDBA==:")
    assert bytes(parsed["sig1"].value) == b"\x01\x02\x03\x04"


def test_parse_dictionary_multiple_keys_and_types():
    parsed = sf.parse_dictionary('a=1, b=:aGVsbG8=:, c="x y", d=?0, e=token')
    assert sf.params_to_dict({}).keys() == set()
    assert parsed["a"].value == 1
    assert bytes(parsed["b"].value) == b"hello"
    assert parsed["c"].value == "x y"
    assert parsed["d"].value is False
    assert parsed["e"].value == "token"


def test_parse_errors():
    with pytest.raises(sf.ParseError):
        sf.parse_dictionary("!!!")
    with pytest.raises(sf.ParseError):
        sf.parse_dictionary('sig1=("unterminated)')
    with pytest.raises(sf.ParseError):
        sf.parse_dictionary(123)  # type: ignore[arg-type]


def test_inner_list_serialization_matches_rfc9421_examples():
    out = sf.inner_list_serialization(
        ["date", "@method", "@path", "@authority", "content-type", "content-length"],
        [("created", 1618884473), ("keyid", "test-key-ed25519")],
    )
    assert out == (
        '("date" "@method" "@path" "@authority" "content-type" "content-length")'
        ';created=1618884473;keyid="test-key-ed25519"'
    )


def test_inner_list_serialization_full_params_order():
    out = sf.inner_list_serialization(
        ["@method"],
        [("created", 1), ("expires", 2), ("nonce", "n1"), ("alg", "ed25519"),
         ("keyid", "k"), ("tag", "t")],
    )
    assert out == '("@method");created=1;expires=2;nonce="n1";alg="ed25519";keyid="k";tag="t"'


def test_params_order_is_preserved():
    out = sf.inner_list_serialization(["a"], [("keyid", "k"), ("created", 5)])
    assert out == '("a");keyid="k";created=5'


def test_cross_check_with_http_sfv_library():
    """Our serializer output must equal the http-sfv library's serialization."""
    import http_sfv

    inner = http_sfv.InnerList()
    for c in ["@method", "@authority", "@path"]:
        inner.append(http_sfv.Item(c))
    inner.params["created"] = 1618884473
    inner.params["nonce"] = "abc"
    inner.params["alg"] = "ed25519"  # RFC 9421 carries alg as an SF string
    inner.params["keyid"] = "k1"
    ours = sf.inner_list_serialization(
        ["@method", "@authority", "@path"],
        [("created", 1618884473), ("nonce", "abc"), ("alg", "ed25519"), ("keyid", "k1")],
    )
    assert ours == str(inner)


def test_cross_check_parse_with_http_sfv():
    """http-sfv must be able to parse what we serialize."""
    ours = sf.inner_list_serialization(
        ["@target-uri", "content-digest"],
        [("created", 1), ("expires", 2), ("nonce", "n"), ("alg", "ed25519"),
         ("keyid", "k"), ("tag", "agent")],
    )
    lst = http_sfv.List()
    lst.parse(ours.encode("ascii"))
    assert [m.value for m in lst[0]] == ["@target-uri", "content-digest"]
    assert dict(lst[0].params)["created"] == 1
    assert str(lst) == ours


def test_byte_sequence_format():
    assert sf.byte_sequence(b"") == "::"
    assert sf.byte_sequence(b"\xc2\xab") == ":wqs=:"


def test_dictionary_serialization_for_content_digest():
    out = sf.dictionary_serialization([("sha-256", b"\x00" * 32)])
    assert out == "sha-256=:" + "A" * 43 + "=:"


def test_params_to_dict_coerces_tokens():
    d = http_sfv.Dictionary()
    d.parse(b'a=("x";alg=ed25519)')
    item_params = sf.params_to_dict(d["a"][0].params)
    assert item_params == {"alg": "ed25519"}
    assert type(item_params["alg"]) is str
