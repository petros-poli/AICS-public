"""RFC 8785 canonicalisation: known vectors + hypothesis idempotence fuzz."""

from __future__ import annotations

import json

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings

from aics_identity.canonical import CanonicalizationError, canonical_text, canonicalize

EURO = "€"
EMOJI = "\U0001f600"
REPLACEMENT = "�"


def test_rfc8785_section_example():
    """The parsed-object example from RFC 8785 section 3.2.2, byte for byte."""
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": EURO + "$" + "\u000f" + "\n" + "A'B\"\\\\\"/",
        "literals": [None, True, False],
    }
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"' + EURO + '$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert canonicalize(value).decode("utf-8") == expected


def test_keys_sorted_by_utf16_code_units():
    # UTF-16 code units: "a"=0061 < D83D (first surrogate of U+1F600) < FFFD.
    value = {REPLACEMENT: 1, EMOJI: 2, "a": 3}
    out = canonical_text(value)
    assert out == '{"a":3,"' + EMOJI + '":2,"' + REPLACEMENT + '":1}'


def test_supplementary_plane_sorts_before_bmp_high_characters():
    # The classic JCS gotcha: U+10000 (surrogates D800 DC00) sorts BEFORE
    # U+FFFD (single unit FFFD) in UTF-16 code-unit order.
    value = {"�": 1, "\U00010000": 2}
    assert canonical_text(value) == '{"\U00010000":2,"�":1}'


def test_whitespace_and_order_normalised():
    assert canonical_text({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert canonical_text([]) == "[]"
    assert canonical_text({}) == "{}"


def test_string_escaping_minimal():
    value = {"k": "a\u0002bc\"d\\e/fgh\ni\tj"}
    assert canonical_text(value) == '{"k":"a\\u0002bc\\"d\\\\e/fgh\\ni\\tj"}'


def test_unicode_passes_through():
    assert canonical_text({"key": "v"}) == '{"key":"v"}'


def test_rejects_nan_and_infinity():
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": float("inf")})


def test_rejects_out_of_range_integers():
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": 2 ** 60})


def test_canonical_text_matches_canonicalize():
    assert canonical_text({"a": [1, 2, 3]}) == canonicalize({"a": [1, 2, 3]}).decode()


# ----------------------------------------------------------------------
# hypothesis fuzz: idempotence of canonicalisation
# ----------------------------------------------------------------------

json_values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2 ** 53 - 1), max_value=2 ** 53 - 1),  # JSON safe-integer domain
        st.floats(allow_nan=False, allow_infinity=False, width=64),
        st.text(max_size=24),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(st.text(max_size=8), children, max_size=6),
    ),
    max_leaves=12,
)


@settings(max_examples=500, deadline=None)
@given(json_values)
def test_canonicalisation_is_idempotent(value):
    once = canonicalize(value)
    # JCS output is lossless for JSON values, so re-parsing and
    # canonicalising again must give the exact same bytes.  Ints are
    # parsed as floats because JCS may render a large double as an
    # integer-digit string outside the JSON safe-integer domain; every
    # int we generate (|n| <= 2**53) is exact as a float.
    twice = canonicalize(json.loads(once, parse_int=float))
    assert once == twice


@settings(max_examples=200, deadline=None)
@given(json_values)
def test_canonical_output_round_trips_through_json(value):
    raw = canonicalize(value)
    raw.decode("utf-8")  # must be valid UTF-8
    # ints and floats both denote IEEE-754 numbers in JSON; parse both
    # sides as floats for comparison (all our ints fit double exactly).
    assert json.loads(raw, parse_int=float) == json.loads(json.dumps(value), parse_int=float)
