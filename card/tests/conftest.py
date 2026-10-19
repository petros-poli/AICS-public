"""Fixtures shared by the card tests."""

from __future__ import annotations

from typing import Any

import pytest

import validate_card as vc
from helpers import PATTERN_DEFINITIONS, REPO, fill_values, load_template


@pytest.fixture
def card() -> dict[str, Any]:
    """A fresh copy of card-content.json."""
    return load_template()


@pytest.fixture
def filled() -> dict[str, Any]:
    """The template with every placeholder filled: test values, the repository's document hashes and the test
    pattern definitions."""
    return vc.fill(load_template(), fill_values(), REPO, PATTERN_DEFINITIONS)
