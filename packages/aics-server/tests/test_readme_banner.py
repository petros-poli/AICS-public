"""The README of the public repository against the texts the server serves (readiness audit of 2026-10-20).

The audit found the README's banner block claiming to be "served identically" while it said "Nothing is ever
deleted" (the served banner says ciphertext can expire after at least 90 days), an ``aics verify message <id>`` that
is not the CLI's syntax, and "openssl 1.1.1 or later" where every other text says 3.0.  The README is the public
repository's, refreshed byte for byte from this checkout, so these checks run here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aics_server.banner import BANNER_TEXT, MANUAL_VERIFY_LINE, get_banner
from aics_server.discovery import PUBLIC_REPOSITORY, SEAL_INSTALL

README = Path(__file__).resolve().parents[3] / "README.md"
BANNER_MD = README.parent / "docs" / "BANNER.md"


def _readme() -> str:
    if not README.exists():
        pytest.skip("README.md is not next to this package")
    return README.read_text(encoding="utf-8")


def _banner_section(text: str) -> str:
    return text.split("\n## The banner\n", 1)[1].split("\n## ", 1)[0]


def _outside_the_block(text: str) -> str:
    return " ".join(re.sub(r"\n```text\n.*?\n```\n", "\n", text, flags=re.S).split())


def test_the_readme_banner_block_is_the_served_banner_byte_for_byte():
    """The block under "The banner" is exactly what the gate, /llms.txt and /?format=json serve: docs/BANNER.md's block
    with its documented "Verify by hand" line in place of the three ``aics verify`` lines.  When every served copy
    switches to the client variant (the notes at the end of docs/BANNER.md), the README switches with them."""
    section = _banner_section(_readme())
    blocks = re.findall(r"\n```text\n(.*?)\n```\n", section, re.S)
    assert len(blocks) == 1, "the banner section holds one text block"
    assert blocks[0] + "\n" == get_banner()
    flat = " ".join(section.split())
    assert "served identically" in flat and "the banner as served now, byte for byte" in flat
    # docs/BANNER.md's block is the served banner's source; the README says where the two differ.
    assert MANUAL_VERIFY_LINE in get_banner() and "three `aics verify` lines" in flat
    if BANNER_MD.exists():
        block = re.search(r"\n```\n(.*?)\n```\n", BANNER_MD.read_text(encoding="utf-8"), re.S).group(1) + "\n"
        assert block == BANNER_TEXT and blocks[0] + "\n" == get_banner()


def test_the_readme_gives_the_cli_syntax_and_the_distribution_name():
    """``aics verify message`` takes a wire bundle, never an id (aics-cli: "verify message needs --bundle FILE"), and
    the PyPI project named ``aics`` is someone else's."""
    text = _readme()
    outside = _outside_the_block(text)
    assert "`aics verify message --bundle F`" in outside
    assert not re.search(r"aics verify message(?! --bundle)", outside)
    assert "The PyPI project named just `aics` is not ours; install `aics-cli`." in " ".join(text.split())
    assert PUBLIC_REPOSITORY in text


def test_the_readme_names_openssl_3_not_libressl_and_how_to_seal():
    """OpenSSL 3.0 or later where the README said 1.1.1, LibreSSL named as what a stock macOS runs, and the sealing
    install line that /llms.txt gives (the words around them are the README's own)."""
    text = _readme()
    flat = " ".join(text.split())
    assert "OpenSSL 3.0 or later" in flat and "LibreSSL" in flat and not re.search(r"1\.1\.1 or\s+later", text)
    assert f"\n    {SEAL_INSTALL}\n" in text
