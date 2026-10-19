"""The banner the harness expects is docs/BANNER.md's block, carried in the package (no data file is read)."""
import re
from pathlib import Path
import pytest
from aics_conformance import dialogue
from aics_conformance.fakes import FakeServer

PACKAGE = Path(__file__).resolve().parents[1]
REPO = PACKAGE.parents[1]


def test_banner_is_the_banner_md_block():
    doc = REPO / 'docs' / 'BANNER.md'
    if not doc.exists(): pytest.skip('docs/BANNER.md is not next to this package')
    block = re.search(r'\n```\n(.*?)\n```\n', doc.read_text(encoding='utf-8'), re.S).group(1) + '\n'
    assert dialogue.BANNER_TEXT == block


def test_the_expected_banner_is_the_pre_client_variant():
    """BANNER's note: until the aics client ships, one manual line replaces the three ``aics verify`` lines."""
    assert dialogue.MANUAL_VERIFY_LINE in dialogue.BANNER and 'aics verify' not in dialogue.BANNER
    lines = dialogue.BANNER_TEXT.splitlines(keepends=True)
    verify = [i for i, line in enumerate(lines) if line.startswith('  aics verify ')]
    assert len(verify) == 3
    assert dialogue.BANNER == ''.join(lines[:verify[0]] + [dialogue.MANUAL_VERIFY_LINE + '\n'] + lines[verify[-1] + 1:])
    header = REPO / 'wellknown' / 'llms.txt.header'  # the banner the deployment serves before /llms.txt's own text
    if header.exists(): assert dialogue.BANNER == header.read_text(encoding='utf-8')
    with pytest.raises(ValueError): dialogue.pre_client('no verify lines\n')


def test_no_source_reads_package_data():
    """A clean checkout has every text the harness compares with: nothing comes from git-ignored data files."""
    src = PACKAGE / 'src' / 'aics_conformance'
    readers = [str(p.relative_to(src)) for p in sorted(src.rglob('*.py'))
               if re.search(r'importlib\.resources|\bfiles\(|data/', p.read_text(encoding='utf-8'))]
    assert readers == []


def test_fake_serves_the_banner_everywhere(server):
    ctx = server.context()
    assert ctx.client.request('GET', '/llms.txt', pages=True).text() == dialogue.BANNER
    assert ctx.client.get('banner', pages=True)['banner'] == dialogue.BANNER
    assert ctx.client.gate().exchange().startswith(dialogue.BANNER)
    assert FakeServer('banner').context().client.get('banner', pages=True)['banner'] != dialogue.BANNER
