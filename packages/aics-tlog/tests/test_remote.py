"""HttpTileReader: mirror fallback, transport rules, and a cache that only
keeps authenticated data."""

import pytest

from aics_tlog import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from aics_tlog.remote import HttpTileReader, tile_source_url
from aics_tlog.tiles import (
    TileUnavailableError,
    TileVerificationError,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
    materialise_tiles,
)
from aics_tlog.verified import VerifiedTileReader

from conftest import flip_bit, make_leaves
from tileserver import TileServer, dead_url

LEAVES = make_leaves(600)
TREE = MerkleTree(LEAVES)
TILES = materialise_tiles(LEAVES)


@pytest.fixture
def servers():
    made = []

    def make(files=None, default=None):
        srv = TileServer(TILES if files is None else files, default)
        made.append(srv)
        return srv

    yield make
    for srv in made:
        srv.close()


def reader(*urls, **kw):
    kw.setdefault("proxies", {})
    kw.setdefault("timeout", 5)
    return HttpTileReader(list(urls), **kw)


def test_reads_tiles_and_computes_proofs(servers):
    good = servers()
    r = reader(good.url)
    p = inclusion_proof_from_tiles(r, 42, 600)
    assert verify_inclusion(leaf_hash(LEAVES[42]), 42, 600, p, TREE.root())
    c = consistency_proof_from_tiles(r, 300, 600)
    assert verify_consistency(300, 600, TREE.root(300), TREE.root(), c)
    path, headers = good.requests[0]
    assert headers.get("Accept-Encoding") == "gzip, identity"
    assert headers.get("User-Agent", "").startswith("aics-tlog/")
    assert r.read_tile(0, 9, None) is None  # beyond the tree: 404


def test_mirror_fallback_skips_every_kind_of_bad_source(servers):
    s500 = servers(default="500")
    s404 = servers(files={})
    sredirect = servers(default="redirect")
    short = {p: d[:-32] if p.startswith("tile/0/") else d for p, d in TILES.items()}
    smalformed = servers(files=short)
    good = servers()
    r = reader(dead_url(), s500.url, s404.url, sredirect.url, smalformed.url, good.url)
    assert r.read_tile(0, 0, None) == TILES["tile/0/000"]
    assert r.read_entry_bundle(2, 88) == TILES["tile/entries/002.p/88"]
    for srv in (s500, s404, sredirect, smalformed):
        assert "tile/0/000" in srv.paths_requested()
    assert len([p for p in sredirect.paths_requested() if p == "tile/0/000"]) == 1  # redirect not followed


def test_not_found_versus_unavailable(servers):
    s404a, s404b, s500 = servers(files={}), servers(files={}), servers(default="500")
    assert reader(s404a.url, s404b.url).read_tile(0, 0, None) is None
    assert reader(s404a.url, dead_url()).read_tile(0, 0, None) is None  # someone answered "not found"
    with pytest.raises(TileUnavailableError):
        reader(dead_url(), s500.url).read_tile(0, 0, None)


def test_gzip_and_size_caps(servers):
    gz = servers(default="gzip")
    r = reader(gz.url)
    assert r.read_tile(0, 1, None) == TILES["tile/0/001"]
    assert r.read_entry_bundle(0, None) == TILES["tile/entries/000"]
    huge, bomb = servers(default="huge"), servers(default="bomb")
    with pytest.raises(TileUnavailableError, match="too large"):
        reader(huge.url).read_tile(0, 0, None)
    with pytest.raises(TileUnavailableError, match="too large"):
        reader(bomb.url).read_tile(0, 0, None)
    good = servers()
    assert reader(huge.url, bomb.url, good.url).read_tile(0, 0, None) == TILES["tile/0/000"]


def test_cache_holds_only_authenticated_resources(servers, tmp_path):
    good = servers()
    cache = tmp_path / "cache"
    r = reader(good.url, cache_dir=cache)
    # Unauthenticated reads are not cached by default.
    r.read_tile(0, 0, None)
    assert not cache.exists()
    vr = VerifiedTileReader(r, 600, TREE.root())
    p = inclusion_proof_from_tiles(vr, 3, 600)
    assert verify_inclusion(leaf_hash(LEAVES[3]), 3, 600, p, TREE.root())
    vr.entry(3)
    assert (cache / "tile/0/000").read_bytes() == TILES["tile/0/000"]
    assert (cache / "tile/entries/000").read_bytes() == TILES["tile/entries/000"]
    assert not (cache / "tile/0/002.p/88").exists()  # partials not cached by default
    # A later run serves full tiles from the cache without asking the network.
    before = len(good.requests)
    r2 = reader(good.url, cache_dir=cache)
    assert r2.read_tile(0, 0, None) == TILES["tile/0/000"]
    assert len(good.requests) == before and r2.stats["cache_hits"] == 1


def test_offline_from_cache_with_partials(servers, tmp_path):
    good = servers()
    cache = tmp_path / "cache"
    vr = VerifiedTileReader(reader(good.url, cache_dir=cache, cache_partials=True), 600, TREE.root())
    for i in (0, 300, 599):
        inclusion_proof_from_tiles(vr, i, 600)
    offline = VerifiedTileReader(reader(dead_url(), cache_dir=cache, cache_partials=True), 600, TREE.root())
    for i in (0, 300, 599):
        p = inclusion_proof_from_tiles(offline, i, 600)
        assert verify_inclusion(leaf_hash(LEAVES[i]), i, 600, p, TREE.root())


def test_cache_unverified_option(servers, tmp_path):
    good = servers()
    r = reader(good.url, cache_dir=tmp_path, cache_unverified=True)
    r.read_tile(0, 1, None)
    r.read_tile(0, 2, 88)
    assert (tmp_path / "tile/0/001").exists()
    assert not (tmp_path / "tile/0/002.p/88").exists()


def test_corrupt_mirror_is_routed_around_and_never_cached(servers, tmp_path):
    corrupt = servers(default="corrupt")
    good = servers()
    r = reader(corrupt.url, good.url, cache_dir=tmp_path)
    vr = VerifiedTileReader(r, 600, TREE.root())
    for i in (0, 255, 256, 599):
        p = inclusion_proof_from_tiles(vr, i, 600)
        assert verify_inclusion(leaf_hash(LEAVES[i]), i, 600, p, TREE.root())
        assert vr.entry(i) == LEAVES[i]
    assert corrupt.requests  # it was asked first ...
    for path in ("tile/0/000", "tile/0/001", "tile/entries/000"):
        assert (tmp_path / path).read_bytes() == TILES[path]  # ... and nothing it served was kept
    # With only the corrupt mirror, verification fails loudly.
    with pytest.raises(TileVerificationError):
        VerifiedTileReader(reader(corrupt.url), 600, TREE.root()).check_root()


def test_poisoned_cache_entry_is_dropped(servers, tmp_path):
    good = servers()
    (tmp_path / "tile/0").mkdir(parents=True)
    (tmp_path / "tile/0/000").write_bytes(flip_bit(TILES["tile/0/000"], 5))
    r = reader(good.url, cache_dir=tmp_path)
    vr = VerifiedTileReader(r, 600, TREE.root())
    p = inclusion_proof_from_tiles(vr, 10, 600)
    assert verify_inclusion(leaf_hash(LEAVES[10]), 10, 600, p, TREE.root())
    assert (tmp_path / "tile/0/000").read_bytes() == TILES["tile/0/000"]


def test_reject_reports_when_sources_run_out(servers):
    a, b = servers(), servers()
    r = reader(a.url, b.url)
    assert r.read_tile(0, 0, None) is not None
    assert r.reject_tile(0, 0, None) is True  # b is left
    assert r.read_tile(0, 0, None) is not None
    assert r.reject_tile(0, 0, None) is False  # nothing left
    assert r.read_tile(0, 0, None) is None
    assert r.reject_tile(5, 5, None) is False  # never served


def test_file_sources_and_mixing(tmp_path, servers):
    from aics_tlog.tiles import TileWriter

    TileWriter(LEAVES).write_to(tmp_path / "tiles")
    url = tile_source_url(str(tmp_path / "tiles"))
    assert url.startswith("file://") and url.endswith("/")
    r = reader(url)
    assert r.read_tile(0, 0, None) == TILES["tile/0/000"]
    assert r.read_tile(0, 7, None) is None
    mixed = reader(dead_url(), url)
    assert mixed.read_entry_bundle(2, 88) == TILES["tile/entries/002.p/88"]
    with pytest.raises(ValueError):
        tile_source_url(str(tmp_path / "missing"))


def test_checkpoint_fetch(servers):
    files = dict(TILES)
    files["checkpoint"] = b"example.org/log\n600\nAAAA\n\n"
    good = servers(files=files)
    r = reader(dead_url(), good.url)
    fetched = r.fetch_checkpoints()
    assert fetched[0].data is None and fetched[0].error
    assert fetched[1].data == files["checkpoint"]
    assert r.read_checkpoint() == files["checkpoint"]
    assert good.requests[-1][1].get("Cache-Control") == "no-cache"
    with pytest.raises(TileUnavailableError):
        reader(dead_url()).read_checkpoint()


@pytest.mark.parametrize("bad", ["ftp://x.example/tiles", "https://x.example/t?x=1", "https://x.example/t#f", "http:///nohost", "relative/dir"])
def test_base_url_validation(bad):
    with pytest.raises(ValueError):
        HttpTileReader([bad])
    with pytest.raises(ValueError):
        HttpTileReader([])
