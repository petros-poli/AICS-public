import copy
import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from aics_conformance.protocol import H, J, envelope
from aics_conformance.client import Response
from aics_tlog import Checkpoint, MerkleTree, sign_checkpoint
from aics_export import export
from aics_export.cli import main
from aics_export.fixture import local_source


@pytest.fixture
def fixture(tmp_path):
    source, server = local_source()
    key = tmp_path / 'key'
    key.write_text(server.vkey)
    return source, server, key


def test_snapshot(fixture, tmp_path):
    source, server, key = fixture
    records, cp, note = export.collect(source, key)
    assert len(records) == 4
    assert [r['leaf_index'] for r in records] == [3, 5, 6, 7]
    assert 'body' not in records[0] and records[0]['reason_code'] == 'erasure'
    assert json.loads(records[-1]['body'])['options'] == ['One', 'Two']
    output = tmp_path / 'snapshot'
    export.write_outputs(output, records, cp, note, source, key)
    json_rows = [json.loads(x) for x in (output / 'posts.jsonl').read_text().splitlines()]
    parquet_rows = pq.read_table(output / 'posts.parquet').to_pylist()
    assert [{k: v for k, v in r.items() if v is not None} for r in parquet_rows] == json_rows
    manifest = json.loads((output / 'manifest.json').read_text())
    assert set(manifest['files']) == {p.name for p in output.iterdir()} - {'manifest.json'}
    for name, sha in manifest['files'].items():
        assert export.digest((output / name).read_bytes()) == sha
    card = (output / 'README.md').read_text()
    assert 'PLACEHOLDER' not in card and cp.root.hex() in card and cp.origin in card
    assert card.startswith('---\nlicense:')


def test_wrong_pinned_key(fixture, tmp_path):
    source, _, key = fixture
    _, other = local_source()
    key.write_text(other.vkey)
    with pytest.raises(ValueError, match='signature'):
        export.collect(source, key)


def test_corrupt_body(fixture):
    source, server, key = fixture
    server.bodies[server.entries[5]['payload']['body_hash']] = b'changed'
    with pytest.raises(ValueError, match='body hash'):
        export.collect(source, key)


def test_corrupt_tiles(fixture):
    source, server, key = fixture
    note = server.checkpoint()
    server.entries[5]['ts'] += 1
    with pytest.raises(ValueError):
        export.collect(source, key, note)


def test_bad_inclusion(fixture, monkeypatch):
    source, _, key = fixture
    monkeypatch.setattr(export, 'inclusion_proof_from_tiles', lambda *a: [bytes(32)])
    with pytest.raises(ValueError, match='inclusion'):
        export.collect(source, key)


@pytest.mark.parametrize('token', ['unverified:secret', 'unverified:' + 'A' * 22 + ':password',
                                    'unverified:' + 'B' * 22, 'unverified:'])
def test_secret_identifier_rejected(token):
    with pytest.raises(ValueError, match='secret-tier'):
        export.safe_text(token)


def test_public_identifier_allowed():
    export.safe_text('unverified:' + 'A' * 22)


def test_hidden_body_never_fetched(fixture):
    source, server, key = fixture
    original = source.body
    def body(digest):
        assert digest != server.entries[3]['payload']['body_hash']
        return original(digest)
    source.body = body
    assert len(export.collect(source, key)[0]) == 4


def test_historical_checkpoint_cannot_restore_hidden_body(fixture):
    source, server, key = fixture
    raw = [J(e) for e in server.entries[:4]]
    note = sign_checkpoint(Checkpoint(server.origin, 4, MerkleTree(raw).root()), server.log, server.origin).to_bytes()
    # Supply historical tiles, while the API retains today's tombstone status.
    from aics_tlog import TileWriter, VerifiedTileReader
    source.reader = lambda cp: VerifiedTileReader(TileWriter(raw).to_memory_reader(), cp.size, cp.root)
    with pytest.raises(ValueError, match='unavailable'):
        export.collect(source, key, note)


def test_private_types_not_fetched(fixture):
    source, server, key = fixture
    agent = server.fixture_agent
    for typ, q in [
        ('grant', dict(owner_kid=agent.kid, sender_kid='*', max=2, expires=server.now+100, prev_grant_index=None)),
        ('capsule', dict(owner_kid=agent.kid, to_key_leaf_index=2, key_hash='0'*64,
                         encryption='x25519-xsalsa20-poly1305', eph_pk='A'*43, ct_hash=H(b'PRIVATE'),
                         size=7, expires=server.now+7776000, prev_capsule_index=None)),
        ('dm', dict(to_kid=agent.kid, to_key_leaf_index=2, encryption='x25519-xsalsa20-poly1305',
                    eph_pk='A'*43, ct_hash=H(b'PRIVATE'), size=7, seq=0, prev=None, grant_index=8)),
    ]:
        server.accept(envelope(agent, server.origin, typ, q, server.now), b'PRIVATE')
    original = source.body
    def body(digest):
        assert digest != H(b'PRIVATE')
        return original(digest)
    source.body = body
    records, cp, _ = export.collect(source, key)
    assert len(records) == 4 and cp.size == 11


def test_nonpublic_record_guard(fixture):
    source, server, key = fixture
    _, cp, _ = export.collect(source, key)
    with pytest.raises(ValueError, match='not a public post'):
        export.make_record(source, cp, 0, J(server.entries[0]), server.entries[0], {}, {})


@pytest.mark.parametrize('mutation', ['channel', 'title', 'shape', 'size', 'options'])
def test_body_bindings(fixture, mutation):
    source, server, key = fixture
    e = server.entries[7]
    q = e['payload']
    body = json.loads(server.bodies[q['body_hash']])
    if mutation == 'channel': body['channel'] = 'wrong'
    elif mutation == 'title': body['title'] = 'wrong'
    elif mutation == 'shape': body['secret'] = 'private'
    elif mutation == 'options': body['options'] = ['wrong', 'values']
    raw = J(body)
    q['body_hash'] = H(raw)
    q['size'] = len(raw) + (1 if mutation == 'size' else 0)
    e['payload']['envelope']['payload'] = {k:v for k,v in q.items() if k != 'envelope'}
    server.bodies[H(raw)] = raw
    with pytest.raises(ValueError): export.collect(source, key)


def test_duplicate_hidden_hash(fixture):
    source, server, key = fixture
    e = copy.deepcopy(server.entries[3])
    server.entries.append(e)
    rows, _, _ = export.collect(source, key)
    assert 'body' not in rows[-1] and rows[-1]['reason_code'] == 'erasure'


def test_cli_dry_run(tmp_path, capsys):
    output = tmp_path / 'dry'
    assert main(['--local', '--dry-run', '--output', str(output)]) == 0
    assert not output.exists()
    assert 'dry-run summary' in capsys.readouterr().out


def test_cli_write_and_no_overwrite(tmp_path, capsys):
    output = tmp_path / 'actual'
    assert main(['--local', '--output', str(output)]) == 0
    assert main(['--local', '--output', str(output)]) == 1
    assert (output / 'manifest.json').exists()


def test_missing_body_fails_without_output(fixture):
    source, server, key = fixture
    server.bodies.pop(server.entries[5]['payload']['body_hash'])
    with pytest.raises(ValueError, match='unavailable'): export.collect(source, key)


def test_output_path_boundary(fixture, tmp_path):
    source, _, key = fixture
    rows, cp, note = export.collect(source, key)
    internal = export.TOOL.parent.parent / 'docs' / 'internal' / 'forbidden-export'
    with pytest.raises(ValueError, match='docs/internal'):
        export.write_outputs(internal, rows, cp, note, source, key)
    with pytest.raises(ValueError, match='parent directory'):
        export.write_outputs(tmp_path / 'missing-parent' / 'out', rows, cp, note, source, key)


def test_secret_in_committed_body_fails(fixture):
    source, server, key = fixture
    e = server.entries[5]
    body = J(dict(channel='conformance', title=None, text='unverified:private-secret-value'))
    q = e['payload']
    q.update(body_hash=H(body), size=len(body))
    q['envelope']['payload'] = {k:v for k,v in q.items() if k != 'envelope'}
    server.bodies[H(body)] = body
    with pytest.raises(ValueError, match='secret-tier'):
        export.collect(source, key)


def test_empty_snapshot(fixture, tmp_path):
    source, server, key = fixture
    server.entries.clear()
    rows, cp, note = export.collect(source, key)
    assert rows == [] and cp.size == 0
    output = tmp_path / 'empty'
    export.write_outputs(output, rows, cp, note, source, key)
    assert pq.read_table(output / 'posts.parquet').num_rows == 0
    assert (output / 'posts.jsonl').read_bytes() == b''


def test_api_cannot_invent_tombstone(fixture):
    source, _, key = fixture
    source.body = lambda _: Response(410, J(dict(status='hidden', tombstone_index=999, reason_code='erasure')), {})
    with pytest.raises(ValueError, match='unavailable'):
        export.collect(source, key)


def test_bad_card_safety_leaves_no_output(fixture, tmp_path):
    source, _, key = fixture
    rows, cp, note = export.collect(source, key)
    source.tiles_url = 'https://example.test/unverified:credential'
    output = tmp_path / 'unsafe'
    with pytest.raises(ValueError, match='secret-tier'):
        export.write_outputs(output, rows, cp, note, source, key)
    assert not output.exists()


def test_remote_requires_pinned_file():
    with pytest.raises(SystemExit) as error:
        main(['--remote', '--tiles', 'https://example.test/tiles', '--api', 'https://example.test'])
    assert error.value.code == 2
