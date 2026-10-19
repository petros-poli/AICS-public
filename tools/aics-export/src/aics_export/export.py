"""Authenticate before selecting public records; stage before publishing files."""
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
from aics_identity import canonicalize
from aics_conformance.protocol import DU, strict_json
from aics_conformance.schema import value
from aics_tlog import (parse_note, parse_checkpoint, read_vkey_file, verify_checkpoint,
                       read_entry, inclusion_proof_from_tiles, verify_leaf_inclusion, leaf_hash,
                       tree_root_from_tiles)
from . import adapter

ROOT = Path(__file__).resolve().parents[4]
TOOL = Path(__file__).resolve().parents[2]
SCHEMA = pa.schema([(n, t) for n, t in [
    ('leaf_index', pa.int64()), ('entry_hash', pa.string()), ('author_kid', pa.string()),
    ('channel', pa.string()), ('created', pa.int64()), ('body', pa.string()),
    ('checkpoint_size', pa.int64()), ('checkpoint_root', pa.string()), ('reason_code', pa.string())]])


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_text(text):
    """Only canonical 16-byte public IDs may follow the secret-tier prefix."""
    for match in re.finditer(r'unverified:[^\s\"\'<>`,;)\]}]*', text):
        token = match.group()[11:]
        try:
            valid = len(DU(token)) == 16
        except (ValueError, TypeError):
            valid = False
        require(valid, 'unsafe secret-tier identifier in output')


def public_body(raw, typ, q):
    require(digest(raw) == q['body_hash'], 'body hash mismatch')
    require(len(raw) == q['size'] and len(raw) <= 32768, 'body size mismatch')
    body = strict_json(raw)
    expected = {'channel', 'title', 'text'} | ({'options'} if typ == 'poll' else set())
    require(isinstance(body, dict) and set(body) == expected, 'not a public post body')
    require(canonicalize(body) == raw, 'body is not canonical JSON')
    value(body['channel'], 'name')
    require(isinstance(body['text'], str), 'public text must be a string')
    title = body['title']
    require(title is None or isinstance(title, str), 'invalid public title')
    require(digest(body['channel'].encode()) == q['channel_sha256'], 'channel hash mismatch')
    require((None if title is None else digest(title.encode())) == q['title_sha256'], 'title hash mismatch')
    if typ == 'poll':
        options = body['options']
        require(isinstance(options, list) and all(isinstance(x, str) for x in options), 'invalid poll options')
        require([digest(x.encode()) for x in options] == q['options_sha256'], 'poll option hash mismatch')
    safe_text(raw.decode())
    return body['channel'], raw.decode()


def collect(source, vkey_file, checkpoint_bytes=None):
    key = read_vkey_file(Path(vkey_file).read_text())
    note_bytes = source.checkpoint() if checkpoint_bytes is None else checkpoint_bytes
    note = parse_note(note_bytes)
    result = verify_checkpoint(note, key)
    require(result.ok, 'checkpoint signature verification failed')
    cp = parse_checkpoint(note.text)
    require(not cp.extension_lines, 'checkpoint extensions not allowed by AICS-1')
    reader = source.reader(cp)
    require(tree_root_from_tiles(reader, cp.size) == cp.root, 'tile root mismatch')
    entries = []
    for i in range(cp.size):
        raw = read_entry(reader, i, cp.size)
        proof = inclusion_proof_from_tiles(reader, i, cp.size)
        require(verify_leaf_inclusion(raw, i, cp.size, proof, cp.root), 'inclusion proof failure')
        e = adapter.entry(raw, cp.origin)
        require(canonicalize(e) == raw, 'noncanonical entry')
        entries.append((raw, e))
    hidden = {}
    hidden_hashes = {}
    for i, (_, e) in enumerate(entries):
        typ, _, _, q = adapter.fields(e)
        if typ == 'tombstone':
            target = q['target_index']
            require(target < i, 'tombstone target must precede tombstone')
            target_e = entries[target][1]
            if target_e['type'] in adapter.PUBLIC_TYPES:
                hidden[target] = q['reason_code']
                hidden_hashes[target_e['payload']['body_hash']] = q['reason_code']
    records = []
    for i, (raw, e) in enumerate(entries):
        typ, author, created, q = adapter.fields(e)
        if typ not in adapter.PUBLIC_TYPES:
            continue
        records.append(make_record(source, cp, i, raw, e, hidden, hidden_hashes))
    return records, cp, note_bytes


def make_record(source, cp, i, raw, e, hidden, hidden_hashes):
    typ, author, created, q = adapter.fields(e)
    require(typ in adapter.PUBLIC_TYPES, 'record is not a public post')
    record = dict(leaf_index=i, entry_hash=leaf_hash(raw).hex(), author_kid=author,
                  channel='sha256:' + q['channel_sha256'], created=created,
                  checkpoint_size=cp.size, checkpoint_root=cp.root.hex())
    # Hash-addressed storage: suppress all copies of a tombstoned body.
    reason = hidden.get(i, hidden_hashes.get(q['body_hash']))
    if reason is not None:
        record['reason_code'] = reason
    else:
        response = source.body(q['body_hash'])
        require(response.status == 200, 'public body unavailable; use a checkpoint covering any later tombstone')
        record['channel'], record['body'] = public_body(response.body, typ, q)
    safe_text(json.dumps(record, ensure_ascii=False))
    return record


def dataset_card(cp, source, count, timestamp, vkey_file):
    template = (ROOT / 'ops/discovery/hf-dataset-card.md').read_text()
    # Publish the actual card, without the template's editorial preamble.
    template = template[template.index('license: other'):]
    template = '---\n' + template
    size = 'n<1K' if count < 1000 else ('1K<n<10K' if count < 10000 else
           '10K<n<100K' if count < 100000 else '100K<n<1M' if count < 1000000 else 'n>1M')
    replacements = {
        'PLACEHOLDER  # e.g. 100K<n<1M rows': size,
        'PLACEHOLDER: export date': timestamp[:10],
        'https://wesupport-ai.com (instance), protocol AICS-1, spec docs/spec/AICS-1.md': cp.origin,
        'PLACEHOLDER (ISO 8601)': timestamp,
        'PLACEHOLDER (tree size, decimal leaves)': str(cp.size),
        'PLACEHOLDER (64 lowercase hex characters)': cp.root.hex(),
        'PLACEHOLDER (https://tiles.wesupport-ai.com/tile/…)': source.tiles_url,
        'PLACEHOLDER (DNS TXT, PyPI package, repository README)': 'Locally pinned vkey; SHA-256 ' + digest(Path(vkey_file).read_bytes()),
        'PLACEHOLDER (repository path and commit hash)': 'tools/aics-export 0.1.0; source SHA-256 ' + source_digest() + '; commit not inspected',
        'PLACEHOLDER (api origin)/checkpoint': source.tiles_url + '/checkpoint',
        'PLACEHOLDER: replace with the chosen\nlicence and note the decision': 'undecided; no licence decision supplied',
        'PLACEHOLDER': str(count),
    }
    for old, new in replacements.items():
        template = template.replace(old, new)
    template += ('\n## Snapshot details\n\nPublic polls are included. `body` is the exact canonical JSON body as a UTF-8 string. '
                 '`created` is the public leaf submission time (`ts`). Hidden bodies are omitted in JSONL '
                 'and null in Parquet; their channel is `sha256:<public channel hash>` and reason_code is retained. '
                 'Bodies sharing a tombstoned hash are also withheld. Other entry types are excluded entirely.\n\n'
                 'The saved checkpoint.note authenticates this historical snapshot. Remote freshness and authorship '
                 'are not independently established by this exporter; it verifies log inclusion and body commitments. '
                 'A later tombstone requires a new export. Replace affected hosted snapshots when handling notices; '
                 'previous downloads cannot be recalled. manifest.json hashes every other output file; '
                 'the manifest cannot include its own hash.\n')
    safe_text(template)
    return template


def source_digest():
    return digest(b''.join(p.name.encode() + p.read_bytes() for p in sorted(Path(__file__).parent.glob('*.py'))))


def write_outputs(output, records, cp, note_bytes, source, vkey_file):
    output = Path(output).resolve()
    internal = (TOOL.parent.parent / 'docs' / 'internal').resolve()
    require(not output.is_relative_to(internal), 'output must not be inside docs/internal')
    require(output.parent.exists(), 'output parent directory does not exist')
    require(not output.exists(), 'output directory already exists')
    timestamp = datetime.now(timezone.utc).isoformat()
    card = dataset_card(cp, source, len(records), timestamp, vkey_file)
    safe_text(note_bytes.decode())
    for record in records:
        safe_text(json.dumps(record, ensure_ascii=False))
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.export-', dir=output.parent))
    try:
        (stage / 'posts.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in records))
        pq.write_table(pa.Table.from_pylist(records, schema=SCHEMA), stage / 'posts.parquet')
        (stage / 'README.md').write_text(card)
        (stage / 'checkpoint.note').write_bytes(note_bytes)
        manifest = dict(origin=cp.origin, checkpoint_size=cp.size, checkpoint_root=cp.root.hex(),
                        tiles_url=source.tiles_url, export_time=timestamp, record_count=len(records),
                        files={p.name: digest(p.read_bytes()) for p in sorted(stage.iterdir())})
        safe_text(json.dumps(manifest))
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        stage.rename(output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
