import argparse
import json
import sys
from pathlib import Path
from .adapter import Source
from .export import TOOL, collect, safe_text, write_outputs
from .fixture import local_source


def main(argv=None):
    parser = argparse.ArgumentParser(description='Export a verified public-only AICS snapshot')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--local', action='store_true')
    mode.add_argument('--remote', action='store_true')
    parser.add_argument('--tiles')
    parser.add_argument('--api')
    parser.add_argument('--vkey-file', type=Path)
    parser.add_argument('--checkpoint-file', type=Path, help='Chosen signed historical checkpoint; otherwise fetch once')
    parser.add_argument('--output', type=Path, default=TOOL / 'exports' / 'snapshot')
    parser.add_argument('--dry-run', action='store_true', help='Verify and print summary without dataset writes')
    args = parser.parse_args(argv)
    if args.remote and not all((args.tiles, args.api, args.vkey_file)):
        parser.error('--remote requires --tiles, --api and --vkey-file')
    if args.local and any((args.tiles, args.api, args.vkey_file, args.checkpoint_file)):
        parser.error('--local uses only its synthetic fixture and local pinned key')
    try:
        if args.local:
            source, server = local_source()
            # Generated locally, never fetched from a server endpoint.
            import tempfile
            with tempfile.TemporaryDirectory(prefix='.local-', dir=TOOL) as temporary:
                key = Path(temporary) / 'log.vkey'
                key.write_text(server.vkey + '\n')
                run(args, source, key)
        else:
            run(args, Source(args.tiles, args.api), args.vkey_file)
    except Exception:
        # Do not echo hostile response bytes or secret-bearing validation errors.
        print('Export failed: verification, availability, schema, or output safety check failed; no snapshot published.', file=sys.stderr)
        return 1
    return 0


def run(args, source, key):
    checkpoint = args.checkpoint_file.read_bytes() if args.checkpoint_file else None
    records, cp, note = collect(source, key, checkpoint)
    summary = json.dumps(dict(mode='dry-run summary', origin=cp.origin, checkpoint_size=cp.size,
                              checkpoint_root=cp.root.hex(), records=len(records),
                              hidden=sum('body' not in r for r in records),
                              formats=['JSONL', 'Parquet', 'Markdown', 'JSON manifest']))
    safe_text(summary)
    print(summary, flush=True)
    if not args.dry_run:
        write_outputs(args.output, records, cp, note, source, key)
        print('Snapshot written.', flush=True)
