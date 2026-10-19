#!/usr/bin/env bash
# Publish the public tile tree; credentials stay in RCLONE_CONFIG.
# Defaults: AICS_TILES_DIR=/data/tiles; AICS_MIRROR_R2=r2:aics-tiles;
# AICS_MIRROR_B2=b2:aics-tiles (bucket[/prefix], separate from private backups).
# Create those buckets first. Configure public read serving separately.
# Exit: 0 published (or another run holds lock), 1 unexpected/local I/O error,
# 2 configuration/dependency error, 3 unstable/unsafe snapshot,
# 4 tile upload/immutable conflict, 5 checkpoint publication failure.
# No deletes. Only this publisher may write these destination prefixes.
set -euo pipefail
umask 077
fail() { printf 'mirror-sync: %s\n' "$2" >&2; exit "$1"; }
for tool in rclone python3 flock; do
    command -v "$tool" >/dev/null || fail 2 "missing dependency: $tool"
done
TILES=${AICS_TILES_DIR:-/data/tiles}
CONF=${RCLONE_CONFIG:-/root/.config/rclone/rclone.conf}
R2=${AICS_MIRROR_R2:-r2:aics-tiles}
B2=${AICS_MIRROR_B2:-b2:aics-tiles}
[[ -d "$TILES" && -r "$CONF" ]] || fail 2 'tiles directory or rclone config unavailable'
[[ "$R2" == r2:?* && "$B2" == b2:?* ]] || fail 2 'destinations must use r2: and b2: with bucket paths'
exec 9>"${AICS_MIRROR_LOCK:-/run/aics-mirror-sync.lock}"
flock -n 9 || { printf 'mirror-sync: another run is active\n'; exit 0; }
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
# The writer atomically publishes tiles before checkpoint. Capture the note
# first and require it unchanged after copying; pruning races fail closed.
# A busy writer may force a retry on the next timer tick. No live files upload.
python3 - "$TILES" "$STAGE" <<'PYTHON' || fail 3 'snapshot failed; no checkpoint published'
import os, re, shutil, stat, sys
from pathlib import Path
src, dst = map(Path, sys.argv[1:])
pattern = re.compile(r'tile/(?:[0-9]+|entries)/(?:x[0-9]{3}/)*[0-9]{3}(?:\.p/(?:[1-9][0-9]{0,2}))?\Z')
def regular(p):
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise ValueError(f'not a single-link regular file: {p}')
regular(src / 'checkpoint')
note = (src / 'checkpoint').read_bytes()
if not note:
    raise ValueError('empty checkpoint')
for base, dirs, names in os.walk(src, followlinks=False):
    for name in dirs:
        if (Path(base) / name).is_symlink():
            raise ValueError('symlink directory in tiles')
    for name in names:
        p = Path(base) / name
        rel = p.relative_to(src).as_posix()
        if rel == 'checkpoint':
            continue
        # Atomic writer temporary files are not public resources.
        if name.startswith('.'):
            continue
        if not pattern.fullmatch(rel) or ('.p/' in rel and int(rel.rsplit('/', 1)[1]) > 255):
            raise ValueError(f'unexpected tile path: {rel}')
        regular(p)
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, out)
if (src / 'checkpoint').read_bytes() != note:
    raise ValueError('checkpoint changed during snapshot; retry next run')
(dst / 'checkpoint').write_bytes(note)
PYTHON
# Every published full or width-qualified partial tile is immutable; only checkpoint advances.
for remote in "$R2" "$B2"; do
    rclone --config "$CONF" copy "$STAGE" "$remote" --immutable --checksum \
        --exclude '/checkpoint' \
        || fail 4 "tile copy failed for $remote (possible immutable conflict)"
    rclone --config "$CONF" check "$STAGE" "$remote" --download --one-way \
        --exclude '/checkpoint' \
        || fail 4 "tile byte comparison failed for $remote"
done
# Both tile uploads finish before either checkpoint advances.
for remote in "$R2" "$B2"; do
    rclone --config "$CONF" copyto "$STAGE/checkpoint" "$remote/checkpoint" --ignore-times \
        || fail 5 "checkpoint copy failed for $remote"
done
printf 'mirror-sync: published tiles then checkpoint to r2 and b2\n'
