#!/usr/bin/env bash
# Verify an entire release against a fixed repository, workflow identity and tag.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^v[[:alnum:]][[:alnum:].+_-]*$ ]]; then
  echo "Usage: $0 vTAG (letters, digits, dots, plus, underscore and hyphen only)" >&2
  exit 2
fi

tag=$1
repository=petros-poli/AICS-public
identity="https://github.com/$repository/.github/workflows/release.yml@refs/tags/$tag"
for tool in gh sigstore slsa-verifier python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 2; }
done

workdir=$(mktemp -d "${TMPDIR:-/tmp}/aics-release.XXXXXXXX")
trap 'rm -rf -- "$workdir"' EXIT
gh release download "$tag" --repo "$repository" --dir "$workdir"
cd "$workdir"

verify_file() {
  local file=$1
  local result=0
  if [[ ! -f "$file" || ! -f "$file.sigstore.json" || ! -f aics.intoto.jsonl ]]; then
    printf 'FAIL %s (missing artifact, bundle or provenance)\n' "$file"
    return 1
  fi
  if ! sigstore verify github --repository "$repository" \
    --cert-identity "$identity" --ref "refs/tags/$tag" \
    --bundle "$file.sigstore.json" "$file" > sigstore.log 2>&1; then
    cat sigstore.log >&2
    result=1
  fi
  if ! slsa-verifier verify-artifact "$file" \
    --provenance-path aics.intoto.jsonl \
    --source-uri "github.com/$repository" --source-tag "$tag" > slsa.log 2>&1; then
    cat slsa.log >&2
    result=1
  fi
  if [[ $result -eq 0 ]]; then
    printf 'PASS %s (Sigstore + SLSA)\n' "$file"
  else
    printf 'FAIL %s (Sigstore or SLSA verification failed)\n' "$file"
  fi
  return "$result"
}

# Authenticate the inventory before using filenames or accepting its hashes.
verify_file SHA256SUMS || exit 1
if ! python3 - <<'PY'
import hashlib
import re
from pathlib import Path

entries = {}
for line in Path("SHA256SUMS").read_text().splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.+\-]*(?:\.whl|\.tar\.gz))", line)
    if match is None:
        raise SystemExit("Invalid checksum manifest entry")
    digest, name = match.groups()
    if name in entries:
        raise SystemExit(f"Duplicate checksum manifest entry: {name}")
    entries[name] = digest
if not entries or not any(n.endswith(".whl") for n in entries) or not any(n.endswith(".tar.gz") for n in entries):
    raise SystemExit("Manifest must contain wheels and sdists")
actual = {p.name for p in Path('.').iterdir() if p.name.endswith((".whl", ".tar.gz"))}
failed = False
for name in sorted(actual - entries.keys()):
    print(f"FAIL {name} (distribution absent from signed manifest)")
    failed = True
for name, digest in entries.items():
    path = Path(name)
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        print(f"FAIL {name} (missing file or SHA-256 mismatch)")
        failed = True
if failed:
    raise SystemExit(1)
Path("verified-inventory.txt").write_text("".join(f"{name}\n" for name in sorted(entries)))
PY
then
  echo "Release inventory verification failed." >&2
  exit 1
fi

failed=0
while IFS= read -r file; do
  verify_file "$file" || failed=1
done < verified-inventory.txt
exit "$failed"
