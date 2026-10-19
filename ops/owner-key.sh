#!/usr/bin/env bash
set -euo pipefail

# Custody (decisions 3, 16 and runbook step 0): the owner holds this private
# key and backs it up offline. Never put it on the VPS or in routine backups.
# It is NOT the server seed (which derives the log and policy keys).
# Decision 16 names the successor custodian; decision 17 leaves the handover
# agreement open. Do not assume that naming a custodian transfers this key.

die() { printf 'owner-key.sh: %s\n' "$*" >&2; exit 1; }
usage() { printf 'Usage: %s <new-private-keyfile> | --show <keyfile>\n' "$0"; }
show=false
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --show) show=true; shift ;;
    --*) usage >&2; exit 1 ;;
esac
[[ $# == 1 && -n $1 ]] || { usage >&2; exit 1; }
keyfile=$1
for tool in openssl python3 tail; do
    command -v "$tool" >/dev/null || die "required command missing: $tool"
done
if ! $show; then
    [[ ! -e $keyfile && ! -L $keyfile ]] || die "refusing to overwrite: $keyfile"
    # Probe support without opening the destination or printing key material.
    openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null \
        || die 'select supported OpenSSL with Ed25519 support (system LibreSSL may lack it)'
    # noclobber makes creation exclusive; OpenSSL writes through the opened FD.
    (umask 077; set -o noclobber; openssl genpkey -algorithm ed25519 > "$keyfile") \
        || die "key generation failed; inspect $keyfile before retrying"
    chmod 600 "$keyfile"
fi
[[ -f $keyfile && -r $keyfile ]] || die "cannot read key file: $keyfile"
# Verify the DER algorithm prefix before taking the final 32 bytes; --show
# must not silently label an RSA or X25519 key as an Ed25519 identity.
openssl pkey -in "$keyfile" -pubout -outform DER | python3 -c '
import sys
der = sys.stdin.buffer.read()
if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
    sys.exit("owner-key.sh: expected an Ed25519 key")
' || die "invalid Ed25519 key: $keyfile"
forms=$(openssl pkey -in "$keyfile" -pubout -outform DER | tail -c 32 | python3 -c '
import base64, sys
raw = sys.stdin.buffer.read()
if len(raw) != 32:
    sys.exit("owner-key.sh: expected 32 public-key bytes")
payload = b"\xed\x01" + raw
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n, encoded = int.from_bytes(payload, "big"), ""
while n:
    n, r = divmod(n, 58)
    encoded = alphabet[r] + encoded
encoded = "1" * (len(payload) - len(payload.lstrip(b"\x00"))) + encoded
public = base64.urlsafe_b64encode(raw).decode().rstrip("=")
print("base64url: " + public)
print("did:key:z" + encoded)
print("# Copy this public-only line into deploy/.env:")
print("AICS_OWNER_PUBKEY=" + public)
') || die 'public-key extraction failed'
printf '%s\n' "$forms"
