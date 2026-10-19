#!/usr/bin/env bash
# DNS only: SSL mode, bot settings, mail routing, optional AAAA/CAA are manual.
set +x  # Never trace the API token, even when invoked with bash -x.
set -euo pipefail
die() { printf 'cloudflare-dns.sh: %s\n' "$*" >&2; exit 1; }
usage() {
    printf 'Usage: %s [--apply] [--bundle <file>] <VPS_IPV4>\n' "$0"
    printf '%s\n' 'Default: offline dry run. --apply needs CLOUDFLARE_API_TOKEN in the environment.'
}
apply=false
bundle=
ipv4=
while [[ $# -gt 0 ]]; do
    case $1 in
        --apply) apply=true; shift ;;
        --bundle)
            [[ $# -ge 2 && -n $2 ]] || die '--bundle requires a file'
            bundle=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) [[ -z $ipv4 ]] || die 'supply exactly one VPS IPv4 address'; ipv4=$1; shift ;;
    esac
done
[[ -n $ipv4 ]] || { usage >&2; exit 1; }
command -v python3 >/dev/null || die 'python3 is required'
python3 -c 'import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])' "$ipv4" \
    2>/dev/null || die "invalid IPv4 address: $ipv4"
zone=wesupport-ai.com
plan=$(python3 -c '
import json, pathlib, re, sys
ip, zone, bundle = sys.argv[1:]
records = [dict(type="A", name=zone if h == "@" else h+"."+zone,
                content=ip, proxied=h in ("@", "tiles"), ttl=1)
           for h in ("@", "api", "gate", "ip", "tiles")]
records.append(dict(type="CNAME", name="www."+zone, content=zone, proxied=True, ttl=1))
if bundle:
    try:
        content = pathlib.Path(bundle).read_text().strip()
    except (OSError, UnicodeError) as exc:
        sys.exit("cloudflare-dns.sh: cannot read bundle: " + str(exc))
    if not re.fullmatch(r"aics1=[A-Za-z0-9_-]+={0,2}", content):
        sys.exit("cloudflare-dns.sh: bundle must contain one aics1=<base64url> line")
    records.append(dict(type="TXT", name="_aics."+zone, content=content, ttl=1))
for record in records:
    print(json.dumps(record, separators=(",", ":")))
' "$ipv4" "$zone" "$bundle") || exit 1
if ! $apply; then
    printf 'DRY RUN: planned upserts for %s (TTL auto; no API calls):\n%s\n' "$zone" "$plan"
    [[ -n $bundle ]] || printf '%s\n' '_aics TXT: untouched (no --bundle supplied).'
    exit 0
fi
[[ -n ${CLOUDFLARE_API_TOKEN:-} ]] || die 'CLOUDFLARE_API_TOKEN is missing; export a token with Zone Read and DNS Edit for wesupport-ai.com'
[[ $CLOUDFLARE_API_TOKEN != *$'\n'* && $CLOUDFLARE_API_TOKEN != *$'\r'* ]] || die 'invalid token: contains a newline'
command -v curl >/dev/null || die 'curl is required for --apply'
api() {
    local method=$1 path=$2 response
    shift 2
    # Pass authorization over stdin, not argv; no token files are created.
    response=$(printf 'Authorization: Bearer %s\n' "$CLOUDFLARE_API_TOKEN" |
        curl --silent --show-error --fail --connect-timeout 15 --max-time 60 \
            --header @- --header 'Content-Type: application/json' \
            --request "$method" "https://api.cloudflare.com/client/v4$path" "$@") \
        || die "Cloudflare $method failed for $path (check token permissions and connectivity)"
    printf '%s' "$response" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit("cloudflare-dns.sh: Cloudflare returned invalid JSON")
if data.get("success") is not True:
    sys.exit("cloudflare-dns.sh: Cloudflare API errors: " + json.dumps(data.get("errors", [])))
print(json.dumps(data))
'
}
zone_id=$(api GET "/zones?name=$zone&per_page=50" | python3 -c '
import json, sys
data = json.load(sys.stdin)
rows = data["result"]
if len(rows) != 1 or rows[0].get("name") != sys.argv[1]:
    sys.exit("cloudflare-dns.sh: expected exactly one accessible matching zone; check Zone Read permission")
print(rows[0]["id"])
' "$zone") || exit 1
while IFS= read -r record; do
    read -r type name <<< "$(printf '%s' "$record" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r["type"],r["name"])')"
    existing=$(api GET "/zones/$zone_id/dns_records?type=$type&name=$name&per_page=100")
    action=$(printf '%s' "$existing" | python3 -c '
import json, sys
data, wanted = json.load(sys.stdin), json.loads(sys.argv[1])
rows = data["result"]
if len(rows) > 1 or data.get("result_info", {}).get("total_count", len(rows)) > 1:
    sys.exit("cloudflare-dns.sh: multiple records match " + wanted["name"] + "; reconcile manually")
if not rows:
    print("create")
else:
    row = rows[0]
    if row.get("type") != wanted["type"] or row.get("name") != wanted["name"]:
        sys.exit("cloudflare-dns.sh: API returned a nonmatching record")
    same = all(row.get(k) == v for k, v in wanted.items())
    print("unchanged" if same else row["id"])
' "$record") || exit 1
    case $action in
        unchanged) printf 'Unchanged %s %s\n' "$type" "$name" ;;
        create)
            api POST "/zones/$zone_id/dns_records" --data "$record" >/dev/null
            printf 'Created %s %s\n' "$type" "$name" ;;
        *)
            api PATCH "/zones/$zone_id/dns_records/$action" --data "$record" >/dev/null
            printf 'Updated %s %s\n' "$type" "$name" ;;
    esac
done <<< "$plan"
