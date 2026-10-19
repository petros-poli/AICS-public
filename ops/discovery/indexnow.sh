#!/usr/bin/env bash
# Ping the IndexNow API (default https://api.indexnow.org) for a list of our
# URLs, so participating search engines (Bing, Yandex, …) pick up new or
# changed pages on wesupport-ai.com quickly. Decision 12: free, zero-labour
# discovery; the Master Plan's "open arms" crawler policy without the parts
# decision 13 discarded.
#
# This script ONLY pings. IndexNow requires — separately, always — that the
# key is downloadable at
#     https://<host>/<key>.txt
# answering HTTP 200 with the key itself as the body. THE SITE must serve that
# file: drop <key>.txt into the static pages served on wesupport-ai.com
# (Cloudflare-proxied host, decision 10) and leave it there permanently. This
# script neither creates nor checks that file; without it IndexNow answers
# 403 and discards the ping.
#
# Usage:
#   ops/discovery/indexnow.sh -k <key> https://wesupport-ai.com/ …
#   ops/discovery/indexnow.sh -k <key> -f urls.txt    # one URL per line, # = comment
#   INDEXNOW_KEY=<key> ops/discovery/indexnow.sh https://…   # key from env
# Env: INDEXNOW_KEY (alternative to -k), INDEXNOW_API (default below).
#
# Key format (per the IndexNow spec): 8–128 characters of a-z A-Z 0-9 and '-'.
# Generate one with: openssl rand -hex 16
#
# Exit codes: 0 every ping accepted (HTTP 200/202); 1 usage error; 2 the API
# rejected a ping (400 bad request, 403 key file not served, 422, 429 …).
set -euo pipefail

API="${INDEXNOW_API:-https://api.indexnow.org}"
key="${INDEXNOW_KEY:-}"
urls=()

usage() {
  printf 'usage: %s [-k <key>] (-f <urls-file> | URL...)\n' "${0##*/}"
  printf '  key also via INDEXNOW_KEY; URLs must be http(s):// and share their host per ping\n'
}

while [ $# -gt 0 ]; do
  case "$1" in
    -k|--key)
      [ $# -ge 2 ] || { printf 'option %s needs a value\n' "$1" >&2; exit 1; }
      key="$2"; shift 2 ;;
    -f|--file)
      [ $# -ge 2 ] || { printf 'option %s needs a value\n' "$1" >&2; exit 1; }
      [ -r "$2" ] || { printf 'cannot read %s\n' "$2" >&2; exit 1; }
      while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        if [ -n "$line" ]; then urls+=("$line"); fi
      done < "$2"
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 1 ;;
    *) urls+=("$1"); shift ;;
  esac
done

[ -n "$key" ] || { printf 'no key: pass -k <key> or set INDEXNOW_KEY (generate: openssl rand -hex 16)\n' >&2; exit 1; }
[ "${#urls[@]}" -gt 0 ] || { printf 'no URLs given\n' >&2; usage >&2; exit 1; }

if ! [[ "$key" =~ ^[0-9a-zA-Z-]{8,128}$ ]]; then
  printf 'key does not match the IndexNow format (8-128 chars of a-z A-Z 0-9 -)\n' >&2
  exit 1
fi

for u in "${urls[@]}"; do
  case "$u" in
    http://*|https://*) ;;
    *) printf 'not an http(s) URL: %s\n' "$u" >&2; exit 1 ;;
  esac
done

rc=0
# One ping per host: the key file is validated per host at
# https://<host>/<key>.txt, so each host is submitted on its own.
for host in $(printf '%s\n' "${urls[@]}" | awk -F/ '{print $3}' | sort -u); do
  host_urls=()
  for u in "${urls[@]}"; do
    case "$u" in
      *://"$host"/*|*://"$host") host_urls+=("$u") ;;
    esac
  done
  payload="$(python3 - "$key" "$host" "${host_urls[@]}" <<'PY'
import json, sys
key, host, urls = sys.argv[1], sys.argv[2], sys.argv[3:]
print(json.dumps({
    "host": host,
    "key": key,
    "keyLocation": f"https://{host}/{key}.txt",
    "urlList": urls,
}))
PY
)"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 \
    -H 'Content-Type: application/json; charset=utf-8' \
    -d "$payload" "$API/indexnow")" || {
      printf 'FAIL: request to %s did not complete for %s\n' "$API" "$host" >&2
      rc=2; continue
    }
  case "$code" in
    200|202)
      printf 'ok: %s accepted %d URL(s) for %s\n' "$API" "${#host_urls[@]}" "$host" ;;
    *)
      printf 'FAIL: %s answered HTTP %s for %s (%d URL(s)) — 403 usually means https://%s/%s.txt is not served\n' \
        "$API" "$code" "$host" "${#host_urls[@]}" "$host" "$key" >&2
      rc=2 ;;
  esac
done

printf 'reminder: this script only pings; every host above must keep serving https://<host>/%s.txt (HTTP 200, body = the key)\n' "$key"
exit "$rc"
