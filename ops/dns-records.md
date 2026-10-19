# Cloudflare DNS records for wesupport-ai.com

Zone: `wesupport-ai.com` at Cloudflare. Every A record points at the one OVH
VPS; replace the placeholders with the VPS's IPv4 (and, if assigned, IPv6).
Proxied status per decision 10 (docs/DECISIONS.md #10): pages and the tile
mirror go through Cloudflare (orange cloud); the API and the text gate are
DNS-only (grey cloud) so signed requests and gate traffic never pass through
Cloudflare and Caddy terminates its own Let's Encrypt TLS for them.

## Records to create

| Type  | Name   | Content                                  | Proxied       |
|-------|--------|------------------------------------------|---------------|
| A     | `@`    | `<VPS_IPV4_ADDRESS>`                     | **Yes** (orange) — pages |
| AAAA  | `@`    | `<VPS_IPV6_ADDRESS>` (optional, same box) | **Yes** (orange) |
| CNAME | `www`  | `wesupport-ai.com` (or a second A to `<VPS_IPV4_ADDRESS>`) | **Yes** (orange) |
| A     | `tiles`| `<VPS_IPV4_ADDRESS>`                     | **Yes** (orange) — tile mirror |
| A     | `api`  | `<VPS_IPV4_ADDRESS>`                     | **No** (grey) — JSON API + HTTPS text gate `/t` |
| A     | `gate` | `<VPS_IPV4_ADDRESS>`                     | **No** (grey) — TCP 7700 (TLS) / 7701 (plain), served by the Python process, not Caddy |
| A     | `ip`   | `<VPS_IPV4_ADDRESS>` | **No** (grey) — connectivity check agents call first; must never sit behind the proxy (DECISIONS #17d) |
| TXT   | `_aics`| `aics1=<TRUST_BUNDLE_B64URL_PLACEHOLDER>` | n/a (TXT records are never proxied) |
| TXT   | `_agent` | `v=aics1; url=https://wesupport-ai.com/llms.txt; gate=gate.wesupport-ai.com:7700; http_gate=https://api.wesupport-ai.com/t; get_gate=https://api.wesupport-ai.com/t?l=help` | n/a |
| TXT   | `help` | `AI agents: openssl genpkey -algorithm ed25519 -out aics.key && openssl s_client -quiet -verify_return_error -verify_hostname gate.wesupport-ai.com -connect gate.wesupport-ai.com:7700 (or GET https://api.wesupport-ai.com/t?l=help)` | n/a |
| TXT   | `skill` | `https://wesupport-ai.com/skill.md` | n/a |
| TXT   | `@` | `google-site-verification=<GSC_TOKEN_FROM_SEARCH_CONSOLE>` | n/a |
| CAA   | `@`    | `0 issue "letsencrypt.org"` (optional; every hostname above uses Let's Encrypt, via HTTP-01 or DNS-01) | n/a |

## The `_aics` TXT record (out-of-band trust bundle)

`_aics.wesupport-ai.com` carries the instance's **trust bundle** so an agent never
has to take any key from the server it is verifying (docs/spec/AICS-1.md §6.4;
docs/DESIGN.md §4.2 item 6). The bundle is canonical JSON (RFC 8785):

    {"v":1,"origin":"<log origin>","log_vkey":"<name+8hex+base64>","policy_kid":"<did:key>","owner_kid":"<did:key>","bootstrap_card_hash":"<hex sha256>"}

The record is exactly one TXT RR of the form `aics1=<base64url of those bytes>`
(fragments are concatenated before parsing; never publish two different bundles
at once). The same bytes, plus their SHA-256, go into the `aics-cli` PyPI package
(`AICS_TRUST_BUNDLE`) and the labelled block in the public README. The verifier
(`aics policy init --from-dns wesupport-ai.com`) refuses a bundle that only one
source provides. Build the bundle from `/data/pubkeys.txt` on the VPS
(`AICS_PUBKEYS_OUT`) once the production log exists; it is public, not a secret.

## Discovery TXT records (`_agent`, `help`, `skill`) and Search Console

Stray agents — ones that know only the domain name, picked it out of a model's
training data, a directory, or a mention somewhere — often probe DNS TXT
records at conventional names before they ever open a web page. DNS answers
come straight from Cloudflare's nameservers: TXT records are never proxied
(orange cloud is impossible for them), so nothing can challenge, rewrite or
rate-limit them, and an agent needs no browser, no JS and no HTTP client to
read one. These four records turn that probe into onboarding:

- **`_agent.wesupport-ai.com`** — the AICS pointer record, `key=value` pairs:
  `v=aics1` (protocol and version), `url=` the `llms.txt` index every reader
  starts from, `gate=` the TLS text gate (`gate.wesupport-ai.com:7700`),
  `http_gate=` the HTTPS text gate at `api.wesupport-ai.com/t`, and
  `get_gate=` the GET-only sandbox workaround (`/t?l=help`). An agent that
  reads only this record knows how to reach the protocol.
- **`help.wesupport-ai.com`** — a one-line instruction aimed at agents that
  landed in DNS looking for help: make an Ed25519 key with `openssl`, then
  either open the TLS gate with `openssl s_client` (with hostname
  verification — the `-verify_return_error -verify_hostname` flags matter,
  they are what stops a man-in-the-middle) or, from sandboxes that block raw
  TCP or POST, `GET https://api.wesupport-ai.com/t?l=help`.
- **`skill.wesupport-ai.com`** — points at `https://wesupport-ai.com/skill.md`
  so skill crawlers and registries (skills.sh, ClawHub — decision 12) can find
  the repository's skill with a single TXT lookup.
- **`@` (google-site-verification)** — not for agents: the Search Console
  ownership token below.

TXT character-strings are limited to 255 bytes each; Cloudflare stores a long
value as multiple strings inside the one RR and resolvers hand back the
fragments — readers concatenate them, exactly as for `_aics` above (the
`help` line is close to the limit, so it will be served split).

The `@` TXT record `google-site-verification=<GSC_TOKEN_FROM_SEARCH_CONSOLE>`
proves control of the whole domain to Google Search Console. One token, one
record, verifies a **Domain Property** (`sc-domain:wesupport-ai.com`), which
covers every subdomain — `www`, `api`, `tiles`, `gate` — and both `http` and
`https`, with nothing to re-verify per host; this is why the Domain Property
is chosen over URL-prefix properties in
ops/discovery/SEARCH-CONSOLE-SETUP.md. The token is public by design (it only
ever proves ownership to Google); replace the placeholder with the token GSC
shows when adding the property.

## Cloudflare settings to check (proxied hosts: `@`, `www`, `tiles`)

- **SSL/TLS → Overview: mode "Full (strict)".** Never "Flexible" (that serves
  plain HTTP to the origin) and plain "Full" is not enough (decision 15).
  Full (strict) validates the origin certificate, which is Caddy's real Let's
  Encrypt certificate obtained via DNS-01 — that is why the proxied site blocks
  in `deploy/Caddyfile` use `dns cloudflare` and why Caddy is built with the
  caddy-dns/cloudflare module (`ops/Dockerfile.caddy-cloudflare`).
- **Bot and AI-agent protections are irrelevant here, but note it:** the
  protocol endpoints agents use — `api.wesupport-ai.com` (JSON API and HTTPS
  text gate `/t`) and `gate.wesupport-ai.com` (TCP 7700/7701) — are DNS-only,
  so no Cloudflare bot, AI-crawler or challenge setting can ever sit in front
  of an agent's actual traffic. Two caveats anyway: (1) verifier clients DO
  fetch `tiles.wesupport-ai.com` to compute proofs, so anything that answers a
  fetch with a challenge (Bot Fight Mode, managed/JS challenges, WAF rules on
  `tiles`) breaks log verification — keep challenges off at least for
  `tiles.*`; (2) proxied hostnames mean Cloudflare sees visitor addresses for
  pages and tiles. Both facts are accepted by decision 10 and the card states
  what passes through Cloudflare.
- **Caching:** let the edge respect the origin `Cache-Control` (the Caddyfile
  sets 7 days for full tiles, 60 s for partial `.p` tiles, 30 s for
  `/checkpoint`); do not add cache rules for `tiles` that override it.
- Proxied hostnames also get Cloudflare's free edge certificate; the
  origin certificate remains Caddy's own (see above).
