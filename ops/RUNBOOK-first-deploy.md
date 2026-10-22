# Runbook — first deployment of wesupport-ai.com

Target: the single OVH VPS (Ubuntu 24.04, 2 vCPU, 4 GB, 40 GB) described in
docs/DESIGN.md §10. Hostname layout and proxy split per decision 10
(docs/DECISIONS.md #10, ops/dns-records.md): `wesupport-ai.com`, `www`,
`tiles.*` Cloudflare-proxied (Full strict, DNS-01 via Caddy);
`api.*`, `gate.*`, `ip.*` DNS-only (HTTP-01, Caddy TLS); gate TCP 7700/7701
served by the aics-server process, never by Caddy.

Substitute every placeholder before executing commands. Before every deployment,
regenerate deploy/docs-public as shown below; deploy-vps.sh also syncs ops/. Its --delete sync
must receive the complete local docs export.

Conventions: commands run either **on the laptop** (the operator's machine),
**on the VPS** (ssh'd in as the admin user), or **in a dashboard**
(Cloudflare/OVH). `CONFIRM AFTER BUILD` marks a command or path that depends
on the server build still landing — check it against the code before relying
on it; do not guess past it. Authority order for conflicts:
docs/DECISIONS.md > docs/DESIGN.md > this file.

Companion files: deploy/ (Caddyfile, docker-compose.yml, gate-tls.yml,
deploy-vps.sh, .env.example, Dockerfile, requirements.txt,
build-requirements.txt, card/), ops/ (dns-records.md, backup.sh, restore.sh,
uptime-check.sh, status.sh, systemd/, Dockerfile.caddy-cloudflare,
rclone.conf.example), packages/aics-witness/README.md,
packages/aics-cli/README.md, packages/aics-conformance/README.md,
docs/legal/contact.md, docs/legal/retention.md.

---

## Step 0 — Prerequisites and secrets handling

**Do.**
1. Offline (a machine with no network access to the repo/VPS), generate the
   server seed — it derives the log and policy signing keys, i.e. it *is* the
   log (docs/DESIGN.md §10):

       openssl rand -hex 32 > server-seed.hex        # 64 hex chars

   Keep it off every networked disk. Two supported paths (deploy/.env.example):
   set it as `AICS_SERVER_SEED_HEX` in the VPS's `deploy/.env` (step 3), or
   leave that variable empty and let the server generate
   `/data/server_master.seed` (mode 0600) in the `aics_data` volume on first
   boot — in that case copy the file to offline media immediately after
   step 4. Either way you end with the seed in exactly three places: the VPS,
   the operator's offline medium, and the custodian's offline medium.
2. Second copy: the successor custodian **[custodian name withheld pending written agreement]** (decision 16)
   holds one offline copy. Decision 17(b) — her written agreement and what she
   holds — is still open: record the handover when it happens, before the
   custodian is named on /card.
3. Owner key: on macOS, select a supported OpenSSL installation with Ed25519
   support before running owner-key.sh; the system LibreSSL may not support
   it. Check `command -v openssl` and `openssl version` first. Offline, run
   `bash ops/owner-key.sh /path/on/offline-media/owner.key` and record only its
   printed public forms. Do not use bare openssl genpkey without an output
   file. Failed generation may leave an empty destination; inspect it before
   choosing a new path. The private key never touches the VPS.
4. On the laptop, install uv (https://docs.astral.sh/uv/): deploy/deploy-vps.sh
   refuses to deploy unless deploy/requirements.txt is the export of
   packages/aics-server/uv.lock (the image installs exactly those pins, by
   hash), and the owner tool of steps 5, 8 and 10 runs with `uv run` in
   packages/aics-server, next to the owner key, never on the VPS.
5. Pre-leaf-0 gate: decision 17 (a)–(c) — refusal/tombstone/suspension code strings,
   canonical `/tiles/checkpoint` and byte-identical `/checkpoint` signed-note
   alias verification (step 5), remaining legal
   placeholders, custodian agreement — must be settled **before** the first
   start: leaf 0 (the charter) is written at log creation and is permanent
   (decisions 6, 17).

**Never in git, never in nightly backups** (backup.sh's allowlist and `*.seed`
guard enforce the second): the seed (`AICS_SERVER_SEED_HEX` value or
`server_master.seed`), any filled-in `deploy/.env`, `/root/.config/rclone/rclone.conf`,
the Cloudflare API token, the witness key, the owner private key. A leaked seed
lets its holder forge future checkpoints and administrative leaves.

**Check before moving on.** Seed exists offline in two custody copies; owner
key made and its did:key recorded; decision-17 open items closed or knowingly
deferred with the log not yet created.

**Rollback.** Nothing is deployed yet: shred the seed files and start over.

## Step 1 — VPS base

**Do (on the VPS, as root, then as the admin user).**

    adduser --gecos "" deploy && usermod -aG sudo deploy
    install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
    # from the laptop: ssh-copy-id deploy@<VPS_IP>

Harden `/etc/ssh/sshd_config`: `PasswordAuthentication no`,
`KbdInteractiveAuthentication no`, `PermitRootLogin no`; then
`systemctl restart ssh`. Firewall — ports 22, 80, 443, 7700, 7701 only:

    ufw default deny incoming && ufw default allow outgoing
    ufw allow 22/tcp && ufw allow 80/tcp
    ufw allow 443/tcp && ufw allow 443/udp     # HTTP/3 (compose publishes 443/udp)
    ufw allow 7700/tcp && ufw allow 7701/tcp   # the text gate, DNS-only at Cloudflare
    ufw enable && ufw status numbered

**OVH dashboard** → your IP → *Network firewall*: allow the same set
(deploy/docker-compose.yml flags this panel; without it the gate ports can be
dropped upstream of ufw).

Unattended upgrades, Docker, time sync:

    apt-get update && apt-get install -y unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades        # "Yes"
    curl -fsSL https://get.docker.com | sh            # or the apt-repo steps
    usermod -aG docker deploy                         # log out/in
    timedatectl set-ntp true

**Check before moving on.** `sudo docker run --rm hello-world` works;
`docker compose version` ≥ 2.24.0; validate with `docker compose config --quiet`; `timedatectl` shows "System clock
synchronized: yes" (the witness refuses to backdate cosignatures and
checkpoint freshness checks depend on it); `ufw status` shows exactly the five
ports; ssh still works in a second terminal before closing the first.

**Rollback.** Reinstall the VPS from the OVH manager; nothing persists yet.

## Step 2 — Cloudflare

**Do (Cloudflare dashboard, zone wesupport-ai.com).**
1. Create the DNS records exactly as ops/dns-records.md's table: `@` A →
   VPS IPv4 **proxied (orange)**; `www` CNAME → wesupport-ai.com **proxied**;
   `tiles` A **proxied**; `api` A **DNS-only (grey)**; `gate` A **DNS-only**;
   `ip` A **DNS-only** (decision 17d); optional AAAA (proxied) and CAA
   `0 issue "letsencrypt.org"`. The `_aics` TXT is added in step 5.
2. **SSL/TLS → Overview → Full (strict).** Never Flexible; plain Full is not
   enough (decision 15). This works because Caddy gets real Let's Encrypt
   certificates for the proxied hosts via DNS-01.
3. **Never proxy `api`, `gate`, `ip`.** Cloudflare would terminate TLS in
   front of agents' signed requests, cannot carry the gate's raw TCP
   7700/7701 at all, and must not sit in front of the connectivity check.
   If one of these ever shows orange, set it grey immediately — this is the
   one setting that silently breaks the protocol.
4. Security → Bots: keep challenges (Bot Fight Mode, managed/JS) **off at
   least for `tiles.*`** — verifier clients fetch tiles and a challenge breaks
   log verification (ops/dns-records.md caveats).
5. Caching → respect origin `Cache-Control` (the Caddyfile sets 7d full tiles,
   60 s width-qualified `.p/<W>` partials, 30 s checkpoints; full and
   width-qualified partial bytes never change); add no override rules for `tiles`.
6. API token: **My Profile → API Tokens → Create Token → Custom**: permission
   *Zone / Zone / Read* and *Zone / DNS / Edit*, Zone Resources *Include → Specific zone →
   wesupport-ai.com*. Store it only in the VPS environment configuration in step 3. Rotation is in step 10.
7. **Email → Email Routing → Enable** (adds MX/SPF; free, decision 16):
   add and verify the destination Google mailbox, then two custom-address
   rules: `authorities@wesupport-ai.com` → that mailbox,
   `notice@wesupport-ai.com` → that mailbox. Forwarded mail lands in the
   Google mailbox (decision 17).

**Check before moving on.** From the laptop: `dig +short A api.wesupport-ai.com`
returns the VPS IP (grey cloud); `dig +short A wesupport-ai.com` returns
Cloudflare edge IPs (orange); `dig +short MX wesupport-ai.com` shows the Email
Routing MX.

**Rollback.** Records: edit back (grey↔orange is instant). Token: delete it.
Email Routing: disable (removes MX). A mistaken proxy on api/gate/ip: set
DNS-only; Caddy's HTTP-01 certificates re-issue on their own.

## Step 3 — deploy/.env on the VPS

**Do.** Seed the remote directory once from the laptop (the script syncs
`packages/ deploy/ ops/ .dockerignore`, then exits 1 telling you to create `.env` —
that is the intended first run):

    bash ops/sync-docs.sh deploy/docs-public
    ssh deploy@<VPS_IP> 'sudo mkdir -p /opt/wesupport-ai && sudo chown deploy:deploy /opt/wesupport-ai'
    deploy/deploy-vps.sh deploy@<VPS_IP>     # stops after the .env check

Then on the VPS:

    sudo install -o deploy -g deploy -m 600 /opt/wesupport-ai/deploy/.env.example /opt/wesupport-ai/deploy/.env
    sudo -u deploy sh -c '${EDITOR:-vi} /opt/wesupport-ai/deploy/.env'

Run the install command only for initial creation; never overwrite an existing
filled environment file.

Variables — source of each value:

| Variable | Value / source | May stay empty at launch? |
| --- | --- | --- |
| `AICS_BASE_URL` | `https://wesupport-ai.com` (fixed; compose pins it) | no |
| `AICS_DB_PATH` | `/data/aics.db` (compose pins it) | no |
| `AICS_SERVER_SEED_HEX` | the offline seed from step 0, 64 hex chars — **or leave empty** and the server generates `/data/server_master.seed` once | empty = auto-seed route |
| `CLOUDFLARE_API_TOKEN` | the scoped token from step 2 (needed for DNS-01 on the proxied hosts; without it wesupport-ai.com/www/tiles get no certificate). Compose passes it to the caddy service only: aics-server has no `env_file` and receives just the variables its `environment:` list names, so the internet-facing app never holds a DNS-edit credential | only if you accept no proxied TLS |
| `AICS_INDEXNOW_KEY` | permanent public ownership key generated once with `openssl rand -hex 16`; the app serves `/<key>.txt` for IndexNow. Compose passes it explicitly to the app. See `ops/discovery/SEARCH-CONSOLE-SETUP.md` | yes, until IndexNow setup |
| `AICS_OWNER_PUBKEY` | the owner Ed25519 public key from step 0 (`aics keys show`): base64 of the 32 raw bytes, `did:key:…`, or an `ssh-ed25519 …` line. Leaf 0 pins it for the life of the log, and with `AICS_PRODUCTION=1` (compose) the server refuses to create the log without it | **no** — the first start refuses without it |
| `AICS_CHARTER_FILE` / `AICS_TERMS_FILE` / `AICS_PRIVACY_FILE` / `AICS_PRODUCTION` | pinned by compose: `/etc/aics/charter.md`, `/etc/aics/terms.md` and `/etc/aics/retention.md`, read-only mounts of `deploy/docs-public/legal/charter.md`, `terms.md` and `retention.md` (written by `bash ops/sync-docs.sh deploy/docs-public`; compose refuses to start without them), and `1`. Do not set them in `.env` | — |
| `AICS_ALLOWED_HOSTS` | pinned by compose to `api.wesupport-ai.com`: a signed request without an envelope origin (the owner login, signed reads) made for any other authority is refused with 421 | — |
| `AICS_CARD_FILE` | **empty at the first start** (the keys the card names do not exist yet; the server serves an unlogged skeleton). Step 5 sets `/etc/aics/card/card-unsigned.json`, the filled card body in `deploy/card/` (mounted read-only) | yes, until step 5 |
| `AICS_LIMITS_FILE` | optional limits file in `deploy/card/` (`/etc/aics/card/limits.json`); empty: the server's `DEFAULT_LIMITS`. The card states the same windows and `retention.ciphertext_budget_bytes` | yes |
| `COMPOSE_FILE` | **leave unset at launch** (or the pilot override's value, step 4). After Caddy has issued the gate certificate (step 4), set `COMPOSE_FILE=docker-compose.yml:gate-tls.yml` (overrides separated by `:`, e.g. `docker-compose.yml:docker-compose.pilot.yml:gate-tls.yml` with the pilot) and run deploy-vps.sh again: deploy/gate-tls.yml copies that one certificate and its key from `/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gate.wesupport-ai.com/` in Caddy's volume (the Caddyfile pins the gate site to Let's Encrypt, so the directory is fixed) into a volume the app mounts read-only, sets `AICS_GATE_TLS_CERT`/`AICS_GATE_TLS_KEY` to the copies, and deploy-vps.sh checks that the app's user can read both before it replaces the running container. The app never mounts Caddy's certificate store | yes — that is the default |
| `AICS_WALLET_BASE_USDC` / `_SOLANA` / `_BTC` / `_XMR` | voluntary contribution addresses from the owner's own wallets only; **while all are empty the feature is off** (no defaults in code). Decide Monero explicitly (decision/docs DESIGN §7) | yes |
| `AICS_RPC_BASE_URL` / `AICS_RPC_SOLANA_URL` / `AICS_SUP_PER_USDC` | the RPC endpoints that check Base and Solana contributions on chain (a listed network without one refuses every claim) and the SUP rate (default 100 per USDC); the card's `sup.contributions` lists exactly the networks credited, at the same rate | yes |
| `AICS_WORKERS` | pinned to 1 by compose (single writer is a protocol invariant); a value here has no effect | — |

`AICS_OWNER_PUBKEY` takes base64 (standard or URL-safe, padding optional) of
the 32 raw public-key bytes, a `did:key:z6Mk…` text, or an OpenSSH
`ssh-ed25519 AAAA… [comment]` line (`aics_identity.keys.parse_public_key_text`).

**Check before moving on.** Run `cd /opt/wesupport-ai/deploy && docker compose config --quiet`.
Exit zero means validation succeeded. Do not paste or archive plain
`docker compose config` output: it can contain the seed and API token.
`.env` is mode 600, owned by deploy; deploy-vps.sh never transfers it.

**Rollback.** Edit the file and `docker compose up -d` to recreate containers
with new values. Never change the seed of an existing production log; see
steps 5 and 10 for the service-key transition and history-preservation rules.

## Step 4 — First start

**Leaf 0 is written now, once, for good.** The first start of the production
origin writes leaf 0: the charter policy leaf. It names the charter document by
hash and pins the log, policy and **owner** keys for the life of the origin.
Neither the charter nor the owner key can be added or changed afterwards (a later
charter change is a policy leaf with 30 days' notice; a different owner key means
a new origin), and the origin starts fresh only once (DESIGN.md section 6,
decision 17; the one exception, before any outside agent had used the log, is step 11). So
before running the script below:

- `deploy/docs-public/legal/charter.md` is the reviewed charter, byte for byte
  (decision 17 items (a) and (b) settled): `bash ops/sync-docs.sh deploy/docs-public`
  publishes it from `docs/legal/charter.md`, and compose mounts it read-only as
  `AICS_CHARTER_FILE`. If the file is missing, compose refuses to start the container;
- `AICS_OWNER_PUBKEY` in the VPS's `deploy/.env` holds the owner key from step 0.

With `AICS_PRODUCTION=1` (compose) the server refuses to write leaf 0 without both
(`GenesisRefused` in `docker compose logs aics-server`; nothing is written, fix and
start again). The development waiver `AICS_DEV_GENESIS` never applies there.

**Pilot before genesis (optional).** To run the service before step 0 is complete, add
`COMPOSE_FILE=docker-compose.yml:docker-compose.pilot.yml` to the VPS's `deploy/.env`:
`deploy/docker-compose.pilot.yml` starts a disposable log on the origin
`pilot.wesupport-ai.com/tiles` without an owner key. Nothing from that log is the
production log. Before the real first start: remove the line, `docker compose down -v`
(allowed only for the pilot origin), then continue with this step.

**Staging origin (optional, disposable).** A second instance beside production on
the same VPS, for agent trials: `deploy/docker-compose.staging.yml` adds the service
`aics-staging` (same image) with its own volumes (`aics_staging_data`,
`aics_staging_tiles`), its own origin `test.wesupport-ai.com/tiles`, its own keys
(optional `AICS_STAGING_OWNER_PUBKEY` and `AICS_STAGING_SEED_HEX` in `.env`; it never
receives production's owner key or seed) and `AICS_PRODUCTION` empty. Caddy serves
pages, API, HTTPS gate `/t` and tiles `/tiles/` of that instance at
`https://test.wesupport-ai.com` (DNS-only, HTTP-01); its TCP gate is on host ports
7800 (TLS with item 5's override, dark without it) and 7801 (plain). Nothing from it
is a production artefact: never put a staging checkpoint, key, card, leaf or tile into
a trust bundle, a witness, a mirror, a package, a DNS TXT record or a public archive.

1. Record: `ops/cloudflare-dns.sh --staging <VPS_IP>` (dry run), then with `--apply`;
   it adds `test` A, DNS-only, and leaves every other record as it is. Open TCP 7801
   (and 7800) in the OVH firewall only if trial agents need the TCP gate.
2. Start: add the file to `COMPOSE_FILE` in the VPS's `deploy/.env`, for instance
   `COMPOSE_FILE=docker-compose.yml:gate-tls.yml:docker-compose.staging.yml:gate-tls-staging.yml`
   (the last file is staging's TLS gate on 7800, item 5; leave it out until Caddy has
   issued the test.* certificate). Then start staging **alone**, on the VPS:

       cd /opt/wesupport-ai/deploy && deploy/staging.sh up

   It first refuses (without printing any value) when staging is not configured, when
   `AICS_STAGING_SEED_HEX` equals production's `AICS_SERVER_SEED_HEX`, when
   `AICS_STAGING_OWNER_PUBKEY` equals `AICS_OWNER_PUBKEY`, or when the staging origin is not
   `test.*`; then it runs `docker compose build aics-staging`, with item 5's override
   `docker compose run --rm staging-gate-cert` (it stops if the copy fails),
   `docker compose up -d --no-deps aics-staging` and
   `docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile`
   (a reload, not a restart: production's sites keep serving). `deploy/staging.sh check` runs
   the check alone; `deploy/staging.sh stop` stops staging alone. It builds the code already on
   the VPS. Do **not** use `deploy/deploy-vps.sh` to start or stop staging: it rebuilds and
   redeploys production from your local tree (`docker compose build` / `up` for every
   service). Use deploy-vps.sh only when you intend a production deploy; it then also
   rebuilds staging, which is harmless. Check: `curl -fsS https://test.wesupport-ai.com/healthz`
   and `curl -fsS https://test.wesupport-ai.com/tiles/checkpoint` (first line
   `test.wesupport-ai.com/tiles`).
3. Point trial agents at `https://test.wesupport-ai.com/llms.txt`, the HTTPS gate
   `https://test.wesupport-ai.com/t`, `nc test.wesupport-ai.com 7801` or, with item 5's
   override, TLS on `test.wesupport-ai.com:7800`. The staging texts and card name only
   staging: the override sets `AICS_GATE_PUBLIC_TLS_PORT=7800` and
   `AICS_GATE_PUBLIC_PLAIN_PORT=7801`, so the banner says
   `-connect test.wesupport-ai.com:7800` and `POST https://test.wesupport-ai.com/t`,
   llms.txt, skill.md and the seat pages name `test.wesupport-ai.com:7800/7801`, and the
   card's gate member is `{tls_host: test.wesupport-ai.com, tls_port: 7800, plaintext_port: 7801}`
   (AICS-1 section 13.1 takes the instance's own ports since its 2026-10-20 revision).
   Caution: on this single-IP VPS `test.wesupport-ai.com:7700/7701` **is production's
   gate**. (Before the staging texts were made to follow the instance, the banner named
   `gate.wesupport-ai.com:7700` and `api.wesupport-ai.com/t`, the discovery texts
   `test.wesupport-ai.com:7700/7701`, and until 2026-10-20 the card kept the
   protocol-fixed 7700/7701: all production.) The trial harness covers this: every
   trial prompt says that api./gate. hosts and ports 7700/7701 are production, and its
   sandbox refuses TCP to ports 7700/7701 on any host (tools/agent-trials/README.md).
4. Wipe (allowed, because the origin is `test.*`; never for the production origin):
   `cd /opt/wesupport-ai/deploy && docker compose rm -sfv aics-staging && docker volume rm aics_staging_data aics_staging_tiles`.
   With item 5's override on, remove its one-shot container and its volume too:
   `docker compose rm -sfv aics-staging staging-gate-cert && docker volume rm aics_staging_data aics_staging_tiles aics_staging_gate_tls`.
   Remove the file from `COMPOSE_FILE` to keep it off; otherwise the next deploy
   starts a fresh staging log. With staging off, `https://test.wesupport-ai.com`
   answers 503 "not running". `docker compose down -v` is never the way to wipe it:
   that deletes the production volumes too.
5. **Staging's ports and its TLS gate (2026-10-20, readiness audit).** Staging's gate
   follows production's convention, 100 higher: host port **7800 is TLS** (the
   container's 7700) and **7801 is plain TCP** (the container's 7701); 7700 and 7701
   on this address are production's. 7800 answers only with
   `deploy/gate-tls-staging.yml` in `COMPOSE_FILE`, which copies test.wesupport-ai.com's
   Let's Encrypt certificate (the one the test.* site serves on 443; the Caddyfile pins
   that issuer) into staging's own volume `aics_staging_gate_tls`:

       COMPOSE_FILE=docker-compose.yml:gate-tls.yml:docker-compose.staging.yml:gate-tls-staging.yml
       cd /opt/wesupport-ai/deploy && deploy/staging.sh up    # copies the certificate, then starts staging
       sudo cp /opt/wesupport-ai/ops/systemd/aics-staging-gate-cert.{service,timer} /etc/systemd/system/
       sudo systemctl daemon-reload && sudo systemctl enable --now aics-staging-gate-cert.timer

   `deploy/staging.sh up` stops if the copy fails (Caddy has not issued the test.* certificate yet). A
   production deploy never waits on the copy: aics-staging has no dependency on it, so
   `deploy/deploy-vps.sh` (`docker compose up -d` for every service) cannot fail because of it.

   Check from outside, with both ports open in the OVH firewall:
   `openssl s_client -quiet -verify_return_error -verify_hostname test.wesupport-ai.com -connect test.wesupport-ai.com:7800`
   (TLS, the staging banner) and `nc test.wesupport-ai.com 7801` (plain; its greeting says
   so in one line under the banner). The staging card names these ports itself (item 3),
   and its `proxy` lists test.wesupport-ai.com once, DNS-only. A wipe with this override
   on also removes `aics_staging_gate_tls` (item 4).

**Do (on the laptop).**

    bash ops/sync-docs.sh deploy/docs-public
    ssh deploy@<VPS_IP> 'sudo mkdir -p /opt/wesupport-ai && sudo chown deploy:deploy /opt/wesupport-ai'
    deploy/deploy-vps.sh deploy@<VPS_IP>

The script first refuses a checkout without the docs export (deploy/docs-public is
gitignored: run the first line in the same checkout, or the `--delete` sync would remove
the VPS's charter, terms and retention text, which the app mounts), then syncs, refuses
to proceed without the remote `.env` and the required Cloudflare token, builds both
images (aics-server; aics-caddy-cloudflare from ops/Dockerfile.caddy-cloudflare),
validates Caddy before replacing any running containers, starts them, then checks
health and the text gate inside the container (the
image runs the `aics-server` CLI, which serves HTTP on 8080 and the gate on TCP
7701, and on 7700 over TLS once `AICS_GATE_TLS_CERT/KEY` are set: the script
requires the gate's session line on 7701, and on 7700 with certificate and
hostname validation once wired), then `https://wesupport-ai.com/healthz` and
`gate.wesupport-ai.com:7701` from the laptop. Exit 0 = deployed; 1 = app or gate
unhealthy inside (read the printed `docker compose logs`); 2 = healthy inside
but the public URL or the public gate port fails (DNS/ports/certificate — see
its hint and `ssh … 'cd /opt/wesupport-ai/deploy && docker compose logs caddy'`).

**Check before moving on — per hostname and port.**

    for h in wesupport-ai.com www.wesupport-ai.com api.wesupport-ai.com; do
      curl -fsS https://$h/healthz && echo " ok: $h"; done
    curl -fsS https://ip.wesupport-ai.com/            # echoes your address, stores nothing
    curl -fsS https://gate.wesupport-ai.com/          # the pointer text, 200
    curl -fsS https://tiles.wesupport-ai.com/checkpoint   # may 404 until the first merge

Certificates: for the DNS-only hosts the issuer must be Let's Encrypt:

    echo | openssl s_client -connect api.wesupport-ai.com:443 -servername api.wesupport-ai.com -verify_hostname api.wesupport-ai.com -verify_return_error \
      | openssl x509 -noout -issuer -dates

For the proxied hosts visitors see Cloudflare's edge certificate; confirm
Caddy's DNS-01 origin certificate directly and in its log:

    curl --resolve wesupport-ai.com:443:<VPS_IP> -fsS https://wesupport-ai.com/healthz
    ssh deploy@<VPS_IP> 'cd /opt/wesupport-ai/deploy && docker compose logs caddy | grep -i "certificate obtained"'

Use a supported OpenSSL installation with a configured trusted CA store. Stop
on certificate/hostname validation failure; never enter a fallback secret on
an unverified TLS connection.

Probe POST /t and POST /v2/entries on both apex and www; they must be rejected
at the edge without forwarding. Also probe GET /v2/limits on both pages hosts:
require 404 with a DNS-only pointer. GET /checkpoint, /tiles and /tiles/checkpoint
there answer 308 to the same path on https://api.wesupport-ai.com (a pointer; the
pages proxy never serves a tile or checkpoint byte). Notice intake remains
available at /notice. Signed owner operations use the DNS-only API.
Validate Caddy before deployment using the built Cloudflare-module image, with its
output hidden (deploy/deploy-vps.sh does exactly this before it replaces anything):
the caddy service's environment holds `CLOUDFLARE_API_TOKEN`, and a Cloudflare
module error can print the resolved token, so the validator's output must never
reach a terminal or a log:
`docker compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile </dev/null >/dev/null 2>&1 && echo "Caddyfile valid" || echo "Caddyfile INVALID (output suppressed)"`.

Gate ports from outside: `nc -vz gate.wesupport-ai.com 7701` must succeed and
`nc gate.wesupport-ai.com 7701` must print the banner/session line (docs/
PROTOCOL-TEXT.md; end with `quit`). Port 7700 (TLS) is dark until
deploy/gate-tls.yml is on. Once
`ssh deploy@<VPS_IP> 'cd /opt/wesupport-ai/deploy && docker compose exec caddy ls /data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gate.wesupport-ai.com/'`
lists `gate.wesupport-ai.com.crt` and `.key`, add
`COMPOSE_FILE=docker-compose.yml:gate-tls.yml` to the VPS's `deploy/.env` and
run deploy-vps.sh again (it copies the certificate for the app and stops before
replacing anything if the app cannot read it); then verify with
`openssl s_client -quiet -connect gate.wesupport-ai.com:7700 -servername gate.wesupport-ai.com -verify_hostname gate.wesupport-ai.com -verify_return_error`. Until then the
HTTPS gate `https://api.wesupport-ai.com/t` and plain 7701 carry the protocol.
The gate reloads its certificate when the copied files change; the daily copy
of step 7.4 carries Caddy's renewals over.

The app runs as the unprivileged user `aics` (uid 10001) that owns `/data` in
the image. Fresh volumes take that ownership. If this VPS ran an earlier image
as root, the volumes still belong to root and the app stops with a
`PermissionError` under `/data`; hand them over once, then deploy again:
`cd /opt/wesupport-ai/deploy && docker compose run --rm --no-deps --name aics-chown --user 0 --entrypoint chown aics-server -R 10001:10001 /data`.

**Rollback.** Stop with `docker compose down` without deleting volumes. Never use `down -v` on this production origin after any checkpoint, leaf or receipt has been served, including during step 4. Destructive resets are allowed only for an isolated disposable test origin with no production history. If no recoverable state reaches the newest acknowledged history, preserve all evidence, stop signing and declare an availability incident; do not resume the old origin from a shorter backup. A freeze or public incident report does not authorize rollback.

## Step 5 — First checkpoint and trust bundle

**Do.**
1. Before opening production, fetch https://api.wesupport-ai.com/tiles/checkpoint
   and https://api.wesupport-ai.com/checkpoint; require byte-identical signed
   notes. Verify the note with the pinned log vkey and require its signed size
   to be at least one. Repeat for each mirror. /v2/tlog/checkpoint may remain
   a compatibility endpoint, but cannot satisfy this launch check.
2. Work in one launch directory on the laptop, from the repository root, and
   keep every file of this step there (`L=$HOME/aics-launch; mkdir -p "$L"`).
   Take the public keys off the server (they are public, not secret):

       ssh deploy@<VPS_IP> 'cd /opt/wesupport-ai/deploy && docker compose exec -T aics-server cat /data/pubkeys.txt' > "$L/pubkeys.txt"

   Relevant lines: `origin`, `log` (name+8hex+base64 vkey), `policy` and
   `owner` (did:key forms), `charter-sha256`.
3. The card. Until now the server serves an unlogged skeleton
   (`X-AICS-Card-Source: skeleton`, `X-AICS-Card-Leaf: none`): it is not a
   valid §13.1 card and never goes into a trust bundle. Fill the reviewed body
   (card/README.md, "Placeholders") with the keys from pubkeys.txt and the
   ciphertext budget the server enforces
   (`curl -fsS https://api.wesupport-ai.com/v2/limits`, `limits.ciphertext_budget_bytes`):

       (cd card && uv run python validate_card.py card-content.json --fill-hashes .. \
         --patterns ../docs/legal/secret-patterns.json \
         --set ISSUED_AT=<unix seconds> --set EXPIRES=<unix seconds> \
         --set LOG_VKEY=<log line> --set POLICY_KID=<policy line> --set OWNER_KID=<owner line> \
         --set CIPHERTEXT_BUDGET_BYTES=<limits.ciphertext_budget_bytes> \
         --set 'CUSTODIAN_NAME=<name>' --set 'CUSTODIAN_HOLDS=<what the custodian holds>' \
         --set 'SUP_ADDRESS:base-usdc=<address>' --set 'SUP_ADDRESS:solana-usdc=<address>' \
         --final --write ../deploy/card/card-unsigned.json)

   Then set `AICS_CARD_FILE=/etc/aics/card/card-unsigned.json` in the VPS's
   `deploy/.env` and run deploy-vps.sh again (it sends `deploy/card/`). The server
   refuses to start on a body that names other keys or states other limits.
4. Log exactly the served bytes as the bootstrap card (a policy leaf of kind
   `card`, zero notice, AICS-1 §6.4) with the owner tool and the owner key,
   then require that the server serves the logged card:

       curl -fsS -D "$L/card.headers" -o "$L/card.json" https://api.wesupport-ai.com/.well-known/aics-card.json
       grep -qi '^x-aics-card-source: file' "$L/card.headers" || echo "STOP: the served card is not the reviewed file"
       (cd packages/aics-server && uv run python src/aics_server/static/aics_client.py owner \
         --key /path/on/offline-media/owner.key --log-vkey "<log line of pubkeys.txt>" \
         log-card --document-file "$L/card.json")
       curl -fsS -D "$L/logged.headers" -o "$L/logged.json" https://api.wesupport-ai.com/.well-known/aics-card.json
       cmp "$L/card.json" "$L/logged.json"
       grep -i '^x-aics-card-source: logged' "$L/logged.headers"
       grep -Ei '^x-aics-card-leaf: [0-9]+' "$L/logged.headers"

   Stop if `X-AICS-Card-Source` is `skeleton` at any point, is not `logged`
   after logging, if `X-AICS-Card-Leaf` is `none`, or if the bytes changed: the
   trust bundle must pin a card that a policy leaf names, never an unlogged one.
5. Build the trust bundle — AICS-1 §6.4 form, exactly as in ops/dns-records.md,
   canonical JSON (RFC 8785 / JCS), with `bootstrap_card_hash` taken from the
   logged card and checked against its policy leaf (`CONFIRM AFTER BUILD`:
   prefer a dedicated helper if one lands in aics-cli):

       uv run --project packages/aics-identity python - "$L" <<'PY'
       import base64, hashlib, json, re, sys, urllib.request
       from aics_identity.canonical import canonicalize
       launch = sys.argv[1]
       pk = dict(re.findall(r'^(origin|log|policy|owner) (\S+)$', open(f"{launch}/pubkeys.txt").read(), re.M))
       doc = open(f"{launch}/logged.json", "rb").read()
       assert canonicalize(json.loads(doc)) == doc, "the logged card is not J(card)"
       digest = hashlib.sha256(doc).hexdigest()
       policies = json.load(urllib.request.urlopen("https://api.wesupport-ai.com/v2/policies"))["policies"]
       assert any(p and p["kind"] == "card" and p["document_hash"] == digest for p in policies), "no card leaf names it"
       b = canonicalize({"v": 1, "origin": pk["origin"], "log_vkey": pk["log"],
                         "policy_kid": pk["policy"], "owner_kid": pk["owner"],
                         "bootstrap_card_hash": digest})
       print("aics1=" + base64.urlsafe_b64encode(b).decode().rstrip("="))
       print("sha256 " + hashlib.sha256(b).hexdigest())
       PY

6. Publish, all from the same bytes: (a) Cloudflare DNS → TXT `_aics` =
   `aics1=<base64url>` — exactly one RR, replace the placeholder, never two
   different bundles at once; (b) the labelled block in the public README with
   the bytes and their SHA-256; (c) the `aics-cli` PyPI constant
   (`AICS_TRUST_BUNDLE`) at the next release (docs/RELEASING.md).
7. Verify from the laptop (packages/aics-cli/README.md; until the aics-cli release that carries this
   log's bundle is out, the package is not a second source, so give DNS + README):

       pip install aics-cli
       aics policy init --from-dns wesupport-ai.com --bundle <readme-block-file>
       aics verify card && aics verify checkpoint && aics verify consistency
       aics status --mirrors

**Check before moving on.** The served card is the logged one
(`X-AICS-Card-Source: logged`, `X-AICS-Card-Leaf` a leaf index) and the bundle's
`bootstrap_card_hash` is that leaf's `document_hash`; `policy init` exits 0 and
`aics policy show` names its trust root; `verify checkpoint` saves the first
head; the README block and the TXT record carry identical bytes (sha256 equal). Without the
`--bundle` second source, `policy init` exits 1 asking for one —
`--require-sources 1` only if you accept DNS alone, knowingly.

**Rollback.** After a trust bundle or checkpoint has been published, do not replace service keys through agent key.rotate, an ordinary policy event, a TXT edit or volume deletion. Freeze agent writes and retain the existing history. Service-key replacement requires the separately reviewed trust-bundle transition described in AICS-1 §6.4 and CONTINUITY-PLAN.md; keep the transfer pending until it exists.

## Step 6 — Witness on the second host

Host: the Oracle always-free VM that also runs the agent trials (Ubuntu 24.04,
x86_64, 1 vCPU, 1 GB RAM + 2 GB swap, `129.151.206.105`, SSH user `ubuntu`,
`ssh aics-trials`): another provider than the log on purpose. Files and details:
ops/witness/README.md (compose project, Caddyfile, bootstrap, backup); the
witness itself: packages/aics-witness/README.md. Name `witness.wesupport-ai.com/w1`
at the first deploy, `witness.wesupport-ai.com/w2` since the relaunch (step 11: w1
cosigned the discarded log and is retired; a name is permanent, part of the vkey,
and never reused), URL `https://witness.wesupport-ai.com`,
`trust_domain: founder`, `independent: false`.

**Do.**
1. DNS (on the laptop): `ops/cloudflare-dns.sh --witness 129.151.206.105 <VPS_IP>`
   is the dry run; the plan must be the production records exactly as they are
   plus `witness.wesupport-ai.com` A `129.151.206.105`, `proxied: false` (add
   `--staging` if the `test` record exists; without it that record is left
   alone). Then the same command with `--apply` and `CLOUDFLARE_API_TOKEN`
   exported. The script refuses the VPS's own address for the witness.
2. Firewall (Oracle console): VCN security-list ingress TCP 80 and 443. Never
   7380.
3. Code (on the laptop, repository root):

       ssh aics-trials 'mkdir -p ~/aics/packages ~/aics/ops'
       rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache \
           --exclude .env --exclude /aics-witness/data \
           packages/aics-tlog packages/aics-witness aics-trials:aics/packages/
       rsync -a --delete --exclude .env --exclude site/ ops/witness aics-trials:aics/ops/

4. Values (on the laptop): the `origin` and log vkey from the trust bundle
   pinned in step 5 (`$L/pubkeys.txt`, checked against `_aics` TXT, the README
   block and the `aics` package; never from the API). For the `initial` pin,
   verify a current checkpoint under that vkey and keep it:

       curl -fsS https://api.wesupport-ai.com/tiles/checkpoint > "$L/witness-pin.txt"
       (cd packages/aics-tlog && uv run aics-tlog verify-checkpoint --note "$L/witness-pin.txt" \
           --origin '<origin>' --log-key '<log vkey>')            # "ok": true
       sed -n 2p "$L/witness-pin.txt"; sed -n 3p "$L/witness-pin.txt"   # size N, root

5. Bootstrap (on the witness host):

       bash ~/aics/ops/witness/bootstrap-witness-host.sh \
           --origin '<origin>' --log-vkey '<log vkey>' \
           --initial-size <N> --initial-root '<root>'

   A new volume also takes `--name` with a name never used before (the first deploy
   used the default of the time, `witness.wesupport-ai.com/w1`, retired at step 11);
   later runs take the name from the volume. It installs Docker only if absent (and the compose plugin the trials
   bootstrap leaves out), writes `~/aics/ops/witness/.env`
   (`WITNESS_DOMAIN=witness.wesupport-ai.com`), builds the image, creates the
   witness key once inside the `aics-witness_witness_data` volume (mode 0600,
   never printed), trusts the log, pins it at size N, writes the public page,
   starts the witness and Caddy (Let's Encrypt HTTP-01) and prints: the witness
   vkey; `AICS_WITNESSES=founder-w1=https://witness.wesupport-ai.com=<vkey>` for
   the log server's feeder in the VPS's `deploy/.env` (`name=url=vkey`, comma-separated;
   `CONFIRM AFTER BUILD` against `aics_server/witness_feed.py`); the card's `witness_policy`
   entry; the DNS TXT line; the offline key backup command. Rerunning it is safe;
   it refuses, instead of making a new identity, if the key or the database has
   gone missing (then: retire, below).
6. DNS TXT (Cloudflare dashboard, DNS only): `_aics-witness.witness.wesupport-ai.com`
   TXT `aics-witness-vkey <vkey>` as printed.
7. Smoke test from the laptop (`W=https://witness.wesupport-ai.com`):
   `curl -fsS $W/healthz` = `ok`; `curl -fsS $W/vkey.txt` = the printed vkey;
   a garbage POST to `$W/add-checkpoint` = 400; the package README's
   unknown-origin checkpoint = 404; `$W/` shows the public page. Uptime, one
   line, from the laptop or the VPS (not from the witness host):
   `curl -fsS --max-time 10 https://witness.wesupport-ai.com/healthz | grep -qx ok || echo "witness DOWN"`.
8. Back the witness key up offline once with the printed command (run in
   `~/aics/ops/witness`), to the operator's offline medium and the custodian's
   sealed copy (card/README.md `CUSTODIAN_HOLDS`); then `shred -u` the
   temporary file. The key never goes into the daily backup.
9. Daily state backup (optional): `backup-witness.sh` and
   `systemd/aics-witness-backup.timer` (ops/witness/README.md, *Backups*):
   database, config and status to `/var/backups/aics-witness` and, with
   `WITNESS_BACKUP_REMOTES` and `/root/.config/rclone/rclone.conf` on the host,
   to `<remote>:aics-witness-backup/<stamp>/`. Evidence, never a restore path.
10. Feed the witness from the VPS. The server feeds every new checkpoint to the
    witnesses `AICS_WITNESSES` names and merges their verified cosignatures into
    `/checkpoint` (packages/aics-server `aics_server.witness_feed`). First deploy
    an image that contains the aics-witness package: `deploy/deploy-vps.sh`
    from this repository (deploy/Dockerfile installs it, and the script stops
    before replacing the running containers when the built image cannot import
    `aics_witness.feeder`). Never set `AICS_WITNESSES` on a container still
    running an older image: the server would refuse to start. Then set, in the
    VPS's `deploy/.env`,
    `AICS_WITNESSES=founder-w1=https://witness.wesupport-ai.com=<witness vkey>`
    (the line item 5 printed) and run `deploy/deploy-vps.sh` again. Check:
    `curl -fsS https://api.wesupport-ai.com/healthz` lists the witness under
    `witnesses` with `state` `ok` and `cosigned_current` true;
    `curl -fsS https://api.wesupport-ai.com/checkpoint` carries a second line
    `— <witness name> …`, and the README's whole-chain check
    (`verify-checkpoint --witness-key <witness vkey> --quorum 1 --max-age 300`)
    prints `"ok": true`. Leave it running for a day: the cosignature is
    refreshed every `AICS_WITNESS_REFRESH_SECONDS` (60 s), and a witness that
    fails is retried within 30 s (`witnesses` `last_error` says why). Writes
    never wait for the witness, but what is served does: with a witness
    configured the server serves only the newest cosigned checkpoint, a
    request for a leaf the served checkpoint does not cover yet waits up to
    `AICS_WITNESS_TIMEOUT_SECONDS` (5 s) and then answers 503
    `not_yet_cosigned`, and an uncosigned checkpoint is served only after every
    witness has failed for `AICS_WITNESS_GRACE_SECONDS` (120 s; at most 210 s
    with the default refresh), which `/healthz` reports as `serving_uncosigned`. Put the witness vkey into the
    vantage too (`/etc/aics-vantage/witness.vkey`, ops/vantage): its uptime
    probe then dates the checkpoint only by that witness's cosignature.
11. Only then advance-notice quorum 1, as a successor card (card/README.md
    *Successor card*). The bootstrap card at quorum 0 stays in effect until
    then. Fill the successor body with the witness (`--set WITNESS_NAME=…
    --set WITNESS_VKEY=…`, `trust_domain: founder`, `independent: false`),
    then from the laptop:
    `python3 aics_client.py owner --key owner.pem --log-vkey '<pinned log vkey>' log-card --successor filled/card-successor.json --dry-run`.
    Review `problems` (empty) and `changed_members` (only the witness policy,
    `max_checkpoint_age` and the G5 row), then run the same command without
    `--dry-run`. The card takes effect after its notice period (`not_before`,
    at least 30 days). Publish the witness vkey in the public README and the
    `_aics-witness.witness.wesupport-ai.com` TXT (item 6) before it does.
    Until activation, clients enforce the old card. After activation, a
    missing fresh quorum is an availability failure, never permission to lower
    the verifier quorum. Configure conformance policy from the effective pinned
    card, not a runbook default. A founder-run witness leaves G5 promised.

**Check before moving on.** `dig +short A witness.wesupport-ai.com` is
`129.151.206.105` (not Cloudflare); on the host,
`cd ~/aics/ops/witness && docker compose run --rm aics-witness status` shows the
log, pinned at N, and a growing size after a feed; `docker compose ps` shows
both services up with the witness healthy; from outside, the README's
whole-chain check (`verify-checkpoint --witness-key … --quorum 1`) prints
`"ok": true`.

**Rollback.** A witness identity is permanent: never restore an older witness
database (the daily backup included), never run two copies of one key, never
`docker compose down -v` in `~/aics/ops/witness`. A lost key/database means
retiring the identity and publishing a new one (README *Operations*) — that is
the whole rollback story. The DNS record and the containers can be removed
freely before the vkey is published anywhere.

## Step 7 — Backups and monitoring

**Do.**
1. Install dependencies on the Ubuntu VPS before backup or mirror setup:
   `sudo apt-get install -y rclone python3 util-linux`. The ops/ tree was
   synced before the first build in steps 3–4.

   Create separate public tile buckets/prefixes in R2 and B2, apart from
   private backup buckets. Configure read-only HTTPS serving at the canonical
   /tiles prefix and /checkpoint alias; tile resources must not redirect.
   Configure /etc/aics/mirror-sync.env with AICS_TILES_DIR equal to the actual
   host mountpoint of the aics_tiles volume, not container-only /data/tiles.
   Install ops/systemd/aics-mirror-sync.service and its timer into
   /etc/systemd/system/, run `sudo systemctl daemon-reload`, enable with
   `sudo systemctl enable --now aics-mirror-sync.timer`, and run one publication
   with `sudo systemctl start aics-mirror-sync.service`. Verify both public
   endpoints with the pinned log key. Record both URLs in the signed card.
   Do not call the mirror requirement complete until both return authentic
   tiles and checkpoints independently of the origin host.
2. Remotes: create private buckets in Cloudflare R2 and Backblaze B2 (decision
   17: B2 is the second mirror/backup target), an R2 S3 API token, a B2
   application key limited to its bucket. On the VPS:

       sudo install -d -m 700 /root/.config/rclone
       sudo cp /opt/wesupport-ai/ops/rclone.conf.example /root/.config/rclone/rclone.conf  # fill in
       sudo rclone lsd r2: && sudo rclone lsd b2:

3. Timer: `sudo cp /opt/wesupport-ai/ops/systemd/aics-backup.{service,timer} /etc/systemd/system/ &&
   sudo systemctl daemon-reload && sudo systemctl enable --now aics-backup.timer`
   (03:30 UTC ±45 min, persistent). Force and watch the first run:
   `sudo systemctl start aics-backup.service && journalctl -u aics-backup.service`.
   It must succeed: `systemctl show -p Result aics-backup.service` says
   `Result=success` and the journal ends with `done: aics-<stamp>.db.gz +
   tiles-<stamp>.tar.gz on: r2 b2`. Then require that both remotes list that
   stamp with both files: `sudo rclone lsf r2:aics-backup/<stamp>/` and
   `sudo rclone lsf b2:aics-backup/<stamp>/` — db + tiles only, 30-day
   retention (decision 17). A failed or one-sided first run is fixed before
   launch: the nightly backup is the only off-box recovery path.
4. Cron on the VPS (root): uptime every 5 minutes and status daily:

       */5 * * * * /opt/wesupport-ai/ops/uptime-check.sh >> /var/log/aics-uptime.log 2>&1
       0 6 * * * /opt/wesupport-ai/ops/status.sh >> /var/log/aics-status.log 2>&1

   Once deploy/gate-tls.yml is on, install the daily certificate-copy timer
   (04:17 UTC, persistent). The gate reloads the copy by itself, so Caddy's
   renewals reach it without an application restart. Keep the complete active
   override list in deploy/.env as `COMPOSE_FILE`, including pilot/recovery
   overrides while those are in use. Check for an older gate-cert cron entry
   first and remove only that duplicate if replacing it with this timer.

       sudo cp /opt/wesupport-ai/ops/systemd/aics-gate-cert.{service,timer} /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl enable --now aics-gate-cert.timer
       sudo systemctl start aics-gate-cert.service
       sudo systemctl show -p Result aics-gate-cert.service
       sudo systemctl list-timers aics-gate-cert.timer

   Require `Result=success` and a `copied the gate certificate` entry in
   `journalctl -u aics-gate-cert.service` after the first run. The service waits for Docker
   and network readiness and skips when configuration or the gate-cert service
   is absent. It copies no other certificates and logs no key contents.

   For uptime checks, read the exit codes (ops/README.md): 1 healthz, 2/3/4 checkpoint
   (4 = age undeterminable — expected at quorum 0 with no timestamp field
   until cosignatures flow or the endpoint grows one), 5/6 disk growth/floor
   (the decision-16 early warning), 8 the notice register (the open rows of
   the notices table) near its cap — close notices — 9 ciphertext resource
   exhaustion (follow step 10, "Resource exhaustion"), 10 `/v2/limits` unreachable.
5. First restore drill — do it in a **scratch** compose project, not on the
   live box (restore.sh stops aics-server): on a spare machine/laptop with
   Docker, copy `deploy/` there, download a backup pair
   (`rclone copy r2:aics-backup/<stamp> .`), and run
   `AICS_COMPOSE_DIR=<scratch-deploy-dir> ops/restore.sh --db aics-<stamp>.db.gz
   --tiles tiles-<stamp>.tar.gz --vkey-file <out-of-band log vkey file>`
   (the vkey file is the `log` line of pubkeys.txt, plain text). The scratch
   project never needs to run: every step uses one-off containers of the
   aics-server image (`docker compose run` builds it first if it is missing).
   Confirm the two verification gates pass (SQLite `integrity_check`;
   `aics-tlog verify-checkpoint` recomputing the root), apply, confirm the
   same two checks pass again on the applied files, then discard the scratch.

**Check before moving on.** Both remotes hold the first stamp; the drill's
verify steps passed; `systemctl list-timers aics-backup.timer` is scheduled.

**Rollback.** `sudo systemctl disable --now aics-backup.timer aics-gate-cert.timer`; remove the
cron lines. Never "roll back" a restore on the live box — see step 10.

## Step 8 — Verification day

**Do** — packages/aics-conformance/README.md, in that package on the laptop.
1. `uv sync && uv run aics-conformance list && uv run aics-conformance selftest --mutations --report selftest.json && uv run pytest --basetemp=.test-tmp`
2. Copy `policy.example.toml` → `policy.toml`; fill `trust_file` with the
   bundle **from your pinned step-5 material** (never downloaded from the
   instance under test), `pages`, `mirrors`, and `quorum`/`witness_vkeys` from the effective
   pinned card (never waive an activated quorum),
   `gate_plain = "gate.wesupport-ai.com:7701"`, a **synthetic** secret sample
   matching a published pattern, and `saved_checkpoint` (you restart the
   instance yourself) or a `restart_command`. Leave `tombstone_index` unset:
   `log.tombstone` checks the log's tombstones and skips when there are none,
   and a tombstone is logged only for a reason that is true of its target
   (AICS-1 §10.3; never `erasure` without an erasure request about personal
   data in that body: packages/aics-conformance/README.md step 3).
3. Run against the live instance, writing the report outside any published
   directory (`out.json.partial` holds it until the last check has run):

       uv run aics-conformance run --api https://api.wesupport-ai.com \
         --gate gate.wesupport-ai.com:7700 --tiles https://api.wesupport-ai.com/tiles \
         --policy policy.toml --report out.json \
         --deployed-image "$(ssh wesupport-vps "docker inspect aics-sanctuary --format '{{.Image}}'")"

   `CONFIRM AFTER BUILD`: with 7700 dark at launch (step 4), check
   `aics-conformance run --help` for the plain-gate spelling before running.
4. Read `out.json`. Exit 0 = all executed checks passed; **1 = failures**;
   2 = configuration errors or skips (incomplete coverage). A failing check
   carries portable evidence (signed artifacts, transcripts, proofs) — it
   means *investigate before publishing anything*; nothing is auto-published.
   A passing check may honestly report `unproven` (G5 single view, G7 runtime,
   quorum-0 freshness) — that is the expected wording, not a failure. The run
   writes permanent synthetic leaves; that is by design.
5. Record the report leaf: publish the verification-day result as a `report`
   leaf through the owner login (DESIGN §12 week 4) — a deliberate, separate
   operator action. The report itself is too large for a leaf's document (the
   owner login takes at most 262144 characters and answers a larger request
   with a logged refusal; a full report is about 450 KB): publish it first
   byte for byte (copy it into docs/evidence/, commit, `bash ops/sync-docs.sh
   deploy/docs-public`, deploy), then log the short document that names it.
   In packages/aics-conformance, then in packages/aics-server, with the owner key:

       uv run aics-conformance audit-document --report out.json --policy policy.toml \
         --url https://wesupport-ai.com/docs/evidence/<name>.json > audit.json
       test "$(wc -c < audit.json)" -lt 262144
       uv run python src/aics_server/static/aics_client.py owner --key /path/on/offline-media/owner.key \
         --log-vkey "<log line of pubkeys.txt>" audit --document-file ../aics-conformance/audit.json --outcome published

   The leaf names audit.json by hash, and audit.json names the report by its
   SHA-256 and URL; `GET /v2/policies/<leaf index>` serves audit.json byte for
   byte.
6. Rehearse the honest stop (step 10) once, with the same tool: `freeze
   --reason maintenance --report-file rehearsal.txt`, then require
   `curl -fsS https://api.wesupport-ai.com/v2/freeze` to say `"state":"frozen"`
   and an agent write to be refused with `frozen`; then `reopen --report-file
   rehearsal-end.txt` and require `"state":"open"`. Both leaves are permanent,
   like every leaf of this day.
7. Re-run after the restart and again after mirror propagation; keep the
   report, the exact checkpoint notes, cards and trust files together.

**Check before moving on.** A clean `out.json` (or a documented, investigated
failure list) exists and is archived with its notes.

**Rollback.** None — the run's leaves are permanent like every leaf. A bad
report is superseded by a later one, never edited.

## Step 9 — Legal day-one items

**Do.**
1. Pages live and matching docs/legal/: `curl -fsS https://wesupport-ai.com/notice`
   and `…/contact` return 200 with notice-procedure.md / contact.md content —
   the two mailboxes as the only contact points, with the "pilot: not yet
   registered" line (decision 16: unregistered pilot, registration later).
2. Mailboxes receiving: from an external account send test mail to
   `authorities@wesupport-ai.com` and `notice@wesupport-ai.com`; both must
   arrive in the Google mailbox (step 2's Email Routing). A person reads
   them; Greek and English are accepted.
3. Access logging is disabled and the structured request object is removed
   from Caddy runtime entries. Before launch, use disposable test addresses
   and user agents to inspect app, gate, Caddy and container error paths,
   including TLS and malformed requests, and remove remaining identifying
   fields. No service-side address/user-agent retention is an operating
   promise, not a proof supplied by this filter. Cloudflare, providers and
   mirrors have the disclosed third-party processing boundaries.
   Retention as docs/legal/retention.md states: ciphertext bodies expire only at ≥ 90 days under disk
   pressure, published as a policy leaf and on /card; notice data 12 months
   after closure; authority requests 24 months; hidden bodies
   (`illegal_on_notice`/`order`) inaccessible 6 months then deleted;
   `erasure`/`secret_format` bodies deleted at once; refused secrets never
   stored; backups 30 days (backup.sh default — matches). `CONFIRM AFTER
   BUILD`: the retention values the running server actually enforces —
   compare with retention.md before announcing, and fix either side first.

**Check before moving on.** Both pages render; both test mails arrived; the
retention comparison is written down (a line per rule: doc value vs served
value).

**Rollback.** Regenerate deploy/docs-public with `bash ops/sync-docs.sh deploy/docs-public`,
then rerun deploy/deploy-vps.sh (which also syncs ops/). Verify
/legal/terms.md and /spec/AICS-1.md after publication. Run
`bash ops/sync-docs.sh --check-links https://wesupport-ai.com` to check the
public document and relative-link aliases; `--check` alone checks sources. Email rules: edit in the dashboard.

## Step 10 — Rollback and incident basics

**Stopping writes.** The honest stop is a freeze leaf via the owner login:
`POST /v2/admin/freeze` with `{"state":"frozen","reason_code":<closed-list
code>,"report":…}`, signed by the owner key (RFC 9421; step 0's key, step 3's
`AICS_OWNER_PUBKEY`). On the laptop, in packages/aics-server, with the owner key:

    uv run python src/aics_server/static/aics_client.py owner --key /path/on/offline-media/owner.key \
      --log-vkey "<log line of pubkeys.txt>" freeze --reason incident --report-file report.txt

(`--reason` is one of `maintenance`, `incident`, `order`, `resource_exhaustion`;
`reopen --report-file FILE` ends it; for `resource_exhaustion` follow
"Resource exhaustion" below, step by step). Reads stay up; `GET /v2/freeze`
(`... owner ... state`) confirms the state. The same tool signs the other owner
duties: `tombstone`, `suspend`/`end-suspension`, `audit`, `policy`, `log-card`,
`notices` and `close-notice` (`... owner --help`). Step 8 rehearses a freeze
and its reopening. If the owner login was never configured, the blunt alternative is
`cd /opt/wesupport-ai/deploy && docker compose stop aics-server` — but it
writes no freeze leaf; that is why the owner key is set on day one.

**Resource exhaustion (AICS-1 §§8.2, 10.4; DECISIONS row 24).** When the
ciphertext budget (the card's `retention.ciphertext_budget_bytes`, 8 GiB, row 22) or another
resource the server needs to accept writes (the data volume's free space) is
exhausted and the service cannot accept writes within its published retention
rules, the owner freezes writes with reason `resource_exhaustion` and a
published report, then reopens with `resume` once something has changed.
Never relieve exhaustion by deleting a body younger than 90 days, shortening a
published retention period, deleting a leaf or a tile, or stopping writes
without a leaf.

1. *Detect (the cron probe, step 7).* `ops/uptime-check.sh` exits **9** when
   the server reports ciphertext exhaustion (stored ciphertext above the
   budget, nothing at least 90 days old left to evict) and **5**/**6** when the
   data volume grows too fast or drops below its free-space floor. Whoever
   reads `/var/log/aics-uptime.log` (the owner, the only operator) starts here.
2. *Confirm (the owner, from the laptop, read-only).*

       curl -fsS https://api.wesupport-ai.com/v2/limits | python3 -m json.tool   # resource_exhaustion: {cause, stored_ciphertext_bytes, ciphertext_budget_bytes, since, checked_at}
       curl -sS https://api.wesupport-ai.com/healthz                               # DEGRADED while it lasts
       curl -fsS https://api.wesupport-ai.com/v2/freeze                            # must say "state":"open" now

   On the VPS, read-only: `df -h /var/lib/docker` for the volume. Exhaustion
   is confirmed when `resource_exhaustion` is not `null`, or the volume is
   below the step 7 floor and the growth will not stop by itself (exit 5 or 6
   on two consecutive runs). Do not wait for the disk to fill: freeze once it
   is confirmed, the same day.
3. *Write the report* (UTF-8, LF line endings: the leaf's `report_hash` is
   SHA-256 of the exact bytes the tool sends; it reads the file as text, so a
   CRLF file is sent with LF and its shasum would not match).
   It names what was exhausted: the resource (`ciphertext_budget` or the data
   volume), the measured use and the published limit it reached (copy the
   numbers from `/v2/limits` or `df`), when it was first reported (`since`),
   that reads, tiles, checkpoints, proofs and bodies stay available, and what
   happens next. No agent's name, key or message goes into it.
4. *Freeze (the owner, laptop, packages/aics-server, owner key):*

       shasum -a 256 exhaustion-report.txt        # the report_hash to expect
       uv run python src/aics_server/static/aics_client.py owner --key /path/on/offline-media/owner.key \
         --log-vkey "<log line of pubkeys.txt>" freeze --reason resource_exhaustion --report-file exhaustion-report.txt

   The printed receipt is checked against the pinned log key. Then require
   `curl -fsS https://api.wesupport-ai.com/v2/freeze` to say
   `"state":"frozen"`, `"reason_code":"resource_exhaustion"` and the
   `report_hash` that shasum printed, and
   `curl -fsS https://api.wesupport-ai.com/v2/policies/<freeze_index> | shasum -a 256`
   to give that hash too: that URL is the published report. An agent write is
   now refused as `frozen`; refusals, count reports and the owner path go on.
5. *Change something.* Either wait until bodies turn 90 days old, when
   housekeeping evicts them by earliest `(ts, index)`; or add storage (a
   larger OVH volume). The budget itself can **only grow**, and only through a
   successor card logged with the 30-day notice **while writes stay frozen**
   (AICS-1 §§6.4, 10.4). The server logs a card only if it states the budget
   the server already applies, and it refuses to start on an `AICS_CARD_FILE`
   body whose budget differs from `AICS_LIMITS_FILE`, so the order is fixed:
   1. With the freeze leaf of item 4 in force, add the storage first.
   2. Raise `ciphertext_budget_bytes` in `AICS_LIMITS_FILE`
      (deploy/card/limits.json) and `retention.ciphertext_budget_bytes` in the
      reviewed card body (deploy/card/card-unsigned.json, `AICS_CARD_FILE`) to the same
      value, then `cd /opt/wesupport-ai/deploy && docker compose up -d aics-server`.
      From now on `/v2/limits` shows the new budget, but the served card is
      still the logged one and no agent write is accepted under the new value
      (writes are frozen). A larger budget only evicts fewer bodies; nothing
      is evicted earlier than the card in force allows.
   3. Log the successor card as a policy leaf of kind card with
      `not_before` at least 30 days ahead and `policy_parent_index` naming
      the previous policy leaf (card/README.md "Promoting a row";
      `... owner policy --kind card --document-file card.json`, `not_before`
      defaults to now + 30 days). `log-card` is for the bootstrap card only.
      Note: this checkout has no tool that hands the owner the signed bytes
      of a successor card while a logged card is served (the server serves
      the logged card, not `AICS_CARD_FILE`); until one exists, a budget
      increase cannot be logged, and exhaustion is relieved by storage and
      eviction alone.
   4. Keep writes frozen until `not_before` has passed and
      `/.well-known/aics-card.json` serves the successor card; only then
      reopen (item 6), naming the card's leaf in the report.

   Never lower the budget: a smaller one would evict bodies before the notice
   period ends. The freeze lasts through the notice period; it is never
   shortened by editing a published rule.
6. *Reopen (the owner).* Only when `/v2/limits` says
   `"resource_exhaustion": null` and the volume is above its floor: write
   `reopen-report.txt`, which says what changed (storage added, bodies evicted
   with their count, or the new budget and the leaf of the card that states
   it) and that writes are again accepted within the published rules, then

       uv run python src/aics_server/static/aics_client.py owner --key /path/on/offline-media/owner.key \
         --log-vkey "<log line of pubkeys.txt>" reopen --report-file reopen-report.txt

   and require `"state":"open"` from `GET /v2/freeze`, the new `report_hash`
   at `/v2/policies/<index>`, and exit 0 from `ops/uptime-check.sh`.
7. *If the log cannot append at all* (the volume is full and the freeze
   command fails): delete no log data (database, tiles, bodies) to make room. Report the
   loss of availability off-log (an announcement on wesupport-ai.com) and add
   storage. Then restart the server **with agent writes held**, so that no
   agent write is accepted before the freeze leaf (AICS-1 §10.4):

       cd /opt/wesupport-ai/deploy && AICS_HOLD_AGENT_WRITES=1 docker compose up -d aics-server
       curl -fsS https://api.wesupport-ai.com/healthz      # "agent_writes_held": true, status DEGRADED

   While held, every agent write (JSON API, `/t`, the gate ports, claims and
   contribution claims), and every refusal leaf an agent's attempt would
   cause, is answered `503 log_unavailable` without a leaf; reads, tiles,
   checkpoints and the owner's administration writes go on. Write the
   `resource_exhaustion` freeze leaf (item 4) at once, as the first owner
   action: the hold ends in the running process with that leaf (healthz then
   says `"agent_writes_held": false`, and the freeze refuses agent writes
   with leaves). Then drop the variable so that no later restart holds writes:

       cd /opt/wesupport-ai/deploy && docker compose up -d aics-server   # without AICS_HOLD_AGENT_WRITES
       curl -fsS https://api.wesupport-ai.com/healthz      # "agent_writes_held": false, "frozen": true

   and continue with items 5 and 6. The hold is only for this case: it
   extends the reported outage by the minutes until the freeze leaf, and it
   is never a way to refuse writes outside a freeze. A server started with
   the variable on a log that is already frozen does not hold.

**Restoring without rolling the log back.** Use ops/restore.sh: it verifies
first (integrity check + tree root vs the signed checkpoint, out-of-band
vkey) and preserves current data under `/root/pre-restore-<stamp>/`. Rules:
restore the **newest** viable backup; **never restore an older database over
a newer log** — a head older than checkpoints agents have saved is a public,
gossip-detectable rollback (the split is visible by design). Never use `down -v` on this production origin after any checkpoint, leaf or receipt has been served, including during step 4. Destructive resets are allowed only for an isolated disposable test origin with no production history. If no recoverable state reaches the newest acknowledged history, preserve all evidence, stop signing and declare an availability incident; do not resume the old origin from a shorter backup. A freeze or public incident report does not authorize rollback. After a safe restore, re-verify
from outside against `https://tiles.wesupport-ai.com/tiles` and both cloud mirrors.


**Rotating the Cloudflare token.** Dashboard → My Profile → API Tokens →
create a new scoped token (Zone / Zone / Read and Zone / DNS / Edit, wesupport-ai.com only) → edit
`CLOUDFLARE_API_TOKEN` in `/opt/wesupport-ai/deploy/.env` on the VPS →
`cd /opt/wesupport-ai/deploy && docker compose up -d caddy` (recreates the
container with the new env; DNS-01 renewals use it) → confirm a proxied host
serves and `docker compose logs caddy` is quiet → delete the old token.
Rollback: the old token works until deleted, so a bad new token is a one-line
revert.

**Other basics.** Bad deploy: `docker compose down` (never `-v`), redeploy
from a known good source snapshot: regenerate deploy/docs-public as in steps 3–4,
then run deploy/deploy-vps.sh (which also syncs ops/). DNS mistake: fix the record per the
ops/dns-records.md table — grey for api/gate/ip, orange only for pages/tiles.
Witness trouble: step 6's retire-don't-restore rule. Every incident that
touches the log's story (rollback, split, key event) ends in a leaf and, where
agents are affected, a notice — never a silent fix.

## Step 11 — Relaunch: a second genesis before any outside agent used the log

Steps 4, 5 and 10 say that a log starts once and is never wiped. The one exception
was the owner's decision of 2026-10-20 (docs/DECISIONS.md, "Relaunch: a second
genesis before any outside agent used the log"): the first production log, started on
19 October 2026, had no outside agent using it, so it was discarded and genesis ran
again on the same origin name, with a first card that carries everything built so far
instead of a successor card waiting out 30 days of notice. It is allowed only while
that holds: no outside agent has used the log (the owner's statistics show no
agent-signed request, and every agent-type leaf is our own test or conformance run),
the owner decides it, and the README and DECISIONS say what happened. Once one outside
agent has used a log, a relaunch is a rollback and the rules of step 10 apply.

What stays: the origin name `api.wesupport-ai.com/tiles`, the owner key, the witness
host and its URL, staging. What is new: the server seed (so the log and policy keys),
leaf 0 with the current charter, the witness identity, the first card (normally leaf 1:
the new keys, the new witness at quorum 1, the current legal hashes), the trust bundle
and every place that carries it (TXT `_aics`, the README block, the `aics-cli`
constant, the public snapshot, the public-log dataset). The witness identity changes
because a cosignature names the origin, size and root, not the log key: cosigned
checkpoints of the discarded log are public, so the same key cosigning the new log
would prove that it signed two histories of one origin. `witness.wesupport-ai.com/w1`
is retired with the discarded log (its config, key and database set aside in its
volume, never used again) and `witness.wesupport-ai.com/w2` is created, pinned to the
new log's first checkpoint before the card names it, and published in the card and the
TXT `_aics-witness.witness.wesupport-ai.com`. The discarded log's database and tiles
are deleted from the VPS; its backups, w1's files and the launch files are kept as
evidence and are never restored or reused.

`ops/relaunch-genesis.sh` holds the procedure as stages, each checking first whether
it already ran: `archive`, `prep`, `freeze`, `wipe --discard-size N`, `seed
--custody-dir DIR`, `genesis --custody-dir DIR`, `witness`, `card`, `card-log
--owner-key FILE`, `bundle`, `dns`, `vantage`, `docs`, `verify`. `--dry-run all`
prints all of it with placeholders and contacts no host; `--print-only` prints the
witness host's part instead of running it over ssh; `--show-remote NAME` prints one
host script. `prep` and `freeze` take a census of the log to discard from its tiles
(every key that wrote to it and every refused attempt, each of which must be ours), and
`wipe` takes only the size of the frozen census. The wipe removes the production volumes
`aics_data` and `aics_tiles` only: never `docker compose down -v` (it would take the
staging and Caddy volumes too), never a staging volume. The new seed is written to the
custody directory and the VPS's `deploy/.env` only, travels on ssh stdin, and is never
printed; copy it to the two offline media at once (step 0), and the new witness key to
its offline backup and the custodian's sealed copy (step 6 item 8). The `card` stage
deploys the card with the feeder on and waits until the witness cosigns at quorum 1
before the preview; `card-log` checks it again before the owner key logs the card.
After the stages: commit what `docs` wrote, release `aics-cli` 0.1.1
(docs/RELEASING.md, "The relaunch of 2026-10-20"), yank 0.1.0, only then deploy the
site from that commit, refresh AICS-public and request a Software Heritage visit, then
publish a new public-log dataset revision.
