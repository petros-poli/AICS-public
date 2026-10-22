# ops/witness: the founder-run witness on the second host

The deployment of [aics-witness](../../packages/aics-witness/README.md) (C2SP
tlog-witness v1.1.0) for the production log of wesupport-ai.com, on the second
host. Runbook: [step 6](../RUNBOOK-first-deploy.md#step-6--witness-on-the-second-host).

| | |
| --- | --- |
| Host | Oracle always-free VM, Ubuntu 24.04, x86_64, 1 vCPU, 1 GB RAM + 2 GB swap, `129.151.206.105`, SSH user `ubuntu` (`ssh aics-trials`). Another provider than the log's OVH VPS. It also runs the agent-trials containers (tools/agent-trials) and the vantage probes (ops/vantage) |
| Name (permanent, part of the vkey) | `witness.wesupport-ai.com/w3`, since 2026-10-22. `witness.wesupport-ai.com/w1` cosigned the log discarded that day and is retired: its config, key and database are in the volume's `retired-w1/`, never used again |
| URL | `https://witness.wesupport-ai.com` (Cloudflare A record, DNS only, `ops/cloudflare-dns.sh --witness`) |
| Trust domain | `founder`, `independent: false`. A split view becomes detectable, not prevented; G5 stays `promised` (AICS-1 §6.3, decision 30) |
| Files | `compose.yml`, `Caddyfile`, `bootstrap-witness-host.sh`, `backup-witness.sh`, `systemd/`, `.env.example`. Host only, never in git: `.env` (public `WITNESS_DOMAIN`), `site/` (the generated public page) |
| Secret | The witness key, an Ed25519 seed created once by `init` inside the `aics-witness_witness_data` volume (mode 0600). Never printed, never in git, never in the daily backup, never on the log server. One offline copy, plus the custodian's sealed copy (card/README.md, `CUSTODIAN_HOLDS`) |

## What runs

`docker compose` project `aics-witness` in `~/aics/ops/witness`:

- **aics-witness**: the image from `packages/aics-witness/Dockerfile` (build
  context `~/aics/packages`, dependencies exactly as `uv.lock` pins them),
  read-only root, all capabilities dropped, state in the `witness_data` volume,
  port 7380 published on `127.0.0.1` only (for the probes on this host).
  128 MB memory limit and `oom_score_adj -500`: on this 1 GB box the kernel
  kills an agent container before the witness.
- **caddy**: stock `caddy:2.11.7-alpine`, pinned by digest, ports 80 and 443,
  Let's Encrypt HTTP-01 for `WITNESS_DOMAIN`. It writes no access log and
  deletes the request object (client address, user agent) from its error
  entries. 128 MB limit.

What `https://witness.wesupport-ai.com` serves, and nothing else (404):

| Request | Served by | What |
| --- | --- | --- |
| `POST /add-checkpoint` | witness | the call the log's feeder makes; body capped at 256 KiB, buffered by Caddy |
| `GET /<sha256(origin) hex>/checkpoint` | witness | the latest checkpoint it cosigned for that log (404 until fed) |
| `GET /healthz` | witness | `ok`, or `503` after a failed database write (the process exits and restarts) |
| `GET /`, `/vkey.txt`, `/witness.json` | Caddy, from `site/` | the public page: name, vkey, URL, trust domain, logs witnessed, DNS TXT name |

The page is written by `bootstrap-witness-host.sh` from `aics-witness status`;
never edit it by hand. It is a convenience copy: the card's `witness_policy`
and the DNS TXT record are where verifiers take the vkey from.

## Set up

From the laptop, in the repository root (the same copy the package README
describes, plus this directory; `--exclude` keeps the host-only `.env` and
`site/` out of `--delete`):

```sh
ssh aics-trials 'mkdir -p ~/aics/packages ~/aics/ops'
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache \
    --exclude .env --exclude /aics-witness/data \
    packages/aics-tlog packages/aics-witness aics-trials:aics/packages/
rsync -a --delete --exclude .env --exclude site/ ops/witness aics-trials:aics/ops/
```

On the host:

```sh
bash ~/aics/ops/witness/bootstrap-witness-host.sh \
    [--name '<a witness name never used before: a new volume only>'] \
    --origin '<origin from the pinned trust bundle>' \
    --log-vkey '<log_vkey from the pinned trust bundle>' \
    --initial-size <N> --initial-root '<base64 root of a verified checkpoint of size N>'
```

The script installs Docker only if it is absent (the agent-trials bootstrap has
installed docker-ce; it adds the compose plugin, which that bootstrap leaves
out), writes `.env`, builds the image, runs `init` (key and database, once),
`add-log`, the optional `initial` pin, writes `site/`, starts both services and
prints what to publish:

- the witness vkey (`<name>+<keyid>+<base64>`);
- `AICS_WITNESSES=founder-<wN>=https://witness.wesupport-ai.com=<vkey>` for the
  log server's feeder in the VPS's `deploy/.env` (comma-separated
  `name=url=vkey` entries, `name` a local label; the format of
  `aics_server/witness_feed.py`, which is being wired as this is written:
  **CONFIRM AFTER BUILD**);
- the card's `witness_policy.witnesses` entry
  `{"name": ..., "vkey": ..., "trust_domain": "founder", "independent": false}`;
- the DNS TXT record `_aics-witness.witness.wesupport-ai.com` with
  `aics-witness-vkey <vkey>`;
- the one-time offline key backup command.

Origin and log vkey come from the out-of-band trust bundle (`_aics` TXT, the
README block, the `aics-cli` package; runbook step 5), never from the log's API. The
script refuses `test.*` and `pilot.*` origins. `--initial-size/--initial-root`
pin a checkpoint you verified yourself, so the first checkpoint the witness
accepts must be consistent with it instead of being trusted on first sight
(the production log is already running); the pin is ignored once the witness
holds state for the log. `--name` is needed once, for a new volume: a name never
used before (the host table names the identity in use; a retired name, such as
`witness.wesupport-ai.com/w1`, is never used again); later runs take the name
from the config in the volume. `--domain` overrides the default on the first run
only (both are permanent once published); `--no-start` stops before `up`.

Rerun the script at any time: after an rsync of new code (it rebuilds and
recreates the witness container), to re-print the published lines, or to add
a log (a running witness gets `SIGHUP`). It refuses, instead of creating a new
identity, when the key or the database has gone missing; then follow
*Retiring* below.

Firewall: in the Oracle console add VCN security-list ingress rules for TCP 80
and 443. Do not open 7380. Docker's published ports normally pass the host's
iptables; if `curl` from outside still times out, the package README's Oracle
iptables recipe (*Deploy on a second host*, step 7) applies.

## Check it

From any other machine:

```sh
W=https://witness.wesupport-ai.com
curl -fsS $W/healthz                                   # ok
curl -fsS $W/vkey.txt                                  # the vkey the script printed
printf 'garbage' | curl -sS -o /dev/null -w '%{http_code}\n' --data-binary @- $W/add-checkpoint   # 400
dig +short TXT _aics-witness.witness.wesupport-ai.com  # "aics-witness-vkey <vkey>"
```

**Uptime, one line** (cron on the laptop or the VPS, or any external monitor;
the host checking itself proves little):

```sh
curl -fsS --max-time 10 https://witness.wesupport-ai.com/healthz | grep -qx ok || echo "witness.wesupport-ai.com DOWN"
```

`/healthz` answers `ok` only while the witness process runs and its last
database write succeeded, and only through Caddy with a valid certificate, so
this one line covers DNS, TLS, Caddy and the witness. Whether it is also
cosigning is the vantage probe's job (ops/vantage, `AICS_VANTAGE_WITNESS_URL`
default `http://127.0.0.1:7380`; the public vkey for its
`AICS_VANTAGE_WITNESS_VKEY_FILE` is `~/aics/ops/witness/site/vkey.txt`).

On the host, in `~/aics/ops/witness`:

```sh
docker compose ps
docker compose run --rm aics-witness status        # per log: size, root, last cosignature, evidence
docker compose logs aics-witness | grep 'witness vkey'
docker compose logs caddy | grep -i 'certificate obtained'
```

## Backups

**The key**: once, offline, right after the first run (the script prints the
command; it never changes):

```sh
cd ~/aics/ops/witness && umask 077
docker compose run --rm --no-deps -T --entrypoint cat aics-witness /data/witness.key > witness.key.offline
# copy to offline media (and the custodian's sealed copy), then: shred -u witness.key.offline
```

**The state, daily (optional)**: `backup-witness.sh` copies the database with
SQLite's online backup API from inside the running container, plus the config
and `status --json`, verifies them (SHA256SUMS, gzip, `integrity_check`, the
database's witness vkey) and keeps them under `/var/backups/aics-witness` for
30 days. It never reads the key. These archives are **evidence, not a restore
path**: a witness restored from an older database has forgotten what it
cosigned since and could be led to cosign a fork, so a lost volume always means
retiring the identity. What the backup preserves is the refused log-signed
requests (proof of a split view) and the last cosigned head per log.

Off-host copies follow ops/backup.sh's rclone pattern: name the remotes in
`WITNESS_BACKUP_REMOTES` and each run goes to `<remote>:aics-witness-backup/<stamp>/`.
The rclone config is `/root/.config/rclone/rclone.conf` on this host, never in
git. A Google Drive remote, for example (create the OAuth token with
`rclone authorize "drive"` on a machine with a browser, then paste it into
`rclone config` here; `drive.file` limits rclone to the files it created):

```ini
[gdrive]
type = drive
scope = drive.file
token = <the JSON token rclone authorize prints>
```

R2 or B2 remotes as in ops/rclone.conf.example work the same way (the first
path element, `aics-witness-backup`, is then the bucket).

```sh
sudo apt-get install -y rclone
sudo rclone config                                       # creates /root/.config/rclone/rclone.conf
echo 'WITNESS_BACKUP_REMOTES=gdrive' | sudo tee /etc/default/aics-witness-backup
sudo bash ~/aics/ops/witness/backup-witness.sh           # one run by hand
sudo cp ~/aics/ops/witness/systemd/aics-witness-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now aics-witness-backup.timer
```

Without a remote the script runs in local mode and says so.

## Sharing the box with agent trials

The trial agents are untrusted programs in containers on the same kernel. What
keeps them away from the witness: the key sits in a root-owned Docker volume;
the witness and Caddy run in their own compose network; 7380 is bound to the
host's loopback, which a bridge container cannot reach; the agents run as an
unprivileged user with all capabilities dropped, `no-new-privileges`, no
Docker socket and only read-only bind mounts
(tools/agent-trials/agent_trials/container.py).
A container or kernel escape would still reach the key. That is acceptable only
because this witness is in the founder's trust domain anyway and G5 stays
`promised`; if trial containers ever get the Docker socket, privileged mode or
host mounts, move the witness first (copy the stopped volume, below). The
memory limits and `oom_score_adj` keep a runaway agent from taking the witness
down with it.

## Operations

Everything in the package README's *Operations* applies; on this host run the
commands in `~/aics/ops/witness` as `docker compose ...` (no `-f`).

- **Upgrade**: rsync the code, rerun the bootstrap (or `docker compose build && docker compose up -d`).
- **Clock**: keep NTP on (`timedatectl`); the bootstrap warns when it is off.
- **Move hosts**: `docker compose stop aics-witness`, copy the whole
  `aics-witness_witness_data` volume (package README), start it on the new host
  only, then repoint the `witness` A record. Never run two copies of the key.
- **Retiring** (key or database lost, database rolled back): never restore an
  older database. Move the old files aside, `init` a new name
  (`witness.wesupport-ai.com/w2`), publish the new vkey and remove the old one
  through an advance-noticed successor card (package README, *Operations*).
- **Never** run `docker compose down -v` here: it deletes the witness state.
