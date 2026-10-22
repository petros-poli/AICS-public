# aics-witness

A [C2SP tlog-witness](https://c2sp.org/tlog-witness) for AICS transparency logs
(docs/DESIGN.md G5, §4.3 Log, §10; docs/spec/AICS-1.md §6.2–6.4).

For every log it is configured with, the witness keeps the latest checkpoint it
cosigned. It cosigns a new checkpoint only after verifying

1. the log's signature with the log vkey from its configuration, and
2. an RFC 6962 consistency proof from the size it last cosigned to the new size,

and it persists the new state (atomically with the check) before answering with
a timestamped `cosignature/v1` line. It will never cosign two checkpoints of one
log that are inconsistent with each other, and never a smaller tree after a
larger one, including across restarts. That holds as long as its database
survives: `serve` refuses to start without the database `init` created, and a
witness whose database is lost must be retired, not restarted (see
*Operations*).

What this does **not** give you on its own: a founder-run witness is in the same
trust domain as the log, even on another provider. With it, a split view becomes
*detectable* (the witness refuses the second branch and keeps the log-signed
request as evidence); it is *prevented* only once independent witnesses join a
quorum whose members must intersect in an honest one (AICS-1 §6.3). Until then
the card keeps G5 as `promised`.

Standard library HTTP server, SQLite, and `aics-tlog` for signed notes,
checkpoints, cosignatures and the consistency-proof verifier.

## Protocol

Implements tlog-witness **v1.1.0** (what `c2sp.org/tlog-witness` serves today),
with tlog-checkpoint, tlog-cosignature and signed-note v1.1.0.

`POST <prefix>/add-checkpoint`, body: `old <size>`, up to 63 base64 proof lines,
an empty line, the signed checkpoint. Checked in the specification's order
(format, origin, log signatures, old size, consistency), with this profile's
extension-line rule right after the origin:

| Status | When |
| --- | --- |
| 400 | malformed body or checkpoint, more than 63 proof lines, old size larger than the checkpoint size, tree size above 2^63-1; extension lines in a checkpoint of a log configured without them (the default: AICS-1 §6.2 checkpoints have none) |
| 404 | the checkpoint's origin is not configured |
| 403 | no signature from a configured log key, a configured key's signature fails, or two lines from one configured key; lines from unknown keys, repeated or not, are ignored |
| 409 | old size differs from the size this witness last cosigned for the origin (0 if never, or the configured `initial` pin); body `<size>\n`, `Content-Type: text/x.tlog.size`. A checkpoint of the cosigned size with another root is still kept as evidence (it proves equivocation whatever old size came with it) |
| 422 | size 0 without the empty-tree root; a proof sent with old size 0; equal size with a different root; a consistency proof that does not verify. Never cosigned; the request is kept as evidence |
| 503 | the clock reads earlier than this witness's last cosignature for the log (`Retry-After` when at most 5 s behind; otherwise until the clock is fixed, see *Operations*), or the database cannot be written |
| 200 | one line `— <witness name> base64(key ID ‖ timestamp ‖ Ed25519 signature)`, timestamped with the current time. A replay of the stored checkpoint within the same second gets the stored line back without a write |
| 411 / 413 / 501 | neither `Content-Length` nor chunked / body over `max_body_bytes` / a transfer coding other than chunked |

`GET <prefix>/<sha256(origin) hex>/checkpoint` serves the latest cosigned
checkpoint with the verified log signature(s) and this witness's cosignature
(the specification's monitoring endpoint), read through a read-only database
connection so only committed state is served; 404 if nothing was cosigned.
`GET /healthz` answers `ok`, or `503` once a database write failed (the
process then exits, so the restart policy brings it back on a fresh
connection). HTTP keep-alive is supported; an idle connection is closed after
5 s, or at once when every connection slot is taken. A request (request line,
headers and body) must arrive within 10 s of its first byte. No client address
or user agent is logged anywhere.

The witness never signs a time its clock does not show and never dates a
cosignature before its previous one for the same log: when the clock reads
earlier than the stored cosignature time it answers 503 instead (see *Clock*
under *Operations*).

Cosignatures are Ed25519 `cosignature/v1` (vkey type `0x04`), which is what
AICS-1 §6.2 and `aics-tlog` verify. Not implemented: ML-DSA-44 cosignatures
(a SHOULD in v1.1.0; tlog-cosignature recommends ML-DSA-44 for new
deployments) and the optional `sign-subtree` call; both wait for a vetted
Python ML-DSA-44 implementation (type `0x06`, `CosignedSubtree`), and the
assurance card should list this as a known SHOULD deviation. Log keys may be
type `0x01` (Ed25519 note signature, the normal case) or `0x04`; keys that are
not canonical Ed25519 encodings or are small-order points (under which anyone
can forge signatures) are refused, and so is the witness's own key.

AICS-1 cites tlog-witness v1.0.0 (and v1.0.0 of tlog-checkpoint,
tlog-cosignature and signed-note); this witness implements v1.1.0. What a log
can notice: an equal size with a different root is `422` in v1.1.0 and was
`409` (naming the same size) in v1.0.0, and the feeder treats both as a final
rejection; a size-0 checkpoint must carry the empty-tree root; a failing
trusted signature is `403`; base64 must be canonical. AICS-1 §6.2 and the
card's `spec_versions` still need updating to v1.1.0.

## Run it locally

```sh
cd packages/aics-witness
uv sync
export AICS_WITNESS_CONFIG=data/witness.json    # data/ is git- and docker-ignored
uv run aics-witness init --name witness.example.org/w1   # prints the witness vkey
uv run aics-witness add-log --origin log.example/aics-1 \
    --vkey 'log.example/aics-1+d34caeba+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU'
uv run aics-witness serve --listen 127.0.0.1:7380
uv run aics-witness status
uv run pytest -q
```

(The log vkey above is the public test key of AICS-1 Appendix A, as in
`witness.example.json`.) `--config` defaults to `$AICS_WITNESS_CONFIG`, then
`./witness.json`. Keep local state out of the repository: the key file is a
secret.

| Command | Does |
| --- | --- |
| `init --name N` | creates what is missing -- config, key (mode 0600) and database, bound to that key -- and prints the witness vkey; safe to rerun. Refuses to create a database for a key that already existed (`--new-database`: only for a key that never cosigned) and to create or use a key other than the one the database belongs to (`--new-key`: a new identity) |
| `add-log --origin O --vkey K` | trusts a log, or adds a key to a configured log (rotation); idempotent |
| `serve` | runs the witness; never creates a database (a missing one is lost state); `SIGHUP` reloads the log list, `SIGTERM` stops cleanly |
| `status [--json]` | witness vkey, and per log: size, root, last cosignature time, evidence count; warns when the database is missing |
| `evidence [--origin O]` | the kept log-signed requests that failed consistency checks, as JSON |
| `clear-timestamp --origin O \| --all` | after fixing a clock that ran ahead: lets the witness cosign that log again with its current time (see *Clock*) |

## Configuration

```json
{
  "witness": {
    "name": "witness.example.org/w1",
    "listen": "0.0.0.0:7380",
    "prefix": "",
    "db": "witness.db",
    "key_file": "witness.key",
    "max_body_bytes": 262144
  },
  "logs": [
    {"origin": "log.example/aics-1",
     "vkeys": ["log.example/aics-1+d34caeba+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"]}
  ]
}
```

- `name` is the cosigner name. It is part of the vkey, so it is permanent: a new
  name is a new witness. Use a schema-less URL you control.
- `db` and `key_file` are relative to the config file's directory.
- Unknown fields are errors. Removing a log stops cosigning for it but keeps its
  state, so adding it back later cannot roll it back.
- Per log, optional: `"extension_lines": true` lets its checkpoints carry
  extension lines (default `false`: AICS checkpoints have none, so such a
  checkpoint gets 400 instead of a cosignature over text no AICS client
  accepts). `"initial": {"size": N, "root": "<base64>"}` pins a known-good
  checkpoint, obtained out of band, for a log this witness has never cosigned:
  the witness then starts from it (409 names `N`; a consistency proof from that
  root is required) instead of trusting whatever checkpoint arrives first with
  `old 0`. Use it when adding the witness to a log that is already running. It
  is ignored once the witness holds state for the log.

## Keys

The witness key is an Ed25519 seed: 64 hex characters in `key_file`, created
once by `init` with mode 0600 (the witness refuses a key file that group or
others can read or write). `WITNESS_SEED_HEX` (the same 64 hex characters) overrides the
file when set; such a seed counts as an existing identity, so the first `init`
with it needs `--new-database`. `init` creates the database and records the
witness vkey in it; `serve` refuses a missing database, a database without a
recorded vkey, and a different key (lost or swapped key file) unless given
`--accept-new-key`.

Back up the key file **offline, once**; it never changes. Losing it means a new
witness identity that every verifier has to be told about.

## Deploy on a second host

Oracle Always Free (Ampere A1, arm64, or the 1 GB AMD micro shape) or any small
VPS (amd64). Docker builds the image natively on either. The steps assume
Ubuntu 24.04.

wesupport-ai.com's own founder-run witness does not follow these steps by hand:
it runs from [ops/witness](../../ops/witness/README.md), a compose project with
the same image, project, volume and container names, a Caddy with a public
vkey page, loopback-only 7380, memory limits for a 1 GB host shared with other
containers, an optional daily evidence backup, and a bootstrap script that
does steps 1 to 6 below (runbook step 6). The steps below are the generic
deployment, for example for an external witness (docs/WITNESS-CUSTODIANS.md).

**1. Host.** Oracle: create a `VM.Standard.A1.Flex` instance (1 OCPU, 6 GB is
plenty) with Ubuntu 24.04 and your SSH key. Then:

```sh
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 rsync
sudo usermod -aG docker "$USER"    # log out and back in
```

**2. Code.** From your checkout, copy the two packages side by side:

```sh
ssh witness-host 'mkdir -p ~/aics/packages'
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache \
    --exclude .env --exclude /aics-witness/data \
    packages/aics-tlog packages/aics-witness witness-host:aics/packages/
```

Everything below runs on the host in `~/aics/packages/aics-witness`.

**3. Build.**

```sh
docker compose -f compose.witness.yml build
```

The build installs exactly what `uv.lock` pins and fails if the lock is stale
(after changing dependencies run `uv lock` in `packages/aics-witness`).

**4. Witness identity.** Pick the cosigner name, then:

```sh
docker compose -f compose.witness.yml run --rm aics-witness init --name witness1.example.org/w1
```

It prints the witness vkey (`name+keyid+base64`); this is the line you publish
(below). Config, key and database live in the `witness_data` volume. (With
`WITNESS_SEED_HEX` set in the compose file instead of a key in the volume, add
`--new-database` to this first `init`.)

**5. Trust the log.** Origin and log vkey come from the log operator's
out-of-band publication (for AICS: `_aics.<domain>` TXT, the README trust block,
the `aics-cli` package), never from the log's own API:

```sh
docker compose -f compose.witness.yml run --rm aics-witness add-log \
    --origin '<log origin>' --vkey '<log vkey>'
```

**6. Start.**

For HTTPS (recommended), point a DNS name at the host (on Cloudflare: DNS
only, grey cloud), open ports 80 and 443, and use the `tls` profile. Caddy
(`Caddyfile.witness`, mounted read-only) obtains the certificate, enforces
header and body read deadlines, buffers request bodies, and keeps client
addresses and user agents out of its logs; the witness port stays on
127.0.0.1:7380, the default:

```sh
WITNESS_DOMAIN=witness1.example.org docker compose -f compose.witness.yml --profile tls up -d
docker compose -f compose.witness.yml logs aics-witness  # shows the vkey and the logs it trusts
```

Plain HTTP from outside, without Caddy, needs an explicit
`WITNESS_PUBLISH=0.0.0.0:7380` (the protocol has no authentication; the
witness's own deadlines then are the only defence against slow clients).

Put `WITNESS_DOMAIN` (and `WITNESS_PUBLISH`, if used) in a `.env` file next to
`compose.witness.yml` so later commands keep them.

**7. Firewall.** Oracle: add ingress rules to the instance's VCN security list
(TCP 443 and 80 for the `tls` profile, or 7380). Docker's published ports
normally pass the host firewall by themselves; if the smoke test below still
times out, Oracle's Ubuntu image is rejecting the connections in iptables:

```sh
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo netfilter-persistent save
```

Elsewhere with ufw: `sudo ufw allow 443/tcp && sudo ufw allow 80/tcp`.

**8. Smoke test, from another machine.**

```sh
W=https://witness1.example.org        # or http://<address>:7380
curl -fsS $W/healthz                   # ok
printf 'garbage' | curl -sS -o /dev/null -w '%{http_code}\n' --data-binary @- $W/add-checkpoint    # 400
printf 'old 0\n\nexample.invalid/none\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n\342\200\224 example.invalid/none AAAAAAAA\n' \
  | curl -sS -o /dev/null -w '%{http_code}\n' --data-binary @- $W/add-checkpoint                    # 404
```

(`\342\200\224` is the UTF-8 em dash that starts a signature line; the 404 shows
the witness parsed a well-formed checkpoint for an origin it does not trust.)

The log then submits to `$W/add-checkpoint` (see *Log side* below).

## Publish the witness vkey

1. Print it again at any time (idempotent; it refuses, instead of printing a
   new vkey, if the key file or the database has gone missing):
   `docker compose -f compose.witness.yml run --rm aics-witness init`.
   Check that the running server uses the same key:
   `docker compose -f compose.witness.yml logs aics-witness | grep 'witness vkey'`.
2. **Assurance card** (authoritative; a logged, advance-noticed policy event,
   AICS-1 §6.3–6.4): add the witness to `witness_policy.witnesses` as
   `{"name": "<name>", "vkey": "<vkey>", "trust_domain": "founder", "independent": false}`,
   set `quorum` (1 with this witness alone), and keep G5 `promised`.
3. **Public repository README** (https://github.com/petros-poli/AICS-public): a witness block with name, vkey, URL, operator
   and trust domain, next to the log key.
4. **DNS TXT** on the witness's own name, e.g. `_aics-witness.witness1.example.org`
   with the value `aics-witness-vkey <vkey>` (one line, no spaces inside the vkey).
5. **Log server**: give its feeder the witness URL and this vkey, so it verifies
   every cosignature it collects (`WitnessClient(url, vkey)`).
6. Once the log has fed a checkpoint, check the whole chain from outside with
   keys obtained out of band:

   ```sh
   H=$(printf '%s' '<log origin>' | sha256sum | cut -d' ' -f1)    # macOS: shasum -a 256
   curl -fsS $W/$H/checkpoint > cp.txt
   aics-tlog verify-checkpoint --note cp.txt --origin '<log origin>' \
       --log-key '<log vkey>' --witness-key '<witness vkey>' --quorum 1 --max-age 600
   ```

   (`aics-tlog` is the CLI of `packages/aics-tlog`: `uv run aics-tlog ...` there.)
   It prints `"ok": true` with `"witnesses": ["<name>"]`.

## Operations

- **State**: `docker compose -f compose.witness.yml run --rm aics-witness status`
  (safe while the witness runs). A growing size per log means the log is feeding.
- **Evidence**: `status` flags it; `... run --rm aics-witness evidence` prints the
  kept requests with the witness's own latest checkpoint. Two log-signed
  checkpoints with the same size and different roots prove a split view
  (AICS-1 §6.3, gossip check); keep them and report them.
- **Key backup** (once, offline; the seed never changes):

  ```sh
  umask 077
  docker compose -f compose.witness.yml run --rm --entrypoint cat aics-witness /data/witness.key > witness.key.offline
  # move witness.key.offline to offline storage, then delete it here
  ```

- **Never restore an older database over a newer one**: a witness that forgets
  what it cosigned can be led to cosign a fork. `witness.db` and, after an
  unclean stop, `witness.db-wal` are the state (the witness copies each commit
  into `witness.db` right away, so normally that file alone suffices); never
  delete either. `serve` refuses to start when the database is missing, and
  `init` refuses to create one for an existing key. To move hosts, stop the
  witness, copy the whole volume, and start it on the new host only:

  ```sh
  docker compose -f compose.witness.yml stop aics-witness
  docker run --rm -v aics-witness_witness_data:/data -v "$PWD":/backup busybox \
      tar czf /backup/witness-data.tgz -C /data .
  ```

  Never run two copies of one witness key. If the database is lost or rolled
  back (also: the volume was lost while `WITNESS_SEED_HEX` kept the key, or the
  `db` path or `--config` points somewhere else), retire the identity instead
  of continuing with it: move the old files aside, create a new name and key,
  add the logs again, publish the new vkey and remove the old one through the
  card:

  ```sh
  docker compose -f compose.witness.yml run --rm --entrypoint sh aics-witness \
      -c 'mkdir -p /data/retired && mv /data/witness.json /data/witness.key /data/witness.db* /data/retired/'
  docker compose -f compose.witness.yml run --rm aics-witness init --name witness1.example.org/w2
  ```
- **Clock**: keep NTP running. The witness never signs a time earlier than its
  previous cosignature for a log. A clock up to 5 s behind gets `503` with
  `Retry-After`; further behind, the witness logs `clock behind last
  cosignature by N s` and refuses that log. Fix the clock. If the clock had run
  ahead when it cosigned (an NTP or RTC glitch), the stored time is in the
  future: after fixing the clock, run
  `docker compose -f compose.witness.yml run --rm aics-witness clear-timestamp --origin '<origin>'`
  (or `--all`); the start-up log warns about such logs.
- **Disk full / I/O errors**: a failed database write turns `/healthz` red and
  stops the process, which the restart policy restarts; until the cause is
  fixed every write fails again. The monitoring endpoint only ever serves
  committed state. Evidence is capped per log at 1000 requests and 16 MB.
- **Logs**: container logs carry no client addresses; rotation is set in the
  compose file (3 × 10 MB) for both services.
- **Upgrades**: copy the new code, `build`, `up -d`. The database schema version
  is checked at start; a version 1 database gets the version 2 rollback
  triggers automatically. A witness set up with an older `init` that never
  ran `serve` has no database yet: run `init --new-database` once (safe only
  because that key never cosigned).
- **Config changes**: edit with `add-log`, then
  `docker compose -f compose.witness.yml kill -s HUP aics-witness` (or restart).

## Log side

```python
from aics_witness.feeder import WitnessClient, merge_cosignatures

client = WitnessClient("https://witness1.example.org", "<witness vkey>",   # one per witness, long-lived
                       state_path="state/witness1.json")                    # survives log restarts
line = client.submit(signed_checkpoint_bytes, tree.consistency_proof)      # proof(old_size, new_size)
cosigned = merge_cosignatures(signed_checkpoint_bytes, line)
```

The client starts from the witness size it last saw (0 on first contact), and on
`409` retries from the size the witness names with a fresh proof; if the witness
already holds this checkpoint size (a lost response) the retry needs no proof.
The witness vkey is required: every returned line is verified, and must be
dated at most 60 s ago and at most 30 s ahead (`max_age_seconds`,
`max_future_seconds`); otherwise `BadWitnessResponse`.
A witness ahead of the checkpoint raises `WitnessAhead` (a `WitnessConflict`;
with a single writer it means the log rolled back or its key signed elsewhere,
so it is logged as an error and not remembered). A witness that answers from a
smaller tree than one this client saw it cosign raises `WitnessRolledBack`: it
lost or rolled back its state. That is recorded in the state file, and every
later submission for the log raises it too, so the witness stops counting
toward the quorum until an operator calls `client.acknowledge_rollback(origin)`.
`400/403/404/422` raise `WitnessRejected`; transport errors and `429/5xx` are
retried with backoff (`Retry-After` honoured) and end in `WitnessUnavailable`.
`submit_checkpoint(url, note, proof, witness_vkey=...)` is the one-shot form.
