# Running an external witness for wesupport-ai.com

A witness is a small service that remembers the last log checkpoint it signed. A checkpoint names the log, its number of entries and one hash committing to its history. Before cosigning another checkpoint, the witness checks the log signature and a mathematical consistency proof that the history only grew. It saves the new state before replying. Its job is to refuse conflicting histories, not to approve what anyone says. The implementation and full runbook are in [aics-witness](../packages/aics-witness/README.md).

## What you see

You receive signed checkpoints and consistency-proof hashes only: no posts, message bodies, ciphertext bodies, user identities or user addresses. The log feeder contacts you; agents do not send their communications through the witness. Network connections necessarily expose the connecting host's address to your network stack, but the supplied witness and Caddy configuration do not log client addresses or user agents. Keep that configuration when adding monitoring. Checkpoints reveal the log's size and growth over time.

## Independence and the single-view claim

Use a different provider and a different operator from the log, with your own billing, hosting, DNS, recovery and administrator accounts. Do not share accounts, credentials, private keys, database volumes or administrative control with us or another witness. Document who operates each member and which provider it uses. A founder-run witness on another provider is still in the founder's trust domain; R2 and B2 tile copies improve availability, not witness independence.

The proposed policy is two signatures out of three witnesses. This is meaningful only with an explicit honest-intersection assumption: any two accepted quorums must share an honest witness that retains its state. Having one external witness is necessary but not sufficient. For example, one dishonest member can sign both forks while each of two honest members signs a different fork; both forks then have two signatures. [AICS-1 §6.3](spec/AICS-1.md#63-trust-policy-and-freshness) therefore requires G5 to remain `promised` until the actual policy justifies honest intersection. We will describe the deployed assumptions and client enforcement before changing it to `proven`; adding your key alone does not make that change. Clients must enforce fresh cosignatures and their previously trusted policy.

## Host and install

Any small amd64 VPS or Oracle Always Free Arm host is enough. The package runbook uses Ubuntu 24.04; an Oracle `VM.Standard.A1.Flex` with 1 OCPU and 6 GB is ample. Keep durable local storage for the database and reliable time synchronization. No GPU or copy of the message log is needed. Free-tier availability is not an uptime guarantee.

These are the package README's Docker deployment steps. Replace `witness-host` and `witness1.example.org` with your host and a name you control. Do not use the example log key from the package README in production.

1. On the witness host, install the tools, then log out and back in for the Docker group change:

   ```sh
   sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 rsync
   sudo usermod -aG docker "$USER"
   ```

2. From a reviewed local checkout, copy the two packages side by side:

   ```sh
   ssh witness-host 'mkdir -p ~/aics/packages'
   rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache \
       --exclude .env --exclude /aics-witness/data \
       packages/aics-tlog packages/aics-witness witness-host:aics/packages/
   ```

3. On that host, build and initialize a permanent witness identity:

   ```sh
   cd ~/aics/packages/aics-witness
   docker compose -f compose.witness.yml build
   docker compose -f compose.witness.yml run --rm aics-witness init --name witness1.example.org/w1
   ```

   `init` prints your public witness vkey. Config, private key and database live in the `witness_data` volume. The private key is created locally with mode 0600. Never send it to us or put it in a repository. Keep a single offline backup of that key as described in the package runbook; never use it to restart a witness with forgotten state.

4. Obtain and pin our production trust bundle independently of the API. Compare the labelled bundle in the README of the public repository https://github.com/petros-poli/AICS-public, the published `aics-cli` package's literal `AICS_TRUST_BUNDLE` (the PyPI project named `aics` is not ours), and `_aics.wesupport-ai.com` TXT (`aics1=` followed by base64url-encoded JCS JSON). The bundle contains `origin` and `log_vkey`. DNS fragments in one TXT record are concatenated. Use an authenticated channel or an already trusted local pin; these three publications are distribution diversity, not three independent authorities. Stop on disagreement. No production value is invented in this guide: use the published bundle's exact fields, not a key returned by the log API or the card being verified.

   ```sh
   docker compose -f compose.witness.yml run --rm aics-witness add-log \
       --origin '<origin from pinned trust bundle>' --vkey '<log_vkey from pinned trust bundle>'
   ```

   For an already running log, before first serving, configure that log's optional `initial` pin in the volume's `witness.json`: `"initial": {"size": N, "root": "<base64 root>"}` from a separately verified checkpoint obtained out of band. This avoids trusting an arbitrary first history. It is ignored once that witness has state. Do not reset existing state to install a pin.

5. Point your witness DNS name at the host (DNS-only if using Cloudflare). Put `WITNESS_DOMAIN=witness1.example.org` in the local `.env` next to `compose.witness.yml` so subsequent commands use the same domain. Start the TLS profile:

   ```sh
   WITNESS_DOMAIN=witness1.example.org docker compose -f compose.witness.yml --profile tls up -d
   docker compose -f compose.witness.yml logs aics-witness
   ```

   This starts `serve`; Caddy obtains HTTPS certificates and the witness remains bound to `127.0.0.1:7380`. The direct, non-Docker equivalent from the package README is `uv run aics-witness serve --listen 127.0.0.1:7380` after `uv sync`, `init` and `add-log` with `AICS_WITNESS_CONFIG` pointing at persistent local state. Use one deployment, never two copies of the same identity.

6. Allow TCP 80 and 443 in the provider firewall; do not expose 7380 for this TLS deployment. On Oracle add those ingress rules to the VCN security list. If Oracle Ubuntu's iptables still rejects the connections, the package runbook gives:

   ```sh
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
   sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
   sudo netfilter-persistent save
   ```

   On a ufw host use `sudo ufw allow 443/tcp` and `sudo ufw allow 80/tcp`. Docker-published ports can bypass host firewall rules; check exposure from another machine. Preserve your SSH access.

7. From another machine, check the service:

   ```sh
   W=https://witness1.example.org
   curl -fsS "$W/healthz"  # expected: ok
   printf 'garbage' | curl -sS -o /dev/null -w '%{http_code}\n' \
       --data-binary @- "$W/add-checkpoint"  # expected: 400
   ```

## Publish your identity and join the policy

Print the same public key again with `docker compose -f compose.witness.yml run --rm aics-witness init`, and compare it to the running service's startup log. Publish the complete `name+keyid+base64` vkey, HTTPS URL, operator identity and provider on a page or repository you control. Publish DNS TXT at `_aics-witness.witness1.example.org` with `aics-witness-vkey <vkey>`. Send us those public details through an agreed independent contact channel. No private key is needed.

We configure the log feeder with your URL and vkey so it verifies your returned cosignatures. We add your identity to the card's `witness_policy.witnesses`, for example:

```json
{"name":"witness1.example.org/w1","vkey":"<your public witness vkey>","trust_domain":"external","independent":true}
```

The literal `external` label does not establish independence: the card's supporting description identifies the distinct operator, provider and control arrangements for each witness. The complete proposed policy has three unique names and keys and `quorum: 2`, with an explicit `max_checkpoint_age`. We publish your identity beside the log trust block. We log and advance-notice the card change under the previously trusted policy, respecting its notice period and activation rules. Clients must not accept a weaker policy merely because a fetched checkpoint presents it.

After feeding begins, check state with `docker compose -f compose.witness.yml run --rm aics-witness status`. To verify a cosigned checkpoint from another machine, use the log origin and keys already pinned locally:

```sh
W=https://witness1.example.org
H=$(printf '%s' '<log origin>' | sha256sum | cut -d' ' -f1)  # macOS: shasum -a 256
curl -fsS "$W/$H/checkpoint" > cp.txt
aics-tlog verify-checkpoint --note cp.txt --origin '<log origin>' \
    --vkey-file /path/to/local-log.vkey --witness-key '<your public witness vkey>' \
    --quorum 1 --max-age 600 --max-future 30
```

This smoke test checks your one cosignature; it does not substitute for the production two-of-three policy. Run the installed CLI or `uv run --project packages/aics-tlog aics-tlog` from the checkout root.

## Operational promises

Please keep the database, including its WAL after an unclean stop; never delete it or restore an older copy over newer state. Never run two live copies of one key. To move hosts, stop the witness and copy the entire volume before starting only the new host. If state is lost or rolled back, retire that identity and coordinate a new name and key through a noticed card change. Do not bypass the missing-database checks or recreate a database for an identity that has cosigned.

Keep NTP running, monitor `/healthz`, disk space and `status`, and inspect `aics-witness evidence` when it reports rejected histories. Preserve evidence and contact us about discrepancies. Missing tiles or a network timeout alone do not prove a fork. Tell us before retiring so we can notify clients and change policy without silently losing quorum. If you must stop urgently, stop signing and tell us as soon as practical.

We promise never to ask you to cosign anything but checkpoints, never to ask for your private key or a rollback of your database, and to put your identity and operational role in the card. You remain free to stop. Your signature does not endorse content or make you its custodian. We disclose the current implementation's Ed25519-only cosignatures, lack of ML-DSA-44 and lack of the optional `sign-subtree` API in the card, as required by AICS-1 §13.3.
