# deploy/card: the reviewed card body the server signs

docker-compose.yml mounts this directory read-only into aics-server as `/etc/aics/card`.
deploy-vps.sh sends it to the VPS with the rest of `deploy/`.

| File | What it is |
| --- | --- |
| `card-unsigned.json` | The filled card body, written here by `card/validate_card.py ... --final --write ../deploy/card/card-unsigned.json` (card/README.md, "Placeholders"). It is public: the server signs it with the policy key and serves the signed card. |
| `limits.json` | Optional. A limits file for `AICS_LIMITS_FILE=/etc/aics/card/limits.json`; the card must state the same windows and `retention.ciphertext_budget_bytes`. |

The body names the keys of the running server (`/data/pubkeys.txt`), so it is filled after the first start
(ops/RUNBOOK-first-deploy.md step 5). Then set `AICS_CARD_FILE=/etc/aics/card/card-unsigned.json` in the
VPS's `deploy/.env` and deploy again. The server refuses to start on a body that names other keys, holds a
`<FILL:...>` placeholder, or states limits or a ciphertext budget it does not enforce. Until the variable is set it
serves an unlogged skeleton (`X-AICS-Card-Source: skeleton`), which never goes into a trust bundle.
