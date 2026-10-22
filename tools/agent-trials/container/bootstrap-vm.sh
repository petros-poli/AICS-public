#!/usr/bin/env bash
# Prepare a fresh Debian or Ubuntu VM for agent trials in container mode (tools/agent-trials/README.md,
# "Cloud VM (container mode)").  Idempotent: run it again at any time, e.g. to rebuild the image.
#
#   bash tools/agent-trials/container/bootstrap-vm.sh        # as your normal user (it uses sudo), or as root
#
# It installs Docker from Docker's apt repository, rejects container TCP to production's gate ports
# 7700/7701 (DOCKER-USER chain, restored at every Docker start), builds the agents' image, creates the
# credentials file /etc/agent-trials/env (mode 600, names only) and prints the sign-in steps that need you.
# The VM must hold nothing but trial credentials: every agent can read its own provider's credential.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIALS_DIR="$(dirname "$HERE")"
IMAGE="${AGENT_TRIALS_IMAGE:-agent-trials:latest}"
ENV_DIR=/etc/agent-trials
ENV_FILE="$ENV_DIR/env"
CREDENTIAL_NAMES=(ZAI_API_KEY CLAUDE_CODE_OAUTH_TOKEN GEMINI_API_KEY)

if [ "$(id -u)" -eq 0 ]; then
    SUDO=()
    OWNER="${SUDO_USER:-root}"
else
    SUDO=(sudo)
    OWNER="$(id -un)"
fi
OWNER_GROUP="$(id -gn "$OWNER")"
OWNER_UID="$(id -u "$OWNER")"
OWNER_GID="$(id -g "$OWNER")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"

say() { printf '\n== %s\n' "$*"; }
as_root() { "${SUDO[@]}" "$@"; }

# -- the OS ------------------------------------------------------------------
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in
    debian) CODENAME="${VERSION_CODENAME:?}" ;;
    ubuntu) CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:?}}" ;;
    *) echo "bootstrap-vm.sh: Debian or Ubuntu only (this is ${PRETTY_NAME:-unknown})" >&2; exit 1 ;;
esac

say "base packages"
as_root apt-get update -qq
as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl python3 iptables >/dev/null

# -- Docker from Docker's apt repository (docs.docker.com/engine/install) ----
say "Docker (docker-ce from download.docker.com)"
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        as_root env DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq "$pkg" >/dev/null
    fi
done
as_root install -m 0755 -d /etc/apt/keyrings
as_root curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
as_root chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${CODENAME} stable" \
    | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null
as_root apt-get update -qq
as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin >/dev/null
as_root systemctl enable --now docker >/dev/null
RELOGIN=0
if [ "$OWNER" != root ] && ! id -nG "$OWNER" | tr ' ' '\n' | grep -qx docker; then
    as_root usermod -aG docker "$OWNER"
    RELOGIN=1
fi

# -- production's gate ports stay closed for every container --------------------
say "egress guard: containers may not open TCP to ports 7700/7701 (production's text gate)"
as_root tee /usr/local/sbin/agent-trials-egress >/dev/null <<'EOF'
#!/bin/sh
# agent-trials: no container may open TCP to production's text gate (ports 7700/7701, any host; on the VPS
# test.wesupport-ai.com:7700/7701 is production too).  Idempotent; run after every Docker start.
set -e
for tool in iptables ip6tables; do
    command -v "$tool" >/dev/null 2>&1 || continue
    "$tool" -n -L DOCKER-USER >/dev/null 2>&1 || continue
    rule="-p tcp -m multiport --dports 7700,7701 -j REJECT --reject-with tcp-reset"
    # shellcheck disable=SC2086
    "$tool" -C DOCKER-USER $rule 2>/dev/null || "$tool" -I DOCKER-USER $rule
done
EOF
as_root chmod 755 /usr/local/sbin/agent-trials-egress
as_root tee /etc/systemd/system/agent-trials-egress.service >/dev/null <<'EOF'
[Unit]
Description=agent-trials: reject container TCP to production's gate ports 7700/7701
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/agent-trials-egress

[Install]
WantedBy=docker.service
EOF
as_root systemctl daemon-reload
as_root systemctl enable agent-trials-egress.service >/dev/null 2>&1
as_root systemctl restart agent-trials-egress.service

# -- the agents' image -----------------------------------------------------------
say "image $IMAGE (from $HERE)"
as_root docker build --pull -t "$IMAGE" "$HERE"
# 192.0.2.1 (TEST-NET-1) is never routed: without the guard the probe times out, with it it is refused at once.
PROBE="$(as_root docker run --rm --pull never --network bridge --entrypoint nc "$IMAGE" -vz -w 5 192.0.2.1 7701 2>&1 || true)"
if grep -qi "refused" <<<"$PROBE"; then
    GUARD="holds (TCP to port 7701 is refused inside a container)"
else
    GUARD="NOT CONFIRMED: TCP to port 7701 was not refused inside a container; check 'sudo iptables -L DOCKER-USER'"
fi

# -- the credentials file (names only; you fill in the values) ---------------------
say "credentials file $ENV_FILE"
as_root install -d -m 0755 "$ENV_DIR"
if [ ! -e "$ENV_FILE" ]; then
    as_root install -m 0600 -o "$OWNER" -g "$OWNER_GROUP" /dev/null "$ENV_FILE"
    as_root tee "$ENV_FILE" >/dev/null <<'EOF'
# agent-trials credentials for container mode: plain NAME=value lines, no quotes needed; parsed, never sourced.
# Trial-only credentials: every agent can read its own provider's value inside its container.
# glm53, glm53flash: a z.ai API key
# sonnet: the long-lived token `claude setup-token` prints
# gemini: a Gemini API key (aistudio.google.com/apikey)
# sol: no entry here; it uses the codex device login in ~/.codex/auth.json
EOF
fi
for name in "${CREDENTIAL_NAMES[@]}"; do
    if ! as_root grep -q "^${name}=" "$ENV_FILE"; then
        echo "${name}=" | as_root tee -a "$ENV_FILE" >/dev/null
    fi
done
as_root chown "$OWNER:$OWNER_GROUP" "$ENV_FILE"
as_root chmod 600 "$ENV_FILE"
as_root install -d -m 0700 -o "$OWNER" -g "$OWNER_GROUP" "$OWNER_HOME/.codex"

# -- what needs you ----------------------------------------------------------------
AS_WHOM="as $OWNER"
if [ "$RELOGIN" = 1 ]; then
    AS_WHOM="$AS_WHOM, after logging out and in again (you were just added to the docker group)"
fi
cat <<EOF

== done.  Egress guard: $GUARD

Next steps ($AS_WHOM):

1. sol: sign codex in with the device flow (open the URL it prints on any machine, enter the code):

   docker run --rm -it --pull never --user $OWNER_UID:$OWNER_GID -e HOME=/tmp -e CODEX_HOME=/codex -v "$OWNER_HOME/.codex:/codex" --entrypoint codex $IMAGE login --device-auth

   This writes $OWNER_HOME/.codex/auth.json, which each sol container gets as a read-only copy.

2. sonnet: create a long-lived Claude token (it prints the token; the container is removed afterwards):

   docker run --rm -it --pull never --entrypoint claude $IMAGE setup-token

3. Put the values into $ENV_FILE (CLAUDE_CODE_OAUTH_TOKEN from step 2, ZAI_API_KEY, GEMINI_API_KEY):

   nano $ENV_FILE

4. Look first (executes nothing), then run a scenario:

   python3 $TRIALS_DIR/run.py --isolation container --scenario onboarding --providers sonnet,glm53flash,gemini,sol --count 1 --dry-run
   python3 $TRIALS_DIR/run.py --isolation container --scenario onboarding --providers sonnet,glm53flash,gemini,sol --count 1

   Results: $TRIALS_DIR/runs/<stamp>/REPORT.md
EOF
