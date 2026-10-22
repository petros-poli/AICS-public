#!/bin/sh
# Entrypoint of the agents' image: prepare the agent's tmpfs HOME, then start the CLI given as arguments
# in $HOME/work.  For sol, the runner mounts a read-only copy of the codex sign-in at
# /run/agent-trials/codex-auth.json; codex wants it writable in CODEX_HOME, so it is copied there (0600).
# Everything here vanishes with the container.
set -eu
umask 077
mkdir -p "$HOME/work"
if [ -n "${CODEX_HOME:-}" ]; then
    mkdir -p "$CODEX_HOME"
    if [ -f /run/agent-trials/codex-auth.json ]; then
        cp /run/agent-trials/codex-auth.json "$CODEX_HOME/auth.json"
        chmod 600 "$CODEX_HOME/auth.json"
    fi
fi
cd "$HOME/work"
exec "$@"
