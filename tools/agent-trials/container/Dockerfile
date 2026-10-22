# The agents' image for container mode (tools/agent-trials/README.md, "Cloud VM (container mode)").
# run.py --isolation container starts one fresh container per agent from it, read-only, with a tmpfs HOME.
# It holds the three model CLIs and the tools the scenarios need, and no secret: credentials arrive per
# container (its environment, or for sol a read-only copy of the codex sign-in) and vanish with it.
#
#   docker build -t agent-trials:latest tools/agent-trials/container      (bootstrap-vm.sh does this)
#
# Pin a CLI with --build-arg, e.g. --build-arg CODEX_VERSION=0.162.1.
FROM debian:13-slim

ARG NODE_MAJOR=22
ARG CLAUDE_CODE_VERSION=latest
ARG GEMINI_CLI_VERSION=latest
ARG CODEX_VERSION=latest

SHELL ["/bin/sh", "-eu", "-c"]

# Base tools, then Node from NodeSource's signed apt repository. bind9-dnsutils is dig and nslookup (Debian 13's
# dnsutils is a virtual package it provides), so an agent can resolve a TXT record such as _aics.<domain>;
# python3-pip lets it install a client such as aics-cli from PyPI.
RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl openssl netcat-openbsd bind9-dnsutils \
        python3 python3-cryptography python3-nacl python3-pip; \
    install -d -m 0755 /etc/apt/keyrings; \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /etc/apt/keyrings/nodesource.asc; \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*; \
    node --version | grep -q "^v${NODE_MAJOR}\."

# pip in a disposable image: Debian's externally-managed guard (PEP 668) is lifted, so "pip install aics-cli" works
# as the agent; as uid 1000 on the read-only image pip installs into the tmpfs HOME (~/.local), gone with the container.
RUN printf '[global]\nbreak-system-packages = true\n' > /etc/pip.conf; \
    python3 -m pip --version; \
    dig -v

# The CLIs: claude (sonnet and the GLM providers through z.ai), gemini, codex (sol).
RUN npm install -g --no-fund --no-audit --no-update-notifier \
        "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
        "@google/gemini-cli@${GEMINI_CLI_VERSION}" \
        "@openai/codex@${CODEX_VERSION}"; \
    npm cache clean --force; \
    export HOME=/tmp/version-check; \
    claude --version; gemini --version; codex --version; \
    rm -rf /tmp/version-check /root/.npm

# The unprivileged agent user (uid 1000, as container.AGENT_UID expects); its HOME is a tmpfs at run time.
RUN useradd --uid 1000 --user-group --home-dir /home/agent --create-home --shell /bin/bash agent; \
    install -d -m 0755 /run/agent-trials

COPY --chmod=0755 entrypoint.sh /usr/local/bin/agent-entrypoint

USER 1000:1000
WORKDIR /home/agent
ENTRYPOINT ["/usr/local/bin/agent-entrypoint"]
CMD ["/bin/bash"]
