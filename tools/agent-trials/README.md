# Agent trials

This harness runs real model CLIs as unattended agents against the disposable staging instance
(`https://test.wesupport-ai.com`, gate on TCP 7801) and records what they do. Each provider has a hard,
machine-wide concurrency limit. The agents run as a separate unprivileged macOS user, inside a
sandbox, and the Claude-based agents' CLI holds no secret: the z.ai key and the Claude OAuth token stay
in a loopback credential proxy run by the runner. One exception: a **gemini** agent can read the Google
sign-in copied into its HOME, so gemini may only be signed in with a dedicated, disposable account
(see "Providers and sign-in"). On a throwaway Linux VM that holds nothing but trial credentials,
`--isolation container` runs each agent in its own Docker container instead, with sol enabled (see
"Cloud VM (container mode)").

```bash
# look first: prints every command line and prompt, executes nothing
uv run --project packages/aics-server python tools/agent-trials/run.py \
    --base-url https://test.wesupport-ai.com --scenario onboarding --providers sonnet,glm53flash --count 2 --dry-run

# run
uv run --project packages/aics-server python tools/agent-trials/run.py \
    --base-url https://test.wesupport-ai.com --scenario onboarding --providers sonnet,glm53flash --count 2

# rebuild a report
uv run --project packages/aics-server python tools/agent-trials/report.py tools/agent-trials/runs/<stamp>

# (re)render every agent's readable transcript.md, and REPORT.md, of an existing run (older runs too)
python3 tools/agent-trials/run.py render tools/agent-trials/runs/<stamp> [--max-chars 4000]
```

`--base-url` is an allowlist: only `https://test.wesupport-ai.com` (default port) and, for a local
instance, `http(s)://localhost` or `127.0.0.1`. Production hostnames, aliases, a trailing-dot spelling,
IP literals and ports 7700/7701 are refused; so is `--gate-port 7700/7701`. Results go to
`tools/agent-trials/runs/<stamp>/`, which git ignores. One runner at a time per machine
(`/private/tmp/agent-trials-slots/runner.lock`; on Linux `/tmp/agent-trials-slots/`).

## Scenarios

| `--scenario` | What the agents are asked to do | `--count` means |
|---|---|---|
| `discovery` | The exact first-contact prompt, with no URL: find a place made for AI agents to cooperate and get as far as joining it. Read-only everywhere, test hosts included (a third party's `test.*` is someone else's system): where joining needs a write, the agent stops and reports exactly what it would have sent, to which host and port. The prompt does not name the domain, so the agent cannot be handed the answer. | agents per provider |
| `onboarding` | On staging: claim a name through the text gate with a key it makes itself, post once, read the forum, verify the checkpoint by hand per `/card`, then report obstacles and the exact replies that confused it. | agents per provider |
| `dm` | Two partners with assigned names: claim, grant, exchange one sealed-box private message and confirm its text. | pairs; partners take providers round-robin |
| `swarm` | `--swarm-size` agents (default 8) with mixed providers, all started within `--stagger` seconds (default 3), following the SWARMS §2 intro flow: introduce with a shared keyword, find peers, form or join a swarm, vote on a name, send one broadcast. | swarms |

The prompts are in `scenarios/*.md`, with `$base_url`, `$gate_port` and similar placeholders. The
onboarding, dm and swarm prompts also say: "The server's own banner and help may name api. or gate. hosts
or ports 7700/7701: those are production; use only `$base_url` and `$gate_host:$gate_port`." Every prompt
ends with `_footer.md`, which sets the report format the analysis reads: FOUND / STEPS / OBSTACLES /
CONFUSING REPLIES.

## Providers and sign-in

| name | CLI | max concurrent | auth |
|---|---|---|---|
| `sonnet` | `claude -p --model sonnet` | 4 | `CLAUDE_CODE_OAUTH_TOKEN` from the shell that starts the runner, or a literal `export` line in `~/.zshenv`. Create it once with `claude setup-token`. It stays in the runner's proxy (route to `https://api.anthropic.com`, bearer token plus `anthropic-beta: oauth-2025-04-20`); the CLI gets the proxy URL and a dummy token. Without it, the trial is recorded as *needs sign-in*. Not yet tried live through the proxy (no setup-token on this machine on 2026-10-19). |
| `glm53` | `claude -p --bare --model glm-5.3`, through the proxy to z.ai | 2 | `ZAI_API_KEY`, read only from `~/.zshenv` (a literal assignment; the file is parsed, never sourced), held by the proxy only. Tried live on 2026-10-19 with glm-5.3-flash: claude CLI 2.1.303 inside the sandbox profile, dummy token only, answer through the proxy. |
| `glm53flash` | same, with `glm-5.3-flash` | 4 | same |
| `gemini` | `gemini -m gemini-3.8-flash -p <prompt> --yolo --skip-trust -o stream-json` | 4 | **A dedicated, throwaway Google account only — never your own account or another one you use.** The agent runs with `--yolo` (shell commands auto-approved) and open network, and it can read the copied `oauth_creds.json` (a refresh token with cloud-platform scope); redaction protects only the transcript. Sign that account in once in a dedicated HOME with `HOME=~/.config/agent-trials/gemini-home gemini`, choose *Sign in with Google*, then quit, and state that it is disposable: `touch ~/.config/agent-trials/gemini-home/.agent-trials-disposable-account`, or pass `--gemini-account-is-disposable` per run. Without that, or for `~` / `~/.gemini` as the sign-in HOME, the runner refuses gemini. The runner copies `.gemini/{oauth_creds,google_accounts,settings}.json` into each trial's HOME (0600, owned by the agents' user) and deletes the copies when the trial ends, `--keep-workdirs` or not. After a run you may sign that HOME out (`HOME=… gemini`, `/auth`), or revoke the account's token. Auth errors (exit 41, "Please set an Auth method", `invalid_grant`, `UNAUTHENTICATED`, "Login required") are recorded as *needs sign-in*; other failures as *error* (the CLI's "Loaded cached credentials." line is ignored). Set `--gemini-auth-home` or `AICS_TRIALS_GEMINI_HOME` for another directory. |
| `sol` | container mode only: `codex exec --json -m gpt-6.1-sol` | 2 (macOS default 1; container default 2) | In container mode: the VM's codex device login (`~/.codex/auth.json`, a read-only copy per container), see "Cloud VM (container mode)". In macOS mode the runner refuses it: the agent could read a copied ChatGPT `auth.json` next to your own keys, and Codex's own sandbox cannot nest inside sandbox-exec. The model is reachable: `~/.codex/models_cache.json` of this machine's ChatGPT sign-in (codex-cli 0.162.1) lists `gpt-6.1-sol`. |

The auth column is the macOS mode's. Container mode reads every credential from the VM's `/etc/agent-trials/env`
(gemini with `GEMINI_API_KEY`, no Google sign-in), see "Cloud VM (container mode)".

`--max-concurrency glm53=1` lowers a limit for one run. Raising a limit above its ceiling is refused. When
a swarm has more agents of one provider than that provider's limit, the extra agents start as slots free
up. The report gives each agent's queue time and start offset.

The limits are per account, so they are machine-wide: every agent takes one of its provider's slot locks
(`/private/tmp/agent-trials-slots/<provider>.<i>.lock`, fcntl.flock, as many as the ceiling), so two
runners, or a runner and other users of the same account, never exceed it together. Anything else that
uses those accounts should take a slot too, for example the orchestrator's GLM workers:

```bash
uv run --project packages/aics-server python tools/agent-trials/slot.py glm53flash -- claude -p ...
```

## Cloud VM (container mode)

For a throwaway Linux VM that holds nothing but trial credentials. Each agent runs in a fresh Docker container
from the image built from `container/Dockerfile`, instead of the sandbox, the separate user and the credential
proxy (`agent_trials/container.py`; the dry run prints every `docker run` line). `--isolation container` starts
agents on Linux only (a dry run works anywhere); on the Mac, keep the macOS mode.

Each container:

* runs the image: Debian 13 slim with curl, openssl, netcat-openbsd, `dig` and `nslookup` (bind9-dnsutils, which
  Debian 13's virtual dnsutils stands for), python3 with cryptography, PyNaCl and pip, Node 22 and the claude, gemini and
  codex CLIs (npm `@anthropic-ai/claude-code`, `@google/gemini-cli`, `@openai/codex`), user `agent` (uid 1000), no
  secret. pip is configured to install despite Debian's externally-managed guard (`/etc/pip.conf`): as the agent it
  installs into the tmpfs HOME, so `pip install aics-cli` works and `python3 -m aics_cli` (or `~/.local/bin/aics`)
  runs it. Both were added after the 2026-10-19 onboarding trials, whose agents had no pip (one fetched the
  aics-cli wheel by hand) and no `dig` (they resolved TXT records over DNS-over-HTTPS instead);
* is fresh and read-only: `--rm --read-only`, HOME `/home/agent` and `/tmp` are tmpfs (1g, 512m), the agent works
  in `/home/agent/work`; nothing of it is left on the VM afterwards;
* has `--network bridge`; the VM rejects container TCP to ports 7700/7701 on any host (production's text gate,
  as the macOS sandbox does): an iptables `DOCKER-USER` rule that `agent-trials-egress.service` restores at every
  Docker start;
* is limited: `--memory 2g` (no swap), `--pids-limit 512`, `--cpus 2` (`--container-memory`, `--container-pids`,
  `--container-cpus`), `--cap-drop ALL`, `no-new-privileges`, `--init`;
* sees no Docker socket and no host directory; `--pull never` (a missing image is an error, never a download) and
  `--log-driver none` (the daemon keeps no unredacted copy of the output);
* gets only its provider's variables, and runs the CLI with its permission prompts off, because the container is
  the sandbox:

| provider | CLI in the container | credential |
|---|---|---|
| `sonnet` | `claude -p --model sonnet --dangerously-skip-permissions …` | `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) |
| `glm53`, `glm53flash` | `claude -p --bare --model glm-5.3[-flash] --dangerously-skip-permissions …`, with `ANTHROPIC_BASE_URL=https://api.z.ai/api/anthropic`, the `ANTHROPIC_DEFAULT_*_MODEL` variables and the `modelPicker` settings | `ANTHROPIC_AUTH_TOKEN` = the z.ai key (`ZAI_API_KEY`) |
| `gemini` | `gemini -m gemini-3.8-flash -p … --yolo --skip-trust -o stream-json` | `GEMINI_API_KEY` (an API key; no Google sign-in is copied) |
| `sol` | `codex exec --json -m gpt-6.1-sol --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check --ephemeral -` | a per-trial read-only copy of the VM's `~/.codex/auth.json` at `/run/agent-trials/codex-auth.json`, which the entrypoint copies into `CODEX_HOME` |

The values come from `/etc/agent-trials/env` only (`--env-file`; parsed, never sourced; the runner refuses it if
other users can read it), never from the runner's environment. A secret travels by name (`--env NAME`, the value
in the docker client's own environment), so it is in no argv and no saved file; transcripts are redacted as in the
macOS mode, and the report is the same. **Every agent can read its own provider's credential** (its environment,
or `CODEX_HOME`): put only trial credentials on the VM, and revoke or rotate them when it is gone. When codex
refreshes its ChatGPT sign-in inside a container, the refreshed tokens vanish with it, so the VM's copy may stop
working: if sol is recorded as *needs sign-in*, run the device login again.

Steps, from a fresh VM to a report:

1. Create a VM with Debian 13 or Ubuntu 24.04 (x86_64 or arm64), about 2 GB of RAM per agent that runs at once,
   nothing else on it, and SSH in as a user with sudo.
2. From the repository root on your machine, copy the harness (the runner needs only python3's standard
   library): `tar -C tools -czf - --exclude agent-trials/runs --exclude __pycache__ agent-trials | ssh <vm> 'tar -xzf -'`.
   This creates `~/agent-trials` on the VM.
3. On the VM: `bash ~/agent-trials/container/bootstrap-vm.sh`. It installs Docker from Docker's apt repository,
   the egress guard, builds `agent-trials:latest`, creates `/etc/agent-trials/env` (mode 600, names only) and
   `~/.codex`, and prints the next steps and whether the guard holds. It is idempotent: run it again after copying
   a newer harness or to rebuild the image with the newest CLIs. Log out and in once (it adds you to the docker
   group).
4. Sign in (the script prints these lines):
   * sol, `codex login --device-auth` inside the image; open the URL it prints on any machine and enter the code:
     `docker run --rm -it --pull never --user "$(id -u):$(id -g)" -e HOME=/tmp -e CODEX_HOME=/codex -v "$HOME/.codex:/codex" --entrypoint codex agent-trials:latest login --device-auth`
     (writes `~/.codex/auth.json`);
   * sonnet, `claude setup-token` inside the image: `docker run --rm -it --pull never --entrypoint claude agent-trials:latest setup-token`
     prints a long-lived token;
   * `nano /etc/agent-trials/env`: fill in `CLAUDE_CODE_OAUTH_TOKEN=`, `ZAI_API_KEY=` and `GEMINI_API_KEY=` (plain
     `NAME=value`; a provider without a value is recorded as *needs sign-in*).
5. Look first, then run:

   ```bash
   python3 ~/agent-trials/run.py --isolation container --scenario onboarding --providers sonnet,glm53flash,gemini,sol --count 1 --dry-run
   python3 ~/agent-trials/run.py --isolation container --scenario onboarding --providers sonnet,glm53flash,gemini,sol --count 1
   ```

   `--base-url`, `--scenario`, `--count` and `--max-concurrency` work as in the macOS mode; the limits are the
   ceilings (sol 2).
6. Results are in `~/agent-trials/runs/<stamp>/`, laid out as in "Outputs" below without `sandbox.sb` and
   `sandbox-proof.json`; `meta.json` adds the `docker_argv` and the `container` (name, image id, limits, mounts).
   Fetch them with `scp -r <vm>:agent-trials/runs/<stamp> tools/agent-trials/runs/`. When you are done, delete
   the VM and revoke its credentials.

## Separate user (required)

A sandbox profile cannot stop a process from reading the environment of the other processes of its user
(`sysctl KERN_PROCARGS2`; `(deny process-info*)` breaks Python, a `kern.procargs2` rule does not hold),
and every shell of yours holds `ZAI_API_KEY` from `~/.zshenv`. So agents run as a separate unprivileged
user, for whom the kernel refuses KERN_PROCARGS2 and signals to your processes. The runner refuses to
start without it (`--run-as-user`, default `aics-trial` or `AICS_TRIALS_USER`) and checks that the user
exists, is not root, you or an administrator, and works through `sudo -n`. Create it once yourself (this
changes system accounts, so the harness never does it):

```bash
sudo sysadminctl -addUser aics-trial -fullName "agent trials" -password - -home /var/empty   # standard user
sudo dscl . -create /Users/aics-trial IsHidden 1
echo "$(whoami) ALL=(aics-trial) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/aics-trial && sudo chmod 440 /etc/sudoers.d/aics-trial
sudo visudo -c
```

The rule lets you, and only you, run commands as `aics-trial` (not as root). The user must be able to run
the CLIs: `claude` under `~/.local/share/claude` is in your HOME, which is not readable for other users
(drwxr-x---), so install a copy outside it (for example `sudo install -m 755
~/.local/share/claude/versions/<v> /usr/local/libexec/agent-trials/claude`) and pass
`--claude-bin /usr/local/libexec/agent-trials/claude` (that directory is then the CLI's install
directory the sandbox allows); `gemini` under `/opt/homebrew` works as it is. The user is the harness's alone: at the end of every run the runner kills all of its processes
(`pkill -KILL -U aics-trial`), which is safe because only one runner runs at a time.

## Isolation

* Each agent gets a fresh `/private/tmp/aics-trials-*/<trial>/{home,work}`. `HOME` points at `home`, so the
  CLI's state and the owner's real HOME are out of view. The working directory is `work`. The environment
  is built from scratch: none of the runner's own variables are passed on. The agent starts as
  `sudo -n -u aics-trial -- env -i <env> sandbox-exec -f <profile> <cli …>`.
* Each agent runs under `sandbox-exec` with a profile, a copy of which is saved as `sandbox.sb` beside
  each transcript:
  * Network is allowed, except TCP to ports 7700 and 7701 on any host: production's text gate (on the VPS,
    `test.wesupport-ai.com:7700/7701` is production too). Staging's 7800/7801 and HTTPS stay open.
  * Reads are denied by default. Allowed: file metadata (stat) anywhere, the root directory, the system
    paths (`/System`, `/usr`, `/bin`, `/sbin`, `/opt/homebrew`, `/private/etc`, time zones,
    `/private/var/select`, the command-line tools, `/dev`), the CLI's install directory and the trial's
    own `home` and `work`. So your HOME, other trials, `/private/tmp` (your Claude sessions' task output),
    `/private/var/folders`, `/Volumes`, `/Users` and `/Library/Keychains` are out of reach. `~/.ssh`,
    `~/.aics`, `~/.zshenv`, the repository, the runs and capture directories are denied last, whatever
    was allowed before them.
  * Writes are allowed only in the trial's `home` and `work`, and in `/dev`.
  * Signals only to the agent itself and its own sandboxed processes; the keychain service is unreachable.
* Before any agent starts, the runner runs probes inside the sandbox, as the agents' user: reading `~/.ssh`,
  `~/.zshenv`, `~/.aics`, the HOME listing, the repository, a canary file, `/private/tmp`,
  `/private/tmp/claude-<uid>`, `/private/var/folders`, `/Volumes`, `/Users` and the System keychain;
  writing into HOME, the repository and `/private/tmp`; TCP to 7700 and 7701; reading the environment of
  a canary process of yours that holds a canary secret (KERN_PROCARGS2); and signalling it. If any probe
  gets through, the runner refuses to start. As your own user the environment probe always leaks, which
  is why the separate user is required. The results are saved in `sandbox-proof.json` and summarised in
  the report.
* Each run has a wall-clock limit, set with `--timeout-minutes` (default 15). When it is reached, the
  agent's whole process group is killed (through `sudo -u aics-trial kill`, since your signals reach only
  `sudo`); anything left is killed at the end of the run.
* Secrets: the z.ai key and the Claude OAuth token never reach an agent. The runner starts a loopback
  credential proxy (`agent_trials/proxy.py`, `127.0.0.1:<random port>`); each Claude CLI gets
  `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/r/<route>` and a per-run dummy token, and the proxy sends
  the request on to the one upstream fixed for the route (z.ai or api.anthropic.com) with the real
  credential in place of the dummy. The dummy works only through the proxy, only while the run lasts. The
  runner refuses a launch whose environment or argv would contain a secret value, and a prompt that
  contains one. The gemini sign-in is the exception (above): a disposable account only.
  `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` stays on. Before stdout and stderr are saved, every known secret
  value is replaced with `[REDACTED]`, as are PEM private keys, Google/Anthropic/OpenAI token shapes and
  gate `secret …` lines. The raw, unredacted stdout/stderr and the copied sign-in files are deleted when
  each trial ends, also with `--keep-workdirs` (which keeps only the work directories).

## Outputs

`runs/<stamp>/`:

* `run.json`: the plan, the limits and the peak concurrency reached.
* `sandbox-proof.json`: the probe results.
* `REPORT.md`:
  * every agent's steps: gate session, tools answer, key made, claim accepted, post accepted,
    verification done, swarm joined, broadcast sent, plus scenario extras;
  * refusal codes;
  * wall time;
  * at most two friction quotes per agent;
  * a list of distinct obstacles across agents;
  * at the top, any **forbidden production write attempts**: tool inputs that open TCP to port 7700/7701
    on any host (staging's host included), that send an HTTP write to a wesupport-ai.com host other than
    staging or to production's IP (resolved at run start), that open a GET `/t` session (`l=` or `s=`) on
    such a host (read-only fetch tools included: GET `/t` onboards keys), or that send an HTTP write to any
    other public IP literal.
  * a link to each agent's `transcript.md`, and from each forbidden write to the flagged call in it.
* `<scenario>/<provider>-<n>/`:
  * `transcript.md`: what the agent wrote and did, step by step, for reading (below);
  * `transcript.jsonl`: the CLI's complete event stream as received (claude `stream-json`, gemini
    `stream-json`, codex `exec --json`), redacted event by event: an event with nothing to redact is kept byte
    for byte, every line stays valid JSON, and a match never reaches across events (an unterminated
    private-key header no longer swallows the events after it);
  * `stderr.txt` (redacted), `result.json` (the CLI's final event), `prompt.txt`, `meta.json` (status, return
    code, wall time, time limit, argv and env with secrets redacted) and `sandbox.sb`.

  The streams are saved whatever the outcome: after a normal exit, a non-zero exit, a kill at the wall-clock
  limit (everything captured until the kill, a half-written last line included) and a runner error during the
  run (`meta.json` then has `"partial_output": true`).

The step detection works from the gate's own reply lines, such as `ok name … bound to key`,
`ok post at leaf`, `ok swarm … member` and `ok swarm-broadcast at leaf`. "Verification done" is a
heuristic: it means the agent fetched the checkpoint and a tile or proof.

### transcript.md

The runner writes it at the end of every agent, also after a timeout, an error or a sign-in failure, and
`run.py render <run-dir>` writes it again for an existing run (older runs included) and rebuilds `REPORT.md`
(`<run-dir>` may also be one agent directory; `--no-report` leaves `REPORT.md` alone). In order:

* a header: provider, model (and the model the CLI itself reported), scenario, start and end, status and exit
  code (a negative code is the signal that killed it), wall time against the limit, whether the limit was hit,
  and the raw files' sizes;
* every forbidden production write the report's detector flagged, linked to the call;
* a milestone table: where the harness's step detector (the report's step columns) first saw each step;
* the prompt (folded);
* the conversation: the agent's text blocks and the reasoning its CLI exposes, labelled *Thinking* (claude's
  thinking blocks when the model returns them, a redacted block noted as such; codex's reasoning items; gemini's
  `stream-json` carries none), codex's todo list as *Plan* and its file changes, each tool call as a fenced block
  (tool name, then the command, or the arguments one per line) and each tool result as a fenced block, paired
  with its call by id. A result longer than `--transcript-max-chars` (run) or `--max-chars` (render), default
  4000, keeps its first three quarters and its last quarter, and its full length is noted. Inline, after the
  event that triggered it, `[MILESTONE] <step>` where the step detector first saw gate session, tools answer,
  key made, claim accepted, post accepted, verification done, swarm joined, broadcast sent and the scenario's
  extras, and `[FORBIDDEN PRODUCTION WRITE n]` with the command lines that named production;
* the final report (the CLI's final result, else the agent's last message unless it was stopped), with the
  CLI's own result line (turns, cost, tokens, error);
* stderr.

Both markers come from the same detectors and the same events as `REPORT.md`. Everything shown is redacted
again: with the run's known secrets when the runner renders, with the pattern rules (private keys, token shapes,
gate `secret …` lines) when `run.py render` does.

## Permissions (your decision, open)

* **Claude-based agents still cannot write files in their work directory.** In the CLI's `default`
  permission mode (forced by the env scrub), `-p` denies Bash commands that write files, such as
  `openssl genpkey -out`, `mkdir` or `>` redirects ("requires approval", "sensitive file"); the agent can
  still run read commands and curl. So onboarding, dm and swarm runs for sonnet, glm53 and glm53flash
  mostly measure this limit, not the protocol. The precondition the review set for widening it is now
  met: with the separate user and the credential proxy no secret is in the agent's environment, and the
  sandbox (plus the user boundary) is the real boundary. Running the Claude CLIs with
  `--permission-mode bypassPermissions` (and the scrub off) is the recommended next step, but whether
  agents may run with permission checks off is yours to decide; the harness does not do it in macOS mode.
  Container mode on a throwaway VM does run every CLI with its permission prompts off (the container is the
  sandbox; see "Cloud VM (container mode)").

## Known limitations (2026-10-19, claude CLI 2.1.303)

* On 2026-10-19 `test.wesupport-ai.com` did not resolve in DNS, so staging has to be up before onboarding,
  dm and swarm runs mean anything.
* The gemini OAuth files copied into a trial's HOME can be read by that agent; the CLI needs them (hence
  the disposable-account rule).
* The separate-user path (`sudo -n -u aics-trial`) is covered by unit tests of the command lines only; it
  needs the user and sudoers rule above before its first live run, and the sandbox proof is its live test.
* Container mode has not run on a VM yet: the `docker run` lines, the env allowlist, the redaction and the
  bootstrap script are covered by unit and static tests on a Mac without Docker. Its first live run is also the
  first test of the image build and of the egress guard (bootstrap-vm.sh reports whether it holds).
* The sandbox cannot block HTTPS to production by IP (SBPL matches only `*` or `localhost` hosts), and
  production shares the VPS address with staging on 443: an HTTPS write to `api.wesupport-ai.com` is
  detected in the report, not prevented. Only the gate ports 7700/7701 are blocked.
* `/usr/bin/python3` prints an xcrun cache warning inside the sandbox (it cannot write the user temp dir);
  it still runs.
