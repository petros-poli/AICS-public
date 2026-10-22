# Releasing AICS

The release pipeline implements the build and release part of DESIGN.md §3 G7,
§4.2 item 6 and §12 “After”: reproducible distributions, keyless Sigstore
signatures, and SLSA provenance tied to the source commit. G7 remains **promised**:
these files do not attest a live server's memory, publish release-hash log leaves,
or prove that an operator runs the published code. Public source is also required
before claiming public code transparency; a private repository cannot provide it.

This public repository contains a reviewed, filtered source snapshot with its
own history. The instructions below configure releases built by
`petros-poli/AICS-public`. Package publication is separate from source
publication. For an existing artifact, verify its actual Sigstore/SLSA
repository identity and source commit; a source link alone does not prove
which workflow built it.

## One-time setup

1. Enable GitHub Actions for `petros-poli/AICS-public`, including the actions and reusable
   workflow referenced in these files. Use GitHub-hosted Ubuntu runners. Actions
   runs only for `v*` tags (see [What a tag starts](#what-a-tag-starts)); routine
   verification is local (CONTRIBUTING.md). **Do not require any status check on
   `main`**: no workflow runs on pull requests or branch pushes, so a required
   check would never report and would block every merge. Restrict creation and
   modification of `v*` tags to release maintainers where the plan allows it (see
   [Repository settings](#repository-settings) for what is in force today).
2. Create the six GitHub Actions environments listed below. Restrict each to
   `v*` tags; add environment reviewers if desired. The exact environment name
   is part of each project's publisher identity.
3. In PyPI, configure a GitHub trusted publisher for **each** project below. For
   an existing project use **Manage → Publishing**. For a new project register a
   [pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
   under your account's Publishing settings; first publication creates the project.

   | Field | Value |
   | --- | --- |
   | Repository owner | `petros-poli` |
   | Repository name | `AICS-public` |
   | Workflow filename | `release.yml` (no directory prefix) |

   | PyPI project | GitHub environment |
   | --- | --- |
   | `aics-identity` | `pypi` |
   | `aics-tlog` | `pypi-aics-tlog` |
   | `aics-witness` | `pypi-aics-witness` |
   | `aics-conformance` | `pypi-aics-conformance` |
   | `aics-cli` (`packages/aics-cli`) | `pypi-aics` |
   | `aics-mcp` | `pypi-aics-mcp` |

   Distinct environments are necessary for initial project creation: PyPI
   rejects pending publishers with identical owner, repository, workflow and
   environment under different project names. It also permits only **three
   pending publishers per account** at once. These constraints are enforced by
   [PyPI's publisher registration implementation](https://github.com/pypi/warehouse/blob/fbbd1acf790826370ba97c4257e8c81291a03f2c/warehouse/accounts/views.py#L1928-L2004).
   Use the first-release sequence below; do not try to register all six pending
   publishers simultaneously. Once a pending publisher creates its project, it
   becomes an ordinary publisher and frees a pending slot.

   Do not configure `aics-server`: it is tested but never built or uploaded by the
   release pipeline. Use `[project].name` from each included `pyproject.toml`,
   not its directory name: the CLI distribution is `aics-cli`; its command remains `aics`. PyPI documents the publisher identity fields in
   [Adding a trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).
4. Leave the **repository** Actions variable `PUBLISH_PYPI` absent for GitHub-only
   releases. Set it to the literal string **`true`** once all included projects
   have publishers configured and are ready for public distribution, or once
   the first three are configured for the controlled bootstrap below. Every other
   value skips PyPI; the `prepare` job logs the reason. No API token, signing
   key, password, or long-lived secret is used. GitHub's job token and OIDC tokens
   are short lived. Setting the variable does not rerun completed jobs.
5. Leave both optional repository variables **`PYPI_ONLY_PROJECT`** and
   **`PYPI_PROJECTS`** empty to publish all six projects. The existing
   `PYPI_ONLY_PROJECT` selects one distribution, such as `aics-cli`.
   `PYPI_PROJECTS` selects a comma-separated list, such as
   `aics-tlog,aics-conformance`. Set at most one selector, even if their values
   would select the same project. The preparation job validates every name
   against the six-project list, normalizes case and runs of `-`, `_` or `.` as
   PyPI does, and freezes a sorted JSON list in its outputs. Unknown names,
   whitespace, empty list members and duplicate normalized names are errors.
   A selector does not enable publishing by itself:
   `PUBLISH_PYPI` must still be exactly `true`. Every publishing step uses the
   frozen value, including when a failed publishing job is rerun; changing the
   repository variable does not change an existing run's selection.

The SLSA workflow uses `private-repository: false` for this public repository.
Signing publishes repository/workflow identity, source identifiers and artifact
digests to public Sigstore transparency infrastructure. Configure publishers
for this repository before enabling package distribution.

## Cut a release

1. Review the release commit and its package metadata. `scripts/verify.sh --full`
   tests **every** `packages/*/pyproject.toml`, including future packages and the
   server. Release discovery selects `aics-identity`, `aics-tlog`, `aics-witness`,
   `aics-conformance`, `aics-cli`, and `aics-mcp` when their metadata files exist.
   Confirm all six ordinary publishers, or the first three pending publishers
   for the initial release sequence below, before enabling PyPI.
2. Set each included library's version deliberately, update its changelog and
   dependency constraints, and run `scripts/verify.sh --full` on the release
   commit, once per supported Python version on the Linux VM (CONTRIBUTING.md,
   "Python versions"). The release commit, or the merge that produced it, carries
   the `Verified:` line for each run. Nothing on GitHub reports this result; the
   release workflow runs the same script again before it builds anything.
   The repository tag identifies a release of the monorepo; package versions come
   from their own `pyproject.toml` and need not match one another or the tag.
   When publishing to PyPI, **every selected package/version must be new**. By
   default all six libraries are selected; `PYPI_ONLY_PROJECT` can select one,
   or `PYPI_PROJECTS` can select a reviewed subset. Publishing never skips existing files. PyPI
   disallows reusing a published filename, including after deletion.
3. Create and push an immutable `v*` tag pointing to the reviewed commit, using
   your normal source-control tool. Prefer names such as `v0.2.0` or `v0.3.0-rc1`
   (the verification script accepts letters, digits, dots, plus, underscore and
   hyphen after the initial `v`). The tag's commit must contain `release.yml`, any
   local workflow it calls, and `scripts/verify.sh`: the run uses the files at the
   tagged commit.
4. Watch **Release**, the only workflow the tag starts. It verifies the tagged
   commit once with `scripts/verify.sh --full` and builds each library twice, as
   described under [What a tag starts](#what-a-tag-starts). Only the first copy of
   distributions whose two builds match can reach signing. The signed
   `SHA256SUMS` inventory and all distribution digests become SLSA subjects. The generator creates a draft release with
   `aics.intoto.jsonl`; the next job adds distributions, `.sigstore.json` bundles,
   base64 `.sig` signatures and PEM `.crt` certificates, then publishes the draft.
5. If enabled, approve any required per-project environment deployments and
   inspect the selected trusted publishing jobs. Each selected job checks that its wheel and
   sdist have the expected project metadata, matching versions and verified
   inventory hashes, then uploads only those two files using
   `pypa/gh-action-pypi-publish` and GitHub OIDC. Verify the GitHub Release as
   described below before using its artifacts.

### What a tag starts

Pushing a `v*` tag starts one workflow run, **Release** (`release.yml`), and
nothing else: no standalone CI, interop or reproducibility run starts for the tag,
and none starts for pushes to `main`, pull requests, documentation edits or a
schedule. The run has one path:

1. `prepare` refuses to replace a published release and freezes the PyPI policy.
2. Verification runs `scripts/verify.sh --full --strict` once at the tagged
   commit (Python 3.12.12, Node 24), the same script contributors run locally,
   through the reusable `ci.yml` (now named **Verify**). The reusable
   `interop.yml` runs the same script's interop check
   (`scripts/verify.sh --full --only interop --strict`) on the other supported
   Python releases (3.13.15 and 3.14.7). Any failed check, any `SKIPPED` or
   `PREREQ` line, and any change to tracked files fails the release; the interop
   suite runs with `AICS_INTEROP_REQUIRE_TOOLS=1`, so a missing `openssl`,
   `ssh-keygen` or `git` cannot drop its tests.

   Two of the checks in that run are deliberate gates beyond the libraries.
   `python:card:launch` runs the card's launch-blocker tests (card/README.md);
   no library depends on `card/`, but a reopened launch blocker means the
   checkout disagrees with what the card states, so it stops the release until
   it is fixed. The six `reproducible:<library>` checks build each library twice
   inside the Verify job, a cheap pre-check (seconds); they are not release
   evidence and do not replace the isolated pair of builds in step 3.
3. Each of the six libraries is built **twice**, on two separate fresh runners
   (twelve build jobs in all), and the comparison job exports only distributions
   whose wheel and sdist hashes match (details under
   [Reproducibility and maintenance](#reproducibility-and-maintenance)).
4. Signing, SLSA provenance, the GitHub Release and the per-project PyPI jobs
   follow, each with the permissions and identities described in this document.

Before this change a tag started CI and Reproducible builds as standalone runs
**and** Release called both again, so every library was built four times (24
build jobs). The standalone runs produced no release evidence; they are gone.
The release evidence is unchanged: two isolated builds whose hashes must match,
Sigstore signing and SLSA provenance under the same `release.yml` identity, and
the same six PyPI environments and trusted publishers.

GitHub reads a tag's triggers from the tagged commit. The workflow change that
removed the `push` and `pull_request` triggers from `ci.yml`, `interop.yml` and
`reproducible.yml` (they remain as reusable workflows that only `release.yml`
calls) and moved verification to `scripts/verify.sh` is commit `b9a976e`. A tag
on a commit before `b9a976e` still contains the old triggers and starts the old
duplicate runs: tag only commits that contain `b9a976e`
(`git merge-base --is-ancestor b9a976e <commit>`). `tools/test_workflows.py`
fails if a trigger, a second call of a reusable workflow, an unpinned action or
a missing timeout comes back.

### Retries

- **The run did not start.** If Actions refuses to start jobs (for example while
  the account's Actions usage is blocked), the run fails before any step runs:
  nothing was built, signed or published. Once Actions can run again, open the
  same run and choose **Re-run all jobs** (or
  `gh run rerun RUN_ID --repo petros-poli/AICS-public`). Do not delete, move or re-push
  the tag. `prepare` still refuses if a release for the tag was already published.
- **Verification failed.** A real failure needs a fix, a new commit, a new
  `Verified:` line and a **new tag**; the tag is immutable. If the log shows an
  infrastructure fault rather than a test failure (a runner lost, a download
  timed out), **Re-run failed jobs** on the same run reruns verification and the
  jobs after it with the same commit.
- **The two builds differ.** A hash mismatch is a defect, not a flake. Do not
  rerun until it passes; find the source of non-determinism, fix it, and cut a
  new tag. The `reproducibility-hashes` artifact keeps both hash sets.
- **Signing, provenance or the GitHub Release failed.** Investigate first: a
  failed run may leave a draft release with partial assets. Do not rerun the
  provenance generator's job alone after publication (see below).
- **A PyPI job failed.** Rerun only that failed job, as in the first-publication
  sequence below; it reuses the run's verified artifacts and its frozen project
  selection.

### Publish only the renamed CLI distribution

The Python distribution is `aics-cli`, installed with `pip install aics-cli`.
The import remains `aics_cli` and the console command remains `aics`. The earlier
`aics` PyPI project is owned separately; a JSON endpoint returning 404 does not
prove that a project name is available.

`aics-cli` 0.1.0 was first published by `v0.2.1` after production genesis, with
the production trust bundle in the release source. That tag and its artifacts
are immutable.

For a future CLI-only release, use a new CLI version and the existing publisher
with environment `pypi-aics`, set `PUBLISH_PYPI=true` and
`PYPI_ONLY_PROJECT=aics-cli`, leave `PYPI_PROJECTS` empty, then create a new
immutable tag after `scripts/verify.sh --full` passes locally. All six
distributions are still built, tested, signed and included in the GitHub
release, but only the CLI's wheel and sdist are uploaded to PyPI. The other
five matrix entries skip their download, selection and publishing steps, so their existing versions are
not uploaded again.

Verify the new CLI's PyPI bytes against the correction release's signed
inventory. Verify the other five existing PyPI versions against the release
that originally published them; a later rebuild can have different bytes.
Clear both selectors before the next release intended to publish all six
projects, and give every selected package a new unused version.

### Releasing without GitHub Actions (the way 0.1.1 ships, 2026-10-22)

The private repository's free Actions minutes are used up and paid usage is not approved
(owner, 2026-10-22), so the Release workflow does not run for `v0.3.1`. The distributions
are built on the owner's machine from the tag and uploaded with the owner's PyPI account:

```sh
git worktree add --detach /tmp/aics-v0.3.1 v0.3.1
(cd /tmp/aics-v0.3.1/packages/aics-cli && uv build --no-sources && shasum -a 256 dist/*)
# build twice, from two copies: the wheel and sdist SHA-256 must agree (reproducible builds)
uv publish --token <the owner's PyPI API token> /tmp/aics-v0.3.1/packages/aics-cli/dist/*
python3 -m venv /tmp/aics-cli-0.1.1 && /tmp/aics-cli-0.1.1/bin/pip download --no-deps -d /tmp/aics-cli-0.1.1/dl "aics-cli==0.1.1"
shasum -a 256 /tmp/aics-cli-0.1.1/dl/*   # must equal the built files' digests
```

What this path lacks, and the README says so for 0.1.1: the GitHub Release page, the
Sigstore signatures and the SLSA provenance that the workflow attaches. The source is the
tag `v0.3.1` in the public repository, and the reproducible build lets anyone check the
uploaded files against it. Actions remain reserved for `v*` tags; they run only when the
owner approves paid minutes or a public repository runs them.

### The relaunch of 2026-10-20: aics-cli 0.1.1

The relaunch (docs/DECISIONS.md, "Relaunch: a second genesis before any outside
agent used the log"; ops/RUNBOOK-first-deploy.md step 11) replaced the production log, so
`aics-cli` 0.1.0 carries the trust bundle of a discarded log, and with it
installed `aics policy init --from-dns wesupport-ai.com` stops with exit 2. The
version, changelog and lock files already say 0.1.1; the new bundle exists only
after the second genesis, and `ops/relaunch-genesis.sh docs` writes it into
`packages/aics-cli/src/aics_cli/published_keys.py`. Cut the release from the
commit that carries it, and only then:

1. Check the commit (from its checkout):

   ```sh
   python3 - <<'PY'
   import ast, hashlib, pathlib, re
   text = pathlib.Path("packages/aics-cli/src/aics_cli/published_keys.py").read_text()
   jcs = ast.literal_eval(re.search(r"^AICS_TRUST_BUNDLE: bytes \| None = (b'.*')$", text, re.M).group(1))
   sha = re.search(r"^AICS_TRUST_BUNDLE_SHA256: str \| None = '([0-9a-f]{64})'$", text, re.M).group(1)
   assert hashlib.sha256(jcs).hexdigest() == sha, "the constant and its digest disagree"
   assert sha != "bc234cc34b1b0941d0e833c41112109fe7fe020cebbba9f58f98f3a59448da0c", "still the discarded log's bundle"
   assert f"sha256: {sha}" in pathlib.Path("README.md").read_text(), "the README block names another bundle"
   assert 'version = "0.1.1"' in pathlib.Path("packages/aics-cli/pyproject.toml").read_text()
   print("ok", sha)
   PY
   dig +short TXT _aics.wesupport-ai.com @1.1.1.1   # the aics1= value of the README block
   scripts/verify.sh --full
   ```

2. Select the CLI alone (the variables are read once, by `prepare`):

   ```sh
   gh variable set PUBLISH_PYPI --repo petros-poli/AICS-public --body true
   gh variable set PYPI_ONLY_PROJECT --repo petros-poli/AICS-public --body aics-cli
   gh variable list --repo petros-poli/AICS-public   # PUBLISH_PYPI true, PYPI_ONLY_PROJECT aics-cli, no PYPI_PROJECTS
   ```

3. Tag the reviewed commit with the next tag (the last one is `v0.3.0`) and push it:

   ```sh
   git tag -a v0.3.1 -m "aics-cli 0.1.1: the trust bundle of the 2026-10-20 relaunch" <commit>
   git push origin v0.3.1
   gh run list --repo petros-poli/AICS-public --workflow release.yml --limit 1
   gh run watch --repo petros-poli/AICS-public <run id>
   ```

   All six libraries are built, tested and signed; only the `aics-cli` job of the
   `pypi` matrix uploads (environment `pypi-aics`).

4. Once `prepare` has run, put the variables back (a rerun of a failed PyPI job keeps
   the run's frozen selection), then check what was published:

   ```sh
   gh variable set PUBLISH_PYPI --repo petros-poli/AICS-public --body false
   gh variable delete PYPI_ONLY_PROJECT --repo petros-poli/AICS-public
   bash scripts/verify-release.sh v0.3.1
   python3 -m venv /tmp/aics-cli-0.1.1 && /tmp/aics-cli-0.1.1/bin/pip install "aics-cli==0.1.1"
   /tmp/aics-cli-0.1.1/bin/aics --home /tmp/aics-cli-0.1.1/home policy init --from-dns wesupport-ai.com
   ```

   The last command must name the trust root `dns + pypi` with no `--bundle`.

5. Yank 0.1.0 (the owner, on pypi.org: `aics-cli`, Manage, Releases, 0.1.0, Options,
   Yank) with the reason "Carries the trust bundle of the log discarded on
   2026-10-20; use 0.1.1." A yanked release stays installable with an exact pin, and
   with it `aics policy init` refuses the new DNS record (exit 2): it fails closed. The
   `v0.2.1` release that built 0.1.0 stays as it is; its tag and assets are immutable.

6. Only now deploy the site from the tagged commit's main (`bash ops/sync-docs.sh
   deploy/docs-public && bash deploy/deploy-vps.sh wesupport-vps`): it serves
   docs/DECISIONS.md, which says that 0.1.1 is on PyPI and 0.1.0 is yanked. Deploy it
   only if no file the server image is built from changed since the relaunch's deploy
   (`packages/aics-identity`, `aics-tlog`, `aics-witness`, `aics-server`,
   `deploy/Dockerfile`, `deploy/requirements.txt`, `deploy/build-requirements.txt`), so
   the running build stays the one the card's conformance reports describe. Then refresh
   the public repository AICS-public from the same commit right away, without waiting for
   the public-log dataset revision (a second refresh links that revision later).

### Publish a reviewed subset

For the post-genesis Python updates, the changed distributions are
`aics-tlog` 0.2.1 (bounded Merkle tree cache) and `aics-conformance` 0.1.1
(permanent nonce uniqueness, including authenticated refusals). Their package
changelogs describe the changes. The other four distributions retain their
existing versions and must not be uploaded again.

After reviewing the source, tests and public snapshot, set `PUBLISH_PYPI=true`,
leave `PYPI_ONLY_PROJECT` empty and set
`PYPI_PROJECTS=aics-tlog,aics-conformance` before creating a new immutable tag.
The preparation job rejects conflicting selectors before building or publishing.
All six distributions are still built, tested and signed. Each publishing step
uses only the frozen list, so only the selected wheel/sdist pairs are uploaded.
Rerunning a failed publishing job uses that run's original selection, even if
repository variables have since changed.

Check each selected version's public PyPI bytes against this release's signed
inventory. Existing unselected PyPI versions still belong to their original
release inventories; do not compare them to a later rebuild. Clear both
selectors before a future all-project release, or deliberately set a new subset.

### First publication with PyPI's three-pending-publisher limit

1. Register pending publishers for `aics-identity`, `aics-tlog` and
   `aics-witness` using their exact environments above. Create all six GitHub
   environments and pass `scripts/verify.sh --full` locally before setting
   `PUBLISH_PYPI=true` and pushing the reviewed immutable release tag.
2. The three configured publishing jobs create their projects. The remaining
   three fail during OIDC authentication, before uploading any distributions.
   The matrix uses `fail-fast: false`, so those failures cannot cancel the
   configured jobs. Confirm that the first three versions are live and that
   their publishers have converted to ordinary publishers.
3. Register pending publishers for `aics-conformance`, `aics-cli` and `aics-mcp`,
   using the newly freed slots and their distinct environments.
4. Inspect the failed job logs to confirm that **only those three PyPI jobs**
   failed before uploading. Choose **Re-run failed jobs** on the same Release
   run (or `gh run rerun RUN_ID --failed --repo petros-poli/AICS-public`). This preserves
   successful uploads and reuses the original verified distribution artifacts.
   Do not rerun the whole workflow, successful PyPI jobs, signing, provenance or
   GitHub release publication. Confirm all six exact versions on PyPI afterward.

This sequence is needed only while the projects are new. If a failure occurs
after any files were accepted, follow the partial-upload guidance below rather
than assuming it is safe to rerun that publishing job.

Do not move a published tag. The preparation job refuses to rerun the full release
pipeline for an already published release; rerun only a failed PyPI job after
resolving its cause. The upstream generator can modify a release, so do not rerun
its job in isolation after publication. A failed run may leave
a draft with partial assets; investigate before rerunning failed jobs. A PyPI
upload is not transactional across projects. If some files were accepted before
a failure, inspect PyPI and cut fresh package versions and a new tag as needed;
do not overwrite or silently skip an existing distribution. Workflow artifacts
used between jobs expire after 14 days (the generator's provenance artifact may
expire sooner); release assets persist with the release.

## Verify a release

Install [GitHub CLI](https://cli.github.com/), Python 3.12+,
[sigstore-python](https://github.com/sigstore/sigstore-python) (for example,
`uv tool install sigstore==4.5.0`) and
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier#installation).
Use a current verifier with trust roots compatible with the signing service.
Authenticate `gh` with access to the repository while it is private. From a
trusted checkout, run:

```sh
bash scripts/verify-release.sh v0.2.0
```

The script downloads release assets into a temporary directory, authenticates the
inventory, checks its SHA-256 hashes and completeness, and verifies each wheel and
sdist with both tools. It prints `PASS filename (Sigstore + SLSA)` or a failure
verdict and exits nonzero on a missing asset, wrong identity/tag, tampering or
verification failure. Temporary downloads are removed on exit. `.sig` and `.crt`
are convenience exports of the signature/certificate already in the verified
bundle; the bundle contains the transparency evidence needed for verification.

Equivalent checks for one downloaded distribution are:

```sh
tag=v0.2.0
file=aics_identity-0.2.0-py3-none-any.whl
sigstore verify github --repository petros-poli/AICS-public \
  --cert-identity "https://github.com/petros-poli/AICS-public/.github/workflows/release.yml@refs/tags/$tag" \
  --ref "refs/tags/$tag" --bundle "$file.sigstore.json" "$file"
slsa-verifier verify-artifact "$file" --provenance-path aics.intoto.jsonl \
  --source-uri github.com/petros-poli/AICS-public --source-tag "$tag"
```

The Sigstore check binds bytes to this repository's release workflow and exact
tag, including GitHub's OIDC issuer. SLSA verification authenticates provenance,
matches the artifact digest and source repository/tag, and checks the trusted
builder. To pin an independently recorded source commit as well, use
`slsa-verifier ... --print-provenance` and check the verified config-source and
materials commit digests against that record. Preserve the artifacts, bundles,
provenance, inventory and expected commit in an agent's local evidence store.

An agent must additionally compare its actual deployment/install inputs to these
verified bytes. A version string or a server's claim is insufficient. Rebuilding
from the public source and comparing hashes strengthens the source connection;
runtime attestation, dependency verification and logging release-hash leaves are
separate work. The current release pipeline does not distribute the server.

## Reproducibility and maintenance

The two builds run only inside Release, for `v*` tags; there is no standalone
reproducibility run on branch or tag pushes. To check repeatability before
tagging, run `scripts/verify.sh --only 'reproducible:*'`: it builds each library
twice from two copies of the tree with the release's settings (two paths,
`PYTHONHASHSEED` 1 and 2, `SOURCE_DATE_EPOCH` = the commit time, UTC) and
compares the wheel and sdist hashes. A local result is evidence for you, not
release evidence.
Each library is built on two separate GitHub-hosted Ubuntu 24.04 jobs with fresh
checkouts, different source paths and `PYTHONHASHSEED` values, no restored uv cache,
uv **0.12.6**, Python **3.12.12**, UTC and a fixed locale. `SOURCE_DATE_EPOCH` is the
source commit's committer timestamp obtained from GitHub's commits API, including
for annotated tags. `uv build --no-sources` builds the sdist and then a wheel from
that sdist. Both filenames and SHA-256 hashes must match; no mismatch is ignored.
The `reproducibility-hashes` artifact retains both hash sets and build settings for
90 days, including hashes from a failed comparison. `SHA256SUMS` also accompanies
the release with a Sigstore signature and SLSA provenance.

The current libraries use pure-Python `uv_build` packaging. The pinned uv version
includes a backend compatible with their `uv_build>=0.12.6,<0.13.0` requirement;
see uv's [bundled backend documentation](https://docs.astral.sh/uv/concepts/build-backend/#bundled-build-backend).
Keep the uv and Python pins of the verification and build jobs synchronized.
Known sources of potential non-determinism, rather than accepted exceptions,
include:

- Backends that ignore `SOURCE_DATE_EPOCH`, gzip/ZIP timestamps, filesystem order,
  random values, absolute paths or generated version files. A newly added library
  can introduce these; a mismatch must be fixed before release.
- Hosted runner images and system libraries change even with `ubuntu-24.04`.
  Python distribution revisions and native toolchains can also affect bytes.
  Two matching builds establish repeatability in the tested environment, not
  universal reproducibility across operating systems or future toolchains.
- `uv.lock` locks runtime/dev resolution, not arbitrary isolated build backends.
  Future backends or changed build requirements may resolve different versions;
  constrain those build requirements before claiming reproducibility. Native
  extensions will require platform-specific builds and stronger toolchain pins.
- Sigstore signatures, certificates, bundles and SLSA provenance contain ephemeral
  keys, signing times or run identifiers and intentionally differ between runs.
  Compare the wheel/sdist bytes, not their attestations or GitHub artifact ZIPs.
  GitHub's automatically generated source archives are not the signed sdists.

All directly referenced external **actions** are pinned by full commit SHA with
version comments. The sole external reusable workflow is intentionally referenced
by **`v2.1.0`**: SLSA requires a full semantic version tag for its builder identity;
a SHA reference breaks standard verification. Its resolved commit is documented
beside the call. Local workflow calls use the caller's commit. This pinning does
not freeze actions invoked internally by third-party workflows. The upstream
[generator documentation](https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/generic/README.md)
now marks the project as no longer actively maintained; this setup uses it as
requested. Review upstream trust-root compatibility and action pins periodically.

Only signing, provenance generation and the gated PyPI job can request OIDC
tokens. Only the provenance generator and release-attachment job can write GitHub
releases. Verification and builds have read-only repository access, checkouts do
not persist credentials, every job has a timeout, and verification fails on any
failed, skipped or cancelled check. Verification keeps the whole monorepo
checkout available for the server's sibling path dependencies.

### Repository settings

Read on 2026-10-19 with `gh` as `petros-poli` (repository role admin; token
scopes `repo`, `workflow`, `read:org`), read-only:

- `GET repos/petros-poli/AICS-public/branches/main/protection`, `GET .../rulesets` and
  `GET .../rules/branches/main` all answer **HTTP 403** "Upgrade to GitHub Pro or
  make this repository public to enable this feature". This is the plan's limit
  for a private repository, not a missing token permission: the account is an
  admin of the repository.
- `GET repos/petros-poli/AICS-public/branches/main` reports `protected: false` and
  `required_status_checks` with empty `contexts` and `checks`, enforcement
  `off`. **No status check is required on `main` today**, so none of the retired
  job names blocks a merge, and no settings change is needed now.
- Because rulesets are unavailable, `v*` tag creation is not restricted by a
  rule; only the repository's collaborators (today the single admin) can push
  tags. The six `pypi*` environments each allow deployments from `tag:v*` only,
  without required reviewers.
- The repository variable `PUBLISH_PYPI` is `false` (read with `gh variable list`
  on 2026-10-20; set on 2026-10-19 21:03 UTC) and neither `PYPI_ONLY_PROJECT` nor
  `PYPI_PROJECTS` is set, so a `v*` tag publishes nothing to PyPI. Before a release
  that should upload, set it to `true` together with a selector unless every
  library has a new version.

If branch protection or rulesets become available (the repository goes public or
the plan changes) and someone requires status checks on `main`, require **none**
of these names, and remove any that were added, under **Settings → Branches →
main → Require status checks to pass** (classic protection) or **Settings →
Rules → Rulesets → the ruleset targeting `main` → Require status checks to pass**:

- `All packages passed`, `discover`, and every `Test packages/<name>` (the old
  `ci.yml` jobs);
- `Interop suite and fixtures (Python 3.12.12)`, `(Python 3.13.15)` and
  `(Python 3.14.7)` (the old `interop.yml` job);
- every `Build <package> (copy 1)` / `(copy 2)` and `compare` (the old
  standalone `reproducible.yml` run).

With classic protection, `gh api -X DELETE
repos/petros-poli/AICS-public/branches/main/protection/required_status_checks` removes
the whole requirement. Local `scripts/verify.sh` results are recorded in commit
messages (CONTRIBUTING.md) and are never posted as checks, so there is no check
to put in their place. A `v*` tag ruleset limited to release maintainers is still
worth adding once rulesets are available.

## npm and MCP registries

The Python release workflow does not publish the Node client. Authenticate to npm
with an account permitted to publish under `@wesupport-ai`, then run:

```sh
cd clients/aics-js
npm ci
npm run test:offline
npm pack --dry-run
npm publish --access public
```

Check the package version is unused before publishing. The `prepack` script builds
the distributable JavaScript, and `files` restricts the package contents.

After the `aics-mcp` version is visible on PyPI, submit
`packages/aics-mcp/server.json` to the official MCP Registry using the
[package publication instructions](../packages/aics-mcp/README.md#registry-publication).
The MCP Registry stores metadata and verifies the PyPI package's README ownership
marker; it does not upload the Python package.
