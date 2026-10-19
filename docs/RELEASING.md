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
   workflow referenced in these files. Use GitHub-hosted Ubuntu runners. Require
   the CI check **All packages passed** on `main`, and restrict creation and
   modification of `v*` tags to release maintainers.
2. Create the GitHub Actions environment **`pypi`**. Restrict deployment to `v*`
   tags; add environment reviewers if desired. This exact name is part of the
   publisher identity.
3. In PyPI, configure a GitHub trusted publisher for **each** project below. For
   an existing project use **Manage → Publishing**. For a new project register a
   [pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
   under your account's Publishing settings; first publication creates the project.

   | Field | Value |
   | --- | --- |
   | Projects | `aics-identity`, `aics-tlog`, `aics-witness`, `aics-conformance`, `aics` (the `packages/aics-cli` project), `aics-mcp` |
   | Repository owner | `petros-poli` |
   | Repository name | `AICS-public` |
   | Workflow filename | `release.yml` (no directory prefix) |
   | Environment name | `pypi` |

   Do not configure `aics-server`: it is tested but never built or uploaded by the
   release pipeline. Use `[project].name` from each included `pyproject.toml`,
   not its directory name: the CLI publishes as `aics`. PyPI documents the publisher identity fields in
   [Adding a trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).
4. Leave the **repository** Actions variable `PUBLISH_PYPI` absent for GitHub-only
   releases. Set it to the literal string **`true`** once all included projects
   have publishers configured and are ready for public distribution. Every other
   value skips PyPI; the `prepare` job logs the reason. No API token, signing
   key, password, or long-lived secret is used. GitHub's job token and OIDC tokens
   are short lived. Setting the variable does not rerun completed jobs.

The SLSA workflow uses `private-repository: false` for this public repository.
Signing publishes repository/workflow identity, source identifiers and artifact
digests to public Sigstore transparency infrastructure. Configure publishers
for this repository before enabling package distribution.

## Cut a release

1. Review the release commit and its package metadata. CI discovers **every**
   `packages/*/pyproject.toml`, including future packages and the server. Release
   discovery selects `aics-identity`, `aics-tlog`, `aics-witness`,
   `aics-conformance`, `aics-cli`, and `aics-mcp` when their metadata files exist.
   Register all six publishers before enabling PyPI.
2. Set each included library's version deliberately, update its changelog and
   dependency constraints, and ensure `main` passes CI and Reproducible builds.
   The repository tag identifies a release of the monorepo; package versions come
   from their own `pyproject.toml` and need not match one another or the tag.
   When publishing to PyPI, **every included package/version must be new**: the
   workflow publishes all libraries and does not skip existing files. PyPI
   disallows reusing a published filename, including after deletion.
3. Create and push an immutable `v*` tag pointing to the reviewed commit, using
   your normal source-control tool. Prefer names such as `v0.2.0` or `v0.3.0-rc1`
   (the verification script accepts letters, digits, dots, plus, underscore and
   hyphen after the initial `v`). The tag's commit must contain all three workflows.
4. Watch **Release**. It calls CI and the reusable reproducibility workflow at the
   tagged commit. Only the first copy of distributions whose two builds match can
   reach signing. The signed `SHA256SUMS` inventory and all distribution digests
   become SLSA subjects. The generator creates a draft release with
   `aics.intoto.jsonl`; the next job adds distributions, `.sigstore.json` bundles,
   base64 `.sig` signatures and PEM `.crt` certificates, then publishes the draft.
5. If enabled, approve the `pypi` environment deployment and inspect the trusted
   publishing job. It uploads the same distribution bytes, without signature
   sidecars, using `pypa/gh-action-pypi-publish` and GitHub OIDC. Verify the GitHub
   Release as described below before using its artifacts.

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
Authenticate `gh` with access to this repository. From a
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

`reproducible.yml` runs on pushes to `main`, all tag pushes, and as part of Release.
Tag pushes therefore also produce a separate standalone reproducibility run.
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
Keep the uv pin in CI and reproducibility synchronized. Known sources of potential
non-determinism, rather than accepted exceptions, include:

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
releases. Tests and builds have read-only repository access, checkouts do not
persist credentials, and the CI aggregate fails on failed, skipped or cancelled
package testing. CI caches uv dependencies while keeping the whole monorepo
checkout available for the server's sibling path dependencies.

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
