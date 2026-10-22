#!/usr/bin/env bash
# Publish only approved documents. Requires Python 3; remote sync also needs rsync/SSH.
set -euo pipefail
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec python3 - "$SCRIPT_DIR/.." "$@" <<'PY'
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

repo = Path(sys.argv[1]).resolve()
args = sys.argv[2:]
usage = """Usage:
  bash ops/sync-docs.sh --check [additional-source-to-audit ...]
  bash ops/sync-docs.sh --check-links HTTPS_PAGES_ORIGIN
  bash ops/sync-docs.sh LOCAL_DIRECTORY
  bash ops/sync-docs.sh user@host [ABSOLUTE_REMOTE_DIRECTORY]
Remote default: /opt/wesupport-ai/deploy/docs-public
The destination must be dedicated to this export; stale files are removed, except
published evidence: a local export refuses to drop an evidence file, a remote sync keeps it.
--check validates the publication sources without writing or connecting anywhere.
--check-links verifies published document/alias bytes over HTTPS after deployment.
Published: docs/{spec,legal,site}/*.md, the three top-level documents (BANNER.md,
DESIGN.md, PROTOCOL-TEXT.md; never DECISIONS.md, the owner's internal record), one data
file, docs/legal/secret-patterns.json (the secret-pattern definitions the card hashes
and the server scans with), and every file of docs/evidence (the evidence a card names
by hash: conformance reports and what re-verifying them needs; .md, .json, .txt or
.toml only, JSON strict, no subdirectory, no symlink), served at /docs/evidence/.
Nothing else, and never docs/internal.
The publisher preserves source bytes. The site must serve /spec, /legal, /site,
/docs/spec, /docs/legal and /docs/site aliases plus root aliases for the three top-level
documents, and /docs/evidence/ (inside the /docs/ export). Repository-only
research/package links require their own public repository URL; never expose
docs/internal to satisfy a broken link.
"""

def fail(message):
    raise ValueError(message)

#: Exactly the data files docs/legal may publish besides its Markdown.
DATA_FILES = ("secret-patterns.json",)
#: docs/evidence: every regular file is published under /docs/evidence/ with this name form; any other entry
#: refuses the whole export (fail closed) rather than being skipped, since a card names these files by hash.
EVIDENCE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.(?:md|json|txt|toml)")
#: The export directories that get a plain index.txt.
INDEXED = ("spec", "legal", "site", "docs", "docs/evidence")

def strict_json_file(path):
    """Refuse an evidence .json that is not strict JSON: UTF-8, no duplicate member, no NaN or Infinity."""
    import json
    def pairs(items):
        members = {}
        for key, value in items:
            if key in members:
                raise ValueError(f"duplicate member {key!r}")
            members[key] = value
        return members
    def constant(name):
        raise ValueError(f"non-standard constant {name}")
    try:
        json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"REFUSED evidence file that is not strict JSON: {path.name} ({error})")

def evidence_sources(docs):
    evidence = docs / "evidence"
    if evidence.is_symlink():
        fail(f"REFUSED symlink in source path: {evidence}")
    if not evidence.is_dir():
        return []
    found = []
    for path in sorted(evidence.iterdir()):
        if path.name.startswith("."):
            continue  # editor and Finder litter (.DS_Store) is never published
        if path.is_symlink() or not path.is_file():
            fail(f"REFUSED evidence entry that is not a regular file: {path}")
        if not EVIDENCE_NAME.fullmatch(path.name) or path.name == "index.txt":
            fail(f"REFUSED evidence file outside the .md/.json/.txt/.toml names (or index.txt): {path.name}")
        if path.suffix == ".json":
            strict_json_file(path)
        found.append((path, Path("docs") / "evidence" / path.name))
    return found

def below(path, parent):
    return path == parent or parent in path.parents

def validate_sources(extra):
    docs = repo / "docs"
    internal = docs / "internal"
    # Inode comparison also rejects a public-looking hard link to private material.
    private_inodes = set()
    for base, dirs, files in os.walk(internal, followlinks=False):
        for name in files:
            stat = (Path(base) / name).stat()
            private_inodes.add((stat.st_dev, stat.st_ino))
    sources = []
    for section in ("spec", "legal", "site"):
        sources.extend((p, Path(section) / p.name)
                       for p in sorted((docs / section).glob("*.md")))
    # docs/DECISIONS.md is the owner's internal record, not a public document (readiness audit 2026-10-20); the
    # specifications link its copy in the public repository instead.
    sources.extend((docs / name, Path("docs") / name) for name in
                   ("BANNER.md", "DESIGN.md", "PROTOCOL-TEXT.md"))
    # The one non-Markdown file, named exactly: the secret-pattern definitions that the
    # card's [secret-scan-scope] names at /legal/secret-patterns.json (decision 29).
    sources.extend((docs / "legal" / name, Path("legal") / name) for name in DATA_FILES)
    evidence = evidence_sources(docs)
    sources.extend(evidence)
    evidence_files = {source for source, target in evidence}
    allowed = {source for source, target in sources}
    for source in [p for p, target in sources] + [Path(p).absolute() for p in extra]:
        resolved = source.resolve(strict=True)
        if below(resolved, internal.resolve()):
            fail(f"REFUSED internal document: {source}")
        if source not in allowed:
            fail(f"REFUSED source outside the public allowlist: {source}")
        if any(p.is_symlink() for p in (source, *source.parents)):
            fail(f"REFUSED symlink in source path: {source}")
        if not source.is_file():
            fail(f"REFUSED non-regular source: {source}")
        stat = source.stat()
        if (stat.st_dev, stat.st_ino) in private_inodes:
            fail(f"REFUSED hard link to internal document: {source}")
        if not (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.md", source.name) or source.name in DATA_FILES
                or (source in evidence_files and EVIDENCE_NAME.fullmatch(source.name))):
            fail(f"REFUSED unsafe index filename: {source.name}")
    return sources

def main():
    if not args or args == ["--help"]:
        print(usage, end="")
        return 0 if args else 2
    check = args[0] == "--check"
    sources = validate_sources(args[1:] if check else [])
    if args[0] == "--check-links":
        from urllib.parse import urlsplit
        from urllib.request import Request, urlopen
        if len(args) != 2:
            fail(usage)
        base = args[1].rstrip("/")
        parsed = urlsplit(base)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
            fail("Expected HTTPS pages origin without path or credentials")
        count = 0
        for source, target in sources:
            paths = ["/" + target.as_posix()]
            if target.parts[0] in ("spec", "legal", "site"):
                paths.append("/docs/" + target.as_posix())
            elif target.parent == Path("docs"):
                paths.append("/" + source.name)
            # docs/evidence/<name> has its one path, /docs/evidence/<name>, and no root alias.
            for path in paths:
                url = base + path
                # Identify our verifier honestly: generic Python-urllib clients can
                # be rejected by edge browser-integrity checks before reaching Caddy.
                request = Request(url, headers={
                    "User-Agent": "AICS-Docs-Check/1.0 (+https://wesupport-ai.com)",
                    "Accept": "text/markdown,application/json,text/plain;q=0.9,*/*;q=0.1",
                })
                try:
                    with urlopen(request, timeout=15) as response:
                        published = response.read()
                except OSError as error:
                    fail(f"Could not fetch {url}: {error}")
                if published != source.read_bytes():
                    fail(f"Published bytes differ: {url}")
                count += 1
        print(f"OK: {count} published document and relative-link alias URLs match source bytes.")
        return 0
    if check:
        evidence = sum(1 for source, target in sources if target.parent == Path("docs/evidence"))
        print(f"OK: {len(sources)} public documents ({len(DATA_FILES)} data file, {evidence} evidence files); "
              "internal sources excluded.")
        return 0
    if args[0].startswith("-") or len(args) > 2:
        fail(usage)
    remote = "@" in args[0]
    if remote:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9.-]*", args[0]):
            fail("Expected user@host (no embedded path or SSH options)")
        destination = args[1] if len(args) == 2 else "/opt/wesupport-ai/deploy/docs-public"
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+/docs-public", destination) or ".." in destination.split("/"):
            fail("Remote destination must be an absolute path ending in /docs-public")
    else:
        if len(args) != 1:
            fail(usage)
        destination = Path(args[0]).absolute()
        if any(p.is_symlink() for p in (destination, *destination.parents)):
            fail("REFUSED symlink in destination path")
        destination = destination.resolve()
        # Never overwrite sources or a repository ancestor; only the dedicated
        # deploy export is permitted inside this checkout.
        if below(repo, destination) or (below(destination, repo) and destination != repo / "deploy/docs-public"):
            fail("REFUSED destination overlapping the repository")
        if destination.exists():
            if not destination.is_dir():
                fail("Destination must be a directory")
            expected = {target.as_posix() for source, target in sources}
            expected.update(f"{section}/index.txt" for section in INDEXED)
            # Fail closed on contamination rather than publish an unknown file.
            for entry in destination.rglob("*"):
                relative = entry.relative_to(destination).as_posix()
                if entry.is_symlink() or (entry.is_dir() and relative not in INDEXED):
                    fail(f"REFUSED unexpected destination entry: {entry}")
                if not entry.is_dir() and relative not in expected:
                    # Old public .md files are safely removed below: those of spec/, legal/ and site/, and a
                    # top-level document no longer published (docs/DECISIONS.md, exported before 2026-10-20). A
                    # stale evidence file (docs/evidence/) or anything else still refuses the export.
                    parent = entry.parent.relative_to(destination).as_posix()
                    if parent not in ("spec", "legal", "site", "docs") or entry.suffix != ".md":
                        fail(f"REFUSED unexpected destination file: {entry}")
    with tempfile.TemporaryDirectory(prefix="aics-public-docs-") as temporary:
        stage = Path(temporary)
        for section in INDEXED:
            (stage / section).mkdir(mode=0o755)
        for source, target in sources:
            shutil.copyfile(source, stage / target)
            (stage / target).chmod(0o644)
        for section in INDEXED:
            # A subdirectory is listed with a trailing slash (docs/index.txt names evidence/).
            names = sorted(p.name + ("/" if p.is_dir() else "") for p in (stage / section).iterdir())
            (stage / section / "index.txt").write_text("\n".join(names + ["index.txt"]) + "\n", encoding="utf-8")
            (stage / section / "index.txt").chmod(0o644)
        if remote:
            subprocess.run(["ssh", args[0], f"mkdir -p -- {destination}"], check=True)
            # The stage holds D755/F644 exactly (its root too), and --perms copies those modes: the effect of
            # --chmod=D755,F644, which macOS's openrsync does not accept. --delete removes stale public files, but
            # never published evidence: a card names those by hash, and an export from a checkout that lacks one
            # (a fresh worktree of an older commit) must not unpublish it (the local export refuses instead; here
            # the remote copy is protected and kept).
            stage.chmod(0o755)
            subprocess.run(["rsync", "-r", "--perms", "--delete", "--filter", "P /docs/evidence/**", "--",
                            str(stage) + "/", f"{args[0]}:{destination}/"], check=True)
        else:
            destination.mkdir(parents=True, exist_ok=True)
            for section in ("spec", "legal", "site", "docs"):
                target = destination / section
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(stage / section, target)
        print(f"Published {len(sources)} documents ({len(DATA_FILES)} data file) and {len(INDEXED)} plain indexes "
              f"to {destination}")
    return 0

try:
    sys.exit(main())
except (ValueError, OSError, subprocess.CalledProcessError) as error:
    print(f"sync-docs: {error}", file=sys.stderr)
    sys.exit(1)
PY
