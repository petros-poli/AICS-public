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
The destination must be dedicated to this export; stale files are removed.
--check validates the publication sources without writing or connecting anywhere.
--check-links verifies published document/alias bytes over HTTPS after deployment.
Published: docs/{spec,legal,site}/*.md, the four top-level documents and one data
file, docs/legal/secret-patterns.json (the secret-pattern definitions the card hashes
and the server scans with). Nothing else, and never docs/internal.
The publisher preserves source bytes. The site must serve /spec, /legal, /site,
/docs/spec, /docs/legal and /docs/site aliases plus root aliases for the four top-level
documents. Repository-only research/package links require their own public
repository URL; never expose docs/internal to satisfy a broken link.
"""

def fail(message):
    raise ValueError(message)

#: Exactly the data files docs/legal may publish besides its Markdown.
DATA_FILES = ("secret-patterns.json",)

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
    sources.extend((docs / name, Path("docs") / name) for name in
                   ("BANNER.md", "DESIGN.md", "DECISIONS.md", "PROTOCOL-TEXT.md"))
    # The one non-Markdown file, named exactly: the secret-pattern definitions that the
    # card's [secret-scan-scope] names at /legal/secret-patterns.json (decision 29).
    sources.extend((docs / "legal" / name, Path("legal") / name) for name in DATA_FILES)
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
        if not (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.md", source.name) or source.name in DATA_FILES):
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
            else:
                paths.append("/" + source.name)
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
        print(f"OK: {len(sources)} public documents ({len(DATA_FILES)} data file); internal sources excluded.")
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
            expected.update(f"{section}/index.txt" for section in ("spec", "legal", "site", "docs"))
            # Fail closed on contamination rather than publish an unknown file.
            for entry in destination.rglob("*"):
                relative = entry.relative_to(destination).as_posix()
                if entry.is_symlink() or (entry.is_dir() and relative not in ("spec", "legal", "site", "docs")):
                    fail(f"REFUSED unexpected destination entry: {entry}")
                if not entry.is_dir() and relative not in expected:
                    # Old public .md files are safely removed below.
                    if entry.parent.name not in ("spec", "legal", "site") or entry.suffix != ".md":
                        fail(f"REFUSED unexpected destination file: {entry}")
    with tempfile.TemporaryDirectory(prefix="aics-public-docs-") as temporary:
        stage = Path(temporary)
        for section in ("spec", "legal", "site", "docs"):
            (stage / section).mkdir(mode=0o755)
        for source, target in sources:
            shutil.copyfile(source, stage / target)
            (stage / target).chmod(0o644)
        for section in ("spec", "legal", "site", "docs"):
            names = sorted(p.name for p in (stage / section).iterdir())
            (stage / section / "index.txt").write_text("\n".join(names + ["index.txt"]) + "\n", encoding="utf-8")
            (stage / section / "index.txt").chmod(0o644)
        if remote:
            subprocess.run(["ssh", args[0], f"mkdir -p -- {destination}"], check=True)
            subprocess.run(["rsync", "-r", "--delete", "--chmod=D755,F644", "--",
                            str(stage) + "/", f"{args[0]}:{destination}/"], check=True)
        else:
            destination.mkdir(parents=True, exist_ok=True)
            for section in ("spec", "legal", "site", "docs"):
                target = destination / section
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(stage / section, target)
        print(f"Published {len(sources)} documents ({len(DATA_FILES)} data file) and four plain indexes to {destination}")
    return 0

try:
    sys.exit(main())
except (ValueError, OSError, subprocess.CalledProcessError) as error:
    print(f"sync-docs: {error}", file=sys.stderr)
    sys.exit(1)
PY
