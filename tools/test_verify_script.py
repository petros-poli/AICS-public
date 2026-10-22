"""scripts/verify.sh: planning, the --affected mapping, prerequisites and exit codes.

Each test builds a throwaway git repository with the layout of this one (fake
packages with the same [tool.uv.sources] graph, card/, clients/aics-js, the
release tools tests), copies the real script into it and runs it with a PATH
that holds fake uv/node/npm/openssl/ssh-keygen and the real system tools the
script needs. A tool is "missing" when its fake is left out of PATH.

    uv run --project packages/aics-server pytest -q tools/test_verify_script.py
"""

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify.sh"
INPUTS = ROOT / "scripts/verify/inputs.txt"

# directory -> sibling path dependencies, as in the real pyproject files
PACKAGES = {
    "aics-identity": [],
    "aics-tlog": [],
    "aics-witness": ["aics-tlog"],
    "aics-conformance": ["aics-tlog", "aics-identity"],
    "aics-cli": ["aics-tlog", "aics-identity"],
    "aics-server": ["aics-identity", "aics-tlog"],
    "aics-mcp": ["aics-server", "aics-identity", "aics-tlog"],
    "aics-interop": ["aics-identity", "aics-tlog", "aics-witness", "aics-cli", "aics-conformance", "aics-server"],
}
TOOLS = {"aics-export": ["aics-tlog", "aics-identity", "aics-conformance"]}
LIBS = ["aics-identity", "aics-tlog", "aics-witness", "aics-conformance", "aics-cli", "aics-mcp"]

ALL_CHECKS = {
    "python:aics-identity", "python:aics-tlog", "python:aics-witness", "python:aics-conformance",
    "python:aics-cli", "python:aics-server", "python:aics-mcp", "python:aics-export",
    "python:card", "python:card:launch", "interop", "js", "release-isolation",
    *(f"reproducible:{lib}" for lib in LIBS),
}

FAKE_UV = r'''#!/bin/bash
echo "uv|$PWD|REQUIRE_TOOLS=${AICS_INTEROP_REQUIRE_TOOLS:-}|$*" >> "$FAKE_LOG"
case " $* " in *" python -c "*) echo "${UV_PYTHON:-3.12.99}"; exit 0 ;; esac
case "$1" in
  python) echo "$FAKE_BIN/fake-python"; exit 0 ;;
  build)
    out=""; prev=""
    for a in "$@"; do [ "$prev" = --out-dir ] && out=$a; prev=$a; done
    mkdir -p "$out" || exit 1
    name=$(basename "$PWD" | tr - _)
    extra=""; [ -f .nondeterministic ] && extra=$PYTHONHASHSEED
    printf 'wheel %s %s %s\n' "$name" "$SOURCE_DATE_EPOCH" "$extra" > "$out/$name-0.1.0-py3-none-any.whl"
    printf 'sdist %s %s %s\n' "$name" "$SOURCE_DATE_EPOCH" "$extra" > "$out/$name-0.1.0.tar.gz"
    exit 0 ;;
esac
[ -f .fail ] && { echo "fake test failure in $PWD"; exit 1; }
case " $* " in *" -m launch "*) [ -f .fail-launch ] && { echo "launch blocker"; exit 1; } ;; esac
exit 0
'''
FAKE_LOGGED = '''#!/bin/bash
echo "{name}|$PWD|$*" >> "$FAKE_LOG"
[ -f .fail ] && {{ echo "fake failure"; exit 1; }}
exit 0
'''
FAKE_PYTHON = '#!/bin/bash\necho "Python 3.12.99"\n'
FAKES = ["uv", "node", "npm", "openssl", "ssh-keygen"]
SYSTEM_TOOLS = [
    "bash", "sh", "git", "awk", "sed", "grep", "sort", "uniq", "cut", "tr", "cat", "mkdir",
    "mktemp", "rm", "cp", "date", "dirname", "basename", "tail", "tee", "head", "ls", "cmp",
    "diff", "env", "locale", "wc", "sha256sum", "shasum", "perl",
]


def write(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, text=True,
                          capture_output=True, env=git_env()).stdout


def git_env():
    env = dict(os.environ)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.invalid")
    return env


def pyproject(name, deps, prefix="..", extra=""):
    sources = "".join(f'{d} = {{ path = "{prefix}/{d}" }}\n' for d in deps)
    return f'[project]\nname = "{name}"\nversion = "0.1.0"\n\n[tool.uv.sources]\n{sources}\n{extra}'


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    write(root / "scripts/verify.sh", SCRIPT.read_text())
    write(root / "scripts/verify/inputs.txt", INPUTS.read_text())
    for name, deps in PACKAGES.items():
        write(root / f"packages/{name}/pyproject.toml", pyproject(name, deps))
        write(root / f"packages/{name}/src/{name.replace('-', '_')}/__init__.py")
        write(root / f"packages/{name}/README.md", f"# {name}\n")
    write(root / "packages/aics-interop/fixtures/case.json", "{}\n")
    for name, deps in TOOLS.items():
        write(root / f"tools/{name}/pyproject.toml", pyproject(name, deps, "../../packages"))
    write(root / "card/pyproject.toml", pyproject("aics-card", [], extra=(
        '[tool.pytest.ini_options]\naddopts = "-q -m \'not launch\'"\n'
        'markers = ["launch: a launch blocker"]\n')))
    write(root / "clients/aics-js/package.json", '{"scripts": {"build": "tsc", "test": "node --test"}}\n')
    write(root / "clients/aics-js/src/index.ts", "export {};\n")
    write(root / "tools/test_pypi_release.py", "")
    write(root / "tools/test_deploy_vps.py", "")
    write(root / ".github/workflows/release.yml", "name: Release\n")
    write(root / "docs/README.md", "# docs\n")
    write(root / "docs/spec/AICS-1.md", "# AICS-1\n")
    write(root / "docs/legal/charter.md", "# charter\n")
    write(root / "research/notes.txt", "notes\n")
    write(root / ".gitignore", ".venv/\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    return root


def commit_change(root, *paths, message="change"):
    for rel in paths:
        path = root / rel
        write(path, (path.read_text() if path.exists() else "") + "changed\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)


def sandbox(tmp_path, missing=()):
    """A PATH with the fakes (minus `missing`) and the real system tools."""
    fake = tmp_path / "fakebin"
    system = tmp_path / "sysbin"
    if not fake.exists():
        fake.mkdir()
        system.mkdir()
        write(fake / "fake-python", FAKE_PYTHON)
        (fake / "fake-python").chmod(0o755)
        for tool in SYSTEM_TOOLS:
            found = shutil.which(tool)
            if found:
                (system / tool).symlink_to(found)
    for tool in FAKES:
        path = fake / tool
        if path.exists():
            path.unlink()
        if tool in missing:
            continue
        write(path, FAKE_UV if tool == "uv" else FAKE_LOGGED.format(name=tool))
        path.chmod(0o755)
    for tool in missing:
        if (system / tool).is_symlink():
            (system / tool).unlink()
    return fake, system


def run(root, *args, missing=(), bash=None, extra_env=None):
    tmp = root.parent
    fake, system = sandbox(tmp, missing)
    log = tmp / "fake.log"
    tmpdir = tmp / "tmp"
    tmpdir.mkdir(exist_ok=True)
    env = git_env()
    env.update(PATH=f"{fake}:{system}", FAKE_LOG=str(log), FAKE_BIN=str(fake), HOME=str(tmp),
               TMPDIR=str(tmpdir), VERIFY_LOG_DIR=str(tmp / "logs"))
    env.pop("SOURCE_DATE_EPOCH", None)
    env.pop("UV_PYTHON", None)
    env.update(extra_env or {})
    shell = bash or str(system / "bash")
    result = subprocess.run([shell, str(root / "scripts/verify.sh"), *args], cwd=root, env=env,
                            text=True, capture_output=True, timeout=300)
    result.calls = log.read_text().splitlines() if log.exists() else []
    if log.exists():
        log.unlink()
    return result


def planned(result):
    return {m.group(1) for m in re.finditer(r"^CHECK (\S+)", result.stdout, re.M)}


def summary(result):
    """{check: RESULT} from the final table."""
    table = result.stdout.split("\nSUMMARY", 1)[1].split("\n\n", 1)[0]
    rows = {}
    for line in table.splitlines()[2:]:
        fields = line.split()
        if fields:
            rows[fields[0]] = fields[1]
    return rows


# ---------------------------------------------------------------------------
# --list
# ---------------------------------------------------------------------------

def test_list_full_names_every_check_and_runs_nothing(repo):
    result = run(repo, "--list")
    assert result.returncode == 0, result.stdout + result.stderr
    assert planned(result) == ALL_CHECKS
    # the interop suite runs once, as `interop`, with the tools required
    assert "python:aics-interop" not in result.stdout
    assert "AICS_INTEROP_REQUIRE_TOOLS=1" in result.stdout
    assert result.calls == []
    assert "PREREQ" not in result.stdout


def test_default_mode_is_full(repo):
    assert planned(run(repo, "--list")) == planned(run(repo, "--full", "--list"))


def test_list_runs_on_the_system_bash(repo):
    """macOS ships bash 3.2 as /bin/bash; the script must plan with it."""
    if not Path("/bin/bash").exists():
        pytest.skip("no /bin/bash")
    commit_change(repo, "packages/aics-witness/src/aics_witness/__init__.py")
    assert planned(run(repo, "--list", bash="/bin/bash")) == ALL_CHECKS
    result = run(repo, "--list", "--affected", bash="/bin/bash")
    assert result.returncode == 0, result.stdout + result.stderr
    assert planned(result) == {"python:aics-witness", "interop", "python:card", "python:card:launch",
                               "reproducible:aics-witness"}


def test_verify_script_check_appears_with_its_tests(repo):
    write(repo / "tools/test_verify_script.py", "")
    commit_change(repo, "scripts/verify/inputs.txt")
    assert "verify-script" in planned(run(repo, "--list"))
    assert planned(run(repo, "--list", "--affected")) == {"verify-script"}


def test_host_and_vantage_checks_appear_with_their_tests(repo):
    """The second host's offline tests and the vantage probe tests are part of the verify path."""
    write(repo / "tools/test_witness_host.py", "")
    write(repo / "tools/test_mirror_sync.py", "")
    write(repo / "ops/vantage/tests/test_vantage_probe.py", "")
    write(repo / "ops/vantage/vantage-probe.sh", "")
    write(repo / "ops/uptime-check.sh", "")
    write(repo / "ops/mirror-sync.sh", "")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "host tests")
    result = run(repo, "--list")
    assert planned(result) == ALL_CHECKS | {"host-ops", "vantage"}
    assert re.search(r"^CHECK host-ops +uv run --locked --project packages/aics-server --with pyyaml pytest -q "
                     r"tools/test_witness_host.py tools/test_mirror_sync.py$", result.stdout, re.M)
    assert re.search(r"^CHECK vantage +uv run --no-project --with pytest pytest -q ops/vantage/tests$",
                     result.stdout, re.M)
    commit_change(repo, "ops/uptime-check.sh")
    assert planned(run(repo, "--list", "--affected", "HEAD~1")) == {"vantage"}
    commit_change(repo, "ops/mirror-sync.sh")
    assert planned(run(repo, "--list", "--affected", "HEAD~1")) == {"host-ops"}
    commit_change(repo, "packages/aics-witness/README.md")
    assert "host-ops" in planned(run(repo, "--list", "--affected", "HEAD~1"))
    result = run(repo, "--only", "host-ops,vantage")
    assert result.returncode == 0, result.stdout + result.stderr
    assert summary(result) == {"host-ops": "PASS", "vantage": "PASS"}
    assert (f"uv|{repo}|REQUIRE_TOOLS=|run --locked --project packages/aics-server --with pyyaml pytest -q "
            "-p no:cacheprovider tools/test_witness_host.py tools/test_mirror_sync.py") in result.calls
    assert f"uv|{repo}|REQUIRE_TOOLS=|run --no-project --with pytest pytest -q -p no:cacheprovider ops/vantage/tests" \
        in result.calls


def test_a_change_to_the_script_itself_selects_every_check(repo):
    """verify.sh decides how every check runs, so --affected cannot narrow it."""
    write(repo / "tools/test_verify_script.py", "")
    commit_change(repo, "scripts/verify.sh")
    assert planned(run(repo, "--list", "--affected")) == ALL_CHECKS | {"verify-script"}


def test_only_filters_by_glob(repo):
    result = run(repo, "--list", "--only", "reproducible:*,js")
    assert planned(result) == {"js", *(f"reproducible:{lib}" for lib in LIBS)}
    result = run(repo, "--only", "nothing-matches")
    assert result.returncode == 0
    assert "NOTHING-TO-RUN" in result.stdout


# ---------------------------------------------------------------------------
# --affected
# ---------------------------------------------------------------------------

SERVER_AND_DEPENDENTS = {"python:aics-server", "python:aics-mcp", "interop", "js", "release-isolation",
                         "python:card", "python:card:launch"}


@pytest.mark.parametrize(("paths", "expected"), [
    (["packages/aics-witness/src/aics_witness/__init__.py"],
     {"python:aics-witness", "interop", "python:card", "python:card:launch", "reproducible:aics-witness"}),
    (["packages/aics-server/src/aics_server/__init__.py"], SERVER_AND_DEPENDENTS),
    (["packages/aics-mcp/README.md"],
     {"python:aics-mcp", "python:card", "python:card:launch", "reproducible:aics-mcp"}),
    (["packages/aics-conformance/src/aics_conformance/__init__.py"],
     {"python:aics-conformance", "python:aics-export", "interop", "python:card", "python:card:launch",
      "reproducible:aics-conformance"}),
    (["packages/aics-tlog/src/aics_tlog/__init__.py"], ALL_CHECKS),
    (["packages/aics-identity/pyproject.toml"], ALL_CHECKS),
    (["packages/aics-interop/fixtures/case.json"], {"interop", "js", "python:card", "python:card:launch"}),
    (["clients/aics-js/src/index.ts"], {"js"}),
    (["card/pyproject.toml"], {"python:card", "python:card:launch"}),
    (["tools/aics-export/pyproject.toml"], {"python:aics-export"}),
    (["tools/test_pypi_release.py"], {"release-isolation"}),
    ([".github/workflows/interop.yml"], {"release-isolation"}),
    (["docs/legal/charter.md"], SERVER_AND_DEPENDENTS),
    (["docs/README.md", "research/notes.txt"], set()),
])
def test_affected_mapping(repo, paths, expected):
    commit_change(repo, *paths)
    result = run(repo, "--list", "--affected", "HEAD~1")
    assert result.returncode == 0, result.stdout + result.stderr
    assert planned(result) == expected
    for path in paths:
        assert f"CHANGED {path} ->" in result.stdout
    if not expected:
        assert "NOTHING-TO-RUN" in result.stdout


def test_documentation_only_change_runs_nothing_and_exits_0(repo):
    commit_change(repo, "docs/README.md")
    result = run(repo, "--affected")
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"^NOTHING-TO-RUN", result.stdout, re.M)
    assert result.calls == []


def test_affected_defaults_to_origin_main_then_head_parent(repo):
    base = git(repo, "rev-parse", "HEAD").strip()
    commit_change(repo, "clients/aics-js/src/index.ts")
    commit_change(repo, "card/pyproject.toml")
    # No origin/main: HEAD~1, so only the last commit (card) counts.
    result = run(repo, "--list", "--affected")
    assert "AFFECTED since HEAD~1" in result.stdout
    assert planned(result) == {"python:card", "python:card:launch"}
    # With origin/main at the base, both commits count.
    git(repo, "update-ref", "refs/remotes/origin/main", base)
    result = run(repo, "--list", "--affected")
    assert "AFFECTED since origin/main" in result.stdout
    assert planned(result) == {"js", "python:card", "python:card:launch"}


def test_affected_counts_uncommitted_and_untracked_files(repo):
    path = repo / "clients/aics-js/src/index.ts"
    path.write_text(path.read_text() + "// edited\n")
    write(repo / "tools/aics-export/src/new_module.py", "")
    result = run(repo, "--list", "--affected", "HEAD")
    assert planned(result) == {"js", "python:aics-export"}


def test_affected_with_unknown_ref_exits_2(repo):
    result = run(repo, "--affected", "no-such-ref")
    assert result.returncode == 2
    assert "unknown git ref" in result.stderr


def test_affected_without_git_is_a_prereq_error(repo):
    result = run(repo, "--affected", missing=("git",))
    assert result.returncode == 2
    assert re.search(r"^PREREQ git:", result.stderr, re.M)


def test_affected_runs_only_the_selected_checks(repo):
    commit_change(repo, "clients/aics-js/src/index.ts")
    result = run(repo, "--affected")
    assert result.returncode == 0, result.stdout + result.stderr
    assert summary(result) == {"js": "PASS"}
    npm = [c.split("|")[2] for c in result.calls if c.startswith("npm|")]
    assert npm == ["ci", "run build", "test"]


# ---------------------------------------------------------------------------
# Running: commands, exit status, PREREQ and SKIPPED lines
# ---------------------------------------------------------------------------

def test_full_run_passes_and_runs_the_mirrored_commands(repo):
    result = run(repo, "--full")
    assert result.returncode == 0, result.stdout + result.stderr
    assert summary(result) == {check: "PASS" for check in ALL_CHECKS}
    assert re.search(rf"^RESULT PASS: {len(ALL_CHECKS)} passed$", result.stdout, re.M)
    calls = result.calls
    for name in [*PACKAGES, "card"]:
        if name == "aics-interop":
            continue
        cwd = repo / ("card" if name == "card" else f"packages/{name}")
        assert f"uv|{cwd}|REQUIRE_TOOLS=|run --locked --all-extras pytest -q" in calls
    assert f"uv|{repo}/tools/aics-export|REQUIRE_TOOLS=|run --locked --all-extras pytest -q" in calls
    assert f"uv|{repo}/card|REQUIRE_TOOLS=|run --locked --all-extras pytest -q -m launch" in calls
    interop = f"uv|{repo}/packages/aics-interop|REQUIRE_TOOLS="
    assert interop + "1|run --locked --all-extras pytest -q -rsx" in calls
    assert interop + "|run --locked aics-interop-fixtures --check" in calls
    assert (f"uv|{repo}|REQUIRE_TOOLS=|run --locked --project packages/aics-server pytest -q "
            "-p no:cacheprovider tools/test_pypi_release.py tools/test_deploy_vps.py") in calls
    builds = [c for c in calls if "|build --no-sources --out-dir " in c]
    assert len(builds) == 2 * len(LIBS)
    for lib in LIBS:
        cwds = {c.split("|")[1] for c in builds if c.split("|")[1].endswith(f"/packages/{lib}")}
        assert len(cwds) == 2, f"{lib} must be built from two different directories"
    assert "NOTE the Linux VM runs the 3.12/3.13/3.14 matrix" in result.stdout
    assert "Python 3.12.99" in result.stdout
    # The Python column is the interpreter the check's own uv run resolves.
    assert f"uv|{repo}/packages/aics-interop|REQUIRE_TOOLS=|run --locked --all-extras python -c " \
        "import platform; print(platform.python_version())" in calls
    assert result.stdout.count("MIRRORED ") >= 4
    assert "PREREQ" not in result.stdout and "SKIPPED" not in result.stdout
    assert git(repo, "status", "--porcelain") == ""


def test_a_failing_check_fails_the_run_and_the_rest_still_run(repo):
    write(repo / "packages/aics-witness/.fail")
    result = run(repo, "--full")
    assert result.returncode == 1
    assert re.search(r"^FAIL python:aics-witness ", result.stdout, re.M)
    assert "fake test failure" in result.stdout  # the log's tail is shown
    rows = summary(result)
    assert rows.pop("python:aics-witness") == "FAIL"
    assert set(rows.values()) == {"PASS"} and len(rows) == len(ALL_CHECKS) - 1
    assert re.search(rf"^RESULT FAIL: {len(ALL_CHECKS) - 1} passed, 1 failed, 0 skipped$", result.stdout, re.M)


def test_a_launch_blocker_fails_only_the_launch_check(repo):
    write(repo / "card/.fail-launch")
    result = run(repo, "--only", "python:card*")
    assert result.returncode == 1
    assert summary(result) == {"python:card": "PASS", "python:card:launch": "FAIL"}


def test_a_nondeterministic_build_fails(repo):
    write(repo / "packages/aics-cli/.nondeterministic")
    result = run(repo, "--only", "reproducible:*")
    assert result.returncode == 1
    rows = summary(result)
    assert rows.pop("reproducible:aics-cli") == "FAIL"
    assert set(rows.values()) == {"PASS"}


def test_missing_uv_skips_its_checks_with_prereq_and_skipped_lines(repo):
    result = run(repo, "--full", missing=("uv",))
    assert result.returncode == 0, result.stdout + result.stderr
    prereq = re.findall(r"^PREREQ (\S+):", result.stdout, re.M)
    assert prereq == ["uv"]
    skipped = set(re.findall(r"^SKIPPED (\S+): PREREQ uv missing$", result.stdout, re.M))
    assert skipped == ALL_CHECKS - {"js"}
    assert summary(result)["js"] == "PASS"
    assert f"RESULT PASS with skips: 1 passed, {len(ALL_CHECKS) - 1} skipped" in result.stdout
    assert run(repo, "--full", "--strict", missing=("uv",)).returncode == 1


def test_missing_node_and_npm_skip_js(repo):
    result = run(repo, "--only", "js,python:aics-identity", missing=("node", "npm"))
    assert result.returncode == 0
    assert re.findall(r"^PREREQ (\S+):", result.stdout, re.M) == ["node", "npm"]
    assert re.search(r"^SKIPPED js: PREREQ node, npm missing$", result.stdout, re.M)
    assert summary(result) == {"js": "SKIPPED", "python:aics-identity": "PASS"}


@pytest.mark.parametrize("tool", ["openssl", "ssh-keygen", "git"])
def test_missing_interop_tool_skips_interop(repo, tool):
    result = run(repo, "--only", "interop", missing=(tool,))
    assert re.search(rf"^PREREQ {re.escape(tool)}: not found on PATH; needed by: interop$", result.stdout, re.M)
    assert re.search(rf"^SKIPPED interop: PREREQ {re.escape(tool)} missing$", result.stdout, re.M)
    assert result.returncode == 0
    assert run(repo, "--only", "interop", "--strict", missing=(tool,)).returncode == 1


def test_list_marks_checks_that_would_skip(repo):
    result = run(repo, "--list", missing=("openssl",))
    assert result.returncode == 0
    assert re.search(r"^PREREQ openssl:", result.stdout, re.M)
    assert re.search(r"^CHECK interop\s+would be SKIPPED \(PREREQ openssl missing\)$", result.stdout, re.M)
    assert result.calls == []


def test_release_interop_leg_reports_the_matrix_python(repo):
    """The command and the two output checks of .github/workflows/interop.yml."""
    result = run(repo, "--full", "--only", "interop", "--strict", "--verbose",
                 missing=("node", "npm"), extra_env={"UV_PYTHON": "3.13.15"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert summary(result) == {"interop": "PASS"}
    assert re.search(r"^interop +PASS .*Python 3\.13\.15\b", result.stdout, re.M)
    blocking = [line for line in re.findall(r"^\s*(?:PREREQ|SKIPPED)\b.*$", result.stdout, re.M)
                if not line.endswith("needed by: no check in this run")]
    assert blocking == []
    assert re.search(r"^PREREQ node: .*needed by: no check in this run$", result.stdout, re.M)


def test_bad_usage_exits_2(repo):
    assert run(repo, "--bogus").returncode == 2
