"""One version per release (interop finding F16): the module, the CLI and the
distribution metadata agree."""

import subprocess
import sys
import tomllib
from pathlib import Path

import aics_tlog

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def test_module_version_is_the_distribution_version():
    with PYPROJECT.open("rb") as fh:
        declared = tomllib.load(fh)["project"]["version"]
    assert aics_tlog.__version__ == declared == "0.2.0"


def test_installed_metadata_and_cli_report_it():
    from importlib.metadata import version

    assert version("aics-tlog") == aics_tlog.__version__
    r = subprocess.run([sys.executable, "-m", "aics_tlog", "--version"], check=False, capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == aics_tlog.__version__
