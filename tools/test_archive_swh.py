"""A successful HTTP status must not disguise an unsuccessful archival request."""
import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("response,success", [
    ({"origin_url": "https://github.com/petros-poli/AICS-public/", "visit_type": "git",
      "save_request_status": "accepted", "save_task_status": "pending"}, True),
    ({"origin_url": "https://github.com/petros-poli/AICS-public", "visit_type": "git",
      "save_request_status": "pending", "save_task_status": "not created"}, True),
    ("<html>Browser challenge</html>", False),
    ({"origin_url": "https://github.com/unrelated/project", "visit_type": "git",
      "save_request_status": "accepted", "save_task_status": "pending"}, False),
    ({"origin_url": "https://github.com/petros-poli/AICS-public", "visit_type": "git",
      "save_request_status": "rejected", "save_task_status": "not created"}, False),
    ({"origin_url": "https://github.com/petros-poli/AICS-public", "visit_type": "git",
      "save_request_status": "accepted", "save_task_status": "failed"}, False),
])
def test_save_requires_api_record(tmp_path, response, success):
    payload = tmp_path / "response"
    payload.write_text(response if isinstance(response, str) else json.dumps(response))
    curl = tmp_path / "curl"
    curl.write_text("""#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then shift; cp "$SWH_TEST_RESPONSE" "$1"; fi
  shift
done
printf 200
""")
    curl.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
               SWH_TEST_RESPONSE=str(payload))
    for name in ("SWH_AUTH_TOKEN", "SWH_SAVE_URL", "CURL_OPTS"):
        env.pop(name, None)
    result = subprocess.run(["bash", str(ROOT / "ops/discovery/archive-swh-and-registries.sh"),
                             "--execute"], env=env, text=True, capture_output=True)
    assert result.returncode == (0 if success else 3), result.stdout + result.stderr
    assert ("RESULT: EXECUTE PASS" in result.stdout) is success
