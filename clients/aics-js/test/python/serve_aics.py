"""Boot the real aics-server on loopback for the npm client's live tests (a production genesis on throwaway paths).

Run inside packages/aics-server: ``uv run --no-sync python -I serve_aics.py ROOT OWNER_PUBLIC_KEY_U64``.  Prints one
JSON line {port, origin, log_vkey, policy_kid, owner_kid} once the socket listens, then serves until killed.  The
service keys come from the out-of-band key file the server writes, never from its API.
"""
import asyncio
import json
import os
import socket
import sys
from pathlib import Path

root, owner = Path(sys.argv[1]), sys.argv[2]
root.mkdir(parents=True, exist_ok=True)
for name, text in (("charter.md", "aics-js live test charter: a throwaway log, not a service policy.\n"),
                   ("terms.md", "aics-js live test terms.\n"), ("privacy.md", "aics-js live test privacy.\n")):
    (root / name).write_text(text, "utf-8")
for k in [k for k in os.environ if k.startswith("AICS_")]:
    del os.environ[k]
os.environ.update(AICS_ORIGIN="api.aics-js.test/tiles", AICS_CHARTER_FILE=str(root / "charter.md"), AICS_PRODUCTION="1",
                  AICS_BASE_URL="https://aics-js.test", AICS_API_URL="https://api.aics-js.test", AICS_GATE_HOSTNAME="localhost",
                  AICS_TILE_MIRRORS="", AICS_TERMS_FILE=str(root / "terms.md"), AICS_PRIVACY_FILE=str(root / "privacy.md"),
                  AICS_TILES_DIR=str(root / "tiles"))
from aics_server.app import create_app  # noqa: E402  (after the environment is set)
import uvicorn  # noqa: E402

limits = {"registrations": {"count": 10000, "interval_seconds": 60}, "preidentity": {"count": 10000, "interval_seconds": 60}}
app = create_app(db_path=root / "aics.db", owner_public_key=owner, pubkeys_out=root / "aics-keys.txt", announce=False,
                 limits=limits)
pins = dict(line.split(" ", 1) for line in (root / "aics-keys.txt").read_text("utf-8").splitlines()
            if line and not line.startswith("#"))
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
sock.listen(64)
print(json.dumps({"port": sock.getsockname()[1], "origin": pins["origin"], "log_vkey": pins["log"],
                  "policy_kid": pins["policy-kid"], "owner_kid": pins["owner-kid"]}), flush=True)
server = uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False, lifespan="off"))
asyncio.run(server.serve(sockets=[sock]))
