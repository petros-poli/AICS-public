"""Verify artifacts the npm client made, with the Python reference package aics-identity (read from stdin as JSON).

Run inside packages/aics-identity: ``uv run --no-sync python -I verify_js.py``.  Prints one line per verified
artifact kind and exits non-zero on the first failure.
"""
import base64
import json
import sys

from aics_identity import envelope, http_signatures as hs, keys, linesig, sealed

data = json.load(sys.stdin)
for e in data["envelopes"]:
    envelope.verify_envelope(e, keys.parse_did_key, now=e["protected"]["created"])
for e in data["text_envelopes"]:
    envelope.verify_text_envelope(e, keys.parse_did_key, now=e["protected"]["created"])
for r in data["requests"]:
    env = r["envelope"]
    hs.verify_request(r["method"], r["url"], r["headers"], base64.b64decode(r["body_b64"]), resolve_key=keys.parse_did_key,
                      now=env["protected"]["created"], envelope=env, **hs.AICS_VERIFY_POLICY)
for c in data["lines"]:
    form = linesig.verify_line(c["session"], c["line"], c["signature"], keys.parse_did_key(c["kid"]))
    assert form == c["form"], (form, c["form"])
for s in data["sealed"]:
    msg = sealed.open_sealed(base64.b64decode(s["ciphertext_b64"]), bytes.fromhex(s["secret_hex"]), envelope=s["envelope"],
                             recipient_kid=s["recipient_kid"])
    assert msg.text == s["text"], msg.text
for name in ("envelopes", "text_envelopes", "requests", "lines", "sealed"):
    print(f"aics-identity verified {len(data[name])} {name}")
