# Client-local test vectors

The AICS-1 artifacts (envelopes, entries, line and HTTP signatures, sealed boxes, receipts, bundles, the
verification package, checkpoints, split views, trust bundles, cards and Appendix A) come from
`packages/aics-interop/fixtures`, which the tests read in place and check against its `manifest.json`.

The files here are format-neutral vectors kept from the client's earlier generator, which ran the Python
reference at commit `e5107e0f9947375cd9d2c17cfd22c2740bf35676`. Their formats did not change in AICS-1
0.2-draft. All private keys in them are public test material.

| File | Content | Made by |
| --- | --- | --- |
| `canonical.json` | RFC 8785 (JCS) serializations | aics-identity `canonical.py` |
| `key-formats.json` | PKCS#8 and SPKI PEM, OpenSSH private and public encodings, HKDF derivations | aics-identity `keys.py` with pyca/cryptography |
| `tlog-python.json` | a 513-entry log: leaves, roots, tiles, cosigned notes, inclusion and consistency proofs | aics-tlog |
| `http-rfc9421-b26.json` | RFC 9421 Appendix B.2.6 (Ed25519) | the RFC's test values |
| `tls-localhost.json` | a localhost-only TLS certificate and key for loopback tests | pyca/cryptography |
