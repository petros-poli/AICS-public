# Changelog

## 0.1.1 — 2026-10-19

- Enforce the amended AICS-1 §4.3 nonce rule during history verification: a
  `(kid, nonce)` used by an earlier accepted envelope or authenticated refusal
  remains used after its original expiry.
- Apply the same rule in the fake server, including authenticated refusals,
  and add regression cases for reuse after expiry.

This release updates verification behavior; it does not establish conformance
of a live deployment without a separately run conformance report.
