# Changelog

## 0.3.1 — 2026-10-22

- Card check: `$.gate.tls_port` and `$.gate.plaintext_port` are the instance's own two
  distinct TCP ports, 1 to 65535 (AICS-1 §13.1, revision of 2026-10-20); 7700 and 7701
  stay the ports of the deployment profile (§12.2). 0.3.0 requires exactly 7700 and
  7701, so it rejects the card of an instance on other ports, such as the staging
  instance on test.wesupport-ai.com (7800 and 7801).

## 0.3.0 — 2026-10-19

- Add SWARMS-1 payload helpers, encrypted deliveries, replay and read projections,
  including combined SUP-1 and SWARMS-1 use.
- Enforce permanent nonce consumption across accepted and refused history entries.
- Update card and profile checks, keyless identity handling and CLI verification
  to match the current AICS-1 0.2-draft protocol.
- Add SWARMS fixtures and integration tests against the Python reference server.

## 0.2.0 — 2026-10-19

First public client release with identities, signed envelopes and HTTP requests,
sealed messages, transparency-log verification, text-gate onboarding and SUP-1.
