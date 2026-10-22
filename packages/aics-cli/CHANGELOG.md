# Changelog

## 0.1.1 — 2026-10-22

- Built reproducibly from tag `v0.3.1` (public source commit 78290c4) and uploaded to PyPI from the
  owner's machine; no GitHub Release, Sigstore signature or SLSA provenance exists for this version.

- Trust bundle of the 2026-10-20 relaunch: `AICS_TRUST_BUNDLE` and
  `AICS_TRUST_BUNDLE_SHA256` carry the bundle of the second genesis of
  `api.wesupport-ai.com/tiles` (new log and policy keys, the same owner key,
  the founder witness at quorum 1 in the first card). The new bundle's SHA-256 is `eada27995662f578ac1729f54f5621e9ea79addaf03f63ecba96758fb46589ca`.
- 0.1.0 carried the bundle of the log started on 2026-10-19 (sha256
  `bc234cc34b1b0941d0e833c41112109fe7fe020cebbba9f58f98f3a59448da0c`), which was
  discarded before any outside agent had used it. With 0.1.0 installed, `aics policy init
  --from-dns wesupport-ai.com` stops with exit 2, because DNS and the package
  disagree; that is the intended refusal, not a split view. 0.1.0 is yanked on PyPI
  (2026-10-22).

Behaviour changes.
- `aics verify card` decides from the log's policy leaves whether the card is in force, pending or
  superseded: it reads `GET <api>/v2/policies`, proves each leaf against a checkpoint accepted under
  the pinned policy, and, while at most 1024 entries follow the listing's last policy leaf, scans those
  entries too. It stores a card only when the card verified as current (0.1.0 stored an unproven card,
  after which the card in force exited 2). `--file` therefore reads the network too: the listing, a
  checkpoint, tiles.
- It exits 1, not 2, for a card that is pending or not logged; for a card that is superseded, expired,
  altered or signed by another key when the origin does not serve it as current at the pinned card URL,
  or did so less than 30 s after the switch or expiry; and for a downgrade whose notice cannot be
  checked, or that is judged while the policy leaves cannot be read. It exits 2 for such a card at the
  pinned card URL, for a card that disagrees with its policy leaf, and for a log-signed policy leaf that
  breaks AICS-1 §6.4.
- `aics verify card URL` checks the document at URL exactly as given (a `/v2/bodies/<hash>` body must
  hash to its path) instead of the host's well-known card.
- `aics verify checkpoint` saves the checkpoint it verified, so `aics verify consistency` run next has a
  predecessor.
- `aics verify card` accepts a card whose `gate` names the instance's own two distinct ports (AICS-1
  §13.1, revision of 2026-10-20); 0.1.0 required 7700 and 7701, which only production uses.
- The README shown on PyPI names the public repository by its URL and no longer calls the trust-bundle
  constant a placeholder.

## 0.1.0 — 2026-10-19

- First release under the distribution name `aics-cli` (command `aics`), with the
  trust bundle of the production genesis of 2026-10-19.
