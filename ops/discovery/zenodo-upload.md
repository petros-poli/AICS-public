# Zenodo specification revisions

`zenodo.json` is the deposit metadata. It preserves the AICS-1 abstract, organizational
creator `wesupport-ai.com`, English language, CC-BY-4.0 license and public source link.
The archive revision label distinguishes dated document changes without changing
the protocol's own `0.2-draft` version or any normative file bytes.

## Published records and current revision

The original `0.2-draft` deposit is [record 23476344](https://zenodo.org/records/23476344),
version DOI [10.5281/zenodo.23476344](https://doi.org/10.5281/zenodo.23476344).
It preserves the specification revision dated 2026-10-18. The concept DOI
[10.5281/zenodo.23476343](https://doi.org/10.5281/zenodo.23476343) groups all versions.
Never replace or rewrite the original record's files.

The dated revision `0.2-draft-revision-2026-10-19` is published at
[record 23480785](https://zenodo.org/records/23480785), version DOI
[10.5281/zenodo.23480785](https://doi.org/10.5281/zenodo.23480785), under the same
concept DOI. All five public files and their metadata were verified on
2026-10-19 at 17:45 UTC; all five original-record files were also confirmed unchanged.
Its AICS-1, SWARMS and PROTOCOL-TEXT files match
[public source snapshot 92429b9](https://github.com/petros-poli/AICS-public/tree/92429b908d8ae4913397359b491dad62f32e1d43)
byte for byte. AICS-1 and SWARMS changed; PROTOCOL-TEXT is unchanged. The revision
covers permanent nonce uniqueness, resource-exhaustion freeze/report requirements,
and the normative locally prepared SWARMS delivery flow. The concept resolves to
this new version; the earlier deposit remains separately citable.

## Prepare a later revision without duplicates

1. Check the concept DOI's latest record, its Versions list and the authenticated
   dashboard. Reuse an existing draft for the intended revision. If the exact
   revision and file hashes are already published, do not publish again.
2. Open the latest record and choose **New version**. Keep the same concept DOI;
   do not create an unrelated new upload or edit an older published record.
3. Choose a distinct dated archive version label. Keep the documents' own version,
   date, DOI text and normative bytes unchanged. An assigned deposit DOI belongs
   in this publication record or other non-normative documentation; a future
   specification revision may adopt it deliberately.
4. Validate sources with `bash ops/discovery/build-zenodo-bundle.sh --check`.
   The legacy `--build` mode replaces `.zenodo-staging`; preserve any existing
   publication bundle and use a separate version-specific staging directory.
5. Copy exactly AICS-1, SWARMS, PROTOCOL-TEXT and `zenodo.json` into the new staging
   directory. Use dated filenames for the changed specifications and create a
   `SHA256SUMS` file covering those four files. Compare the specification bytes
   with the reviewed public source revision and inspect metadata for private URLs
   or personal details before upload.

The 2026-10-19 bundle contains exactly:

- `AICS-1-v0.2-draft-revision-2026-10-19.md`
- `SWARMS-v0.2-draft-revision-2026-10-19.md`
- `PROTOCOL-TEXT.md`
- `zenodo.json`
- `SHA256SUMS`

## Review and publish through the authenticated dashboard

Use the existing signed-in Zenodo session. This workflow needs no new API token
or permission grant. Importing the previous files is unnecessary when uploading
a fully prepared replacement bundle into the new-version draft.

1. Set the distinct archive version and publication date. Preserve the title,
   creator, report resource type, license, keywords, English language, public
   visibility and public repository relation. Describe the revision and its
   exact source snapshot without claiming deployment conformance.
2. Upload all five files, save the draft and check every filename, byte count and
   server-displayed checksum against the staging inventory. Confirm that only
   the new-version draft is being changed.
3. Preview the draft. Publish only after the intended public metadata and exact
   file inventory are verified and publication has been authorized.
4. Record the assigned version DOI and unchanged concept DOI. Download every
   public file and verify its SHA-256 against the prepared inventory; verify the
   archived checksum manifest as well. Check that the concept resolves to the
   new version and that the older record retains its previous hashes.

Keep upload inventories, API verification and screenshots as local evidence,
without credentials. Do not add runtime data, signing seeds or private operational
notes to a specification deposit.
