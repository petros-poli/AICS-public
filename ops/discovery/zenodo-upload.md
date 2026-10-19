# Zenodo deposit of the AICS-1 spec — exact steps

`zenodo.json` next to this file is the deposit-request metadata for
`docs/spec/AICS-1.md` (title, version 0.2-draft, organizational creator
"wesupport-ai.com", abstract verbatim, keywords, CC-BY-4.0 licence,
related identifier pointing at the repository). This file is the procedure.
No token is ever written into a file: it comes from the environment and is
revoked when done.

## 0. Preconditions (all must hold before touching the API)

- [ ] `docs/spec/AICS-1.md` says `0.2-draft` in its publication-metadata table;
      the deposited bytes are archived unchanged, so deposit exactly what the repo
      carries at that tag.
- [ ] Licence is `cc-by-4.0` in `zenodo.json` and CC-BY-4.0 in the spec.
      This is the approved documentation licence; code is Apache-2.0.
- [ ] The repository (`https://github.com/petros-poli/AICS-public`, the
      `isSupplementTo` related identifier) is publicly readable, or replace
      that identifier with an appropriate publicly readable spec/release URL.
      A release/tag URL in a private repository does not solve this requirement.
      Never reference a private URL in a public deposit.
- [ ] Run `bash ops/discovery/build-zenodo-bundle.sh --build` and verify
      `(cd ops/discovery/.zenodo-staging && shasum -a 256 -c SHA256SUMS)`.
- [ ] After publishing: write the DOI Zenodo assigns into the spec's
      publication-metadata table (row "DOI") in the next spec version.

## 1. Token — environment only, never in a file

Create a personal access token at zenodo.org → Settings → Applications →
Personal access tokens, scopes `deposit:write` and `deposit:actions`. Then in
the shell you run the calls from:

    export ZENODO_TOKEN='…'      # paste; this line must not be saved anywhere

Rules: the token never goes into files, commit messages, issue text, or shared
command histories (`history -d` / run from a clean shell); anyone who sees it
can write and publish under the account — revoke it at the same settings page
the moment the work is done (`unset ZENODO_TOKEN` only clears the shell).

Rehearse first on the sandbox, which has its own tokens and its own API base:
everything below works unchanged against
`https://sandbox.zenodo.org/api/deposit/depositions` with a sandbox token.

## 2. Create the draft deposit

    curl --fail-with-body -sS -X POST \
      -H "Authorization: Bearer $ZENODO_TOKEN" \
      -H "Content-Type: application/json" \
      --data-binary @ops/discovery/.zenodo-staging/zenodo.json \
      https://zenodo.org/api/deposit/depositions

The response JSON contains the deposition `id` and, under `links`, the
`bucket` URL used next. Stop on a non-success response; retain the draft ID
and reuse it rather than creating duplicate deposits.

## 3. Upload the file bytes

    for f in AICS-1-v0.2-draft.md SWARMS-v0.2-draft.md PROTOCOL-TEXT.md zenodo.json SHA256SUMS; do
      curl --fail-with-body -sS -X PUT \
        -H "Authorization: Bearer $ZENODO_TOKEN" \
        --data-binary @ops/discovery/.zenodo-staging/"$f" \
        "$BUCKET/$f"
    done

where `$BUCKET` is the `links.bucket` value from step 2. The filename becomes
public; keep the version in it. Upload all five files so every checksum has a
corresponding archived file, including the metadata snapshot.

## 4. Review, then publish

Open the draft at `https://zenodo.org/deposits/<id>` and check: metadata rows,
all five files, their checksums, the licence, the related identifier.
Publishing mints the DOI and freezes the record — corrections afterwards are new versions, so this is the
last cheap checkpoint. Then:

    curl --fail-with-body -sS -X POST \
      -H "Authorization: Bearer $ZENODO_TOKEN" \
      https://zenodo.org/api/deposit/depositions/<id>/actions/publish

A mistaken draft can be deleted instead: `DELETE
https://zenodo.org/api/deposit/depositions/<id>` (drafts only; published
records cannot be deleted, only new-versioned).

## 5. Aftermath

- [ ] DOI recorded in the spec's metadata table (precondition 4).
- [ ] Deposit URL added to `ops/discovery/directories.md` under the
      durable-mentions note if useful.
- [ ] Token revoked, `unset ZENODO_TOKEN`.
