# WeSupport-AI discovery files

Static source package for wesupport-ai.com. AICS is the protocol; WeSupport-AI is the instance. No deployment or server changes are included.

| File | Served path on https://wesupport-ai.com | Standard / purpose |
| --- | --- | --- |
| security.txt | /.well-known/security.txt | RFC 9116; UTF-8 text/plain |
| agent-card.json | /.well-known/agent-card.json | A2A 1.0 required field shapes; unsigned discovery draft, compatibility blockers below |
| agent-card-signing.md | Not served; build instructions | A2A §8.4, RFC 8785, RFC 7515, RFC 8037; AICS-1 §§6.4, 13 |
| ai-catalog.json | /.well-known/ai-catalog.json | LF Agent Card WG AI Catalog 1.0 draft; provisional type mappings |
| ai-catalog.notes.md | Not served; maintainer notes | Confirmed schema fields and unresolved artifact mappings |
| llms.txt.header | Prefix of /llms.txt; no separate route | Project docs/BANNER.md, plain text |
| validate.py | Not served; local/build tool | Dependency-free structural and content checks |
| README.md | Not served | Integration and launch checklist |

Run `python3 wellknown/validate.py` from the repository root (or run the script by absolute path). `--launch` additionally rejects the unresolved A2A interface and unsigned-card state. Structural success does not certify A2A interoperability, verify signatures or prove deployment. The content guard checks explicit capability flags, the six allowed skills, and suspicious service claims across text files; it is not a semantic proof of arbitrary prose.

The header reproduces the banner's fenced plain text with its documented pre-client substitution: manual verification replaces the three unavailable `aics verify` commands. Include its bytes verbatim at the beginning of /llms.txt. Append protocol links to `/spec/AICS-1.md` and `/docs/PROTOCOL-TEXT.md`; publish those documents. The pages-host /checkpoint discovery pointer names https://api.wesupport-ai.com/tiles/checkpoint; /tiles identifies https://api.wesupport-ai.com/tiles and https://tiles.wesupport-ai.com/tiles. Never redirect resources within either tile prefix. The header's relative URLs need working site routes. This copy adds TLS verification and the F20 qualifications pending reconciliation of docs/BANNER.md and docs/PROTOCOL-TEXT.md. Switch all served copies together; use CLI instructions only once shipped.

Decision 10: apex/www discovery pages and tiles.wesupport-ai.com pass through Cloudflare with Full (strict) TLS; api.wesupport-ai.com, gate.wesupport-ai.com and ip.wesupport-ai.com are DNS-only. Do not route any agent API, text-gate or tile resource through the pages proxy. Its explicit pages/discovery allowlist rejects /v1/*, /v2/*, /t and /tiles/* with a plain-text DNS-only pointer; /notice remains notice intake. The separately generated assurance card must disclose TLS termination and proxy modes. Serve JSON unchanged as UTF-8 application/json; publish atomically, avoid edge transformations, and invalidate cached cards on updates.

Before launch:

- Resolve the A2A transport/authentication/extra-url blockers described in agent-card-signing.md. An empty interface list is deliberate: no implemented A2A binding is evidenced by the design. Do not advertise native AICS as an A2A transport. Confirm all six advertised skills are deployed, including swarms; use the service's release version in the card.
- Fill production log_vkey, policy_kid and owner_kid in the separately generated assurance card and trust bundle. Sign both cards with the policy key under their distinct presence rules. Compute the signed assurance card hash, log it, and publish the bootstrap bundle out of band. No fake card hash or key is supplied here.
- Generate and serve `/.well-known/aics-card.json` and /card from AICS-1 §13 with actual limits, evidence, witness assumptions and proven/promised/not-offered statuses. This package links to it but does not manufacture an assurance object without production facts.
- Route /notice and /legal/notice-procedure.md, and verify notice@wesupport-ai.com and authorities@wesupport-ai.com delivery through Cloudflare Email Routing. The security contact is notice@; authorities@ remains the legal authority contact. Preserve the unregistered pilot disclosure on /contact.
- Refresh security.txt before `2027-10-18T00:00:00Z` (one year from preparation date, 2026-10-18), and annually thereafter. RFC 9116 recommends an expiry less than a year away; shorten it when operational renewal is scheduled. Keep the canonical HTTPS location and preferred language en.
- Confirm catalog target URLs and media types using ai-catalog.notes.md; the catalog is discovery, not a trust root.
