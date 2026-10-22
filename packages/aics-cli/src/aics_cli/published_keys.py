"""The trust bundle shipped inside the ``aics-cli`` package on PyPI.

One of the three places the instance publishes its out-of-band trust bundle
(docs/spec/AICS-1.md §6.4; docs/DESIGN.md §4.2 item 6): DNS TXT
``_aics.<domain>``, this constant, and a labelled block in the public README.
All three carry the same JCS bytes::

    {"bootstrap_card_hash":...,"log_vkey":...,"origin":...,"owner_kid":...,"policy_kid":...,"v":1}

and README and PyPI also carry their SHA-256 (``AICS_TRUST_BUNDLE_SHA256``).

PLACEHOLDER was True until the first production genesis of 2026-10-19; while it
is True the constant is ``None`` and ``aics policy init`` and ``aics policy diff``
report it as "placeholder" - not published, never counted as agreement.
aics-cli 0.1.0 carried the bundle of that log (sha256 bc234cc3...).  The log was
discarded on 2026-10-22 before any outside agent had used it, and a second genesis on the same
origin started a log with new log and policy keys (docs/DECISIONS.md row 33); 0.1.0
is yanked, and with it installed ``aics policy init`` refuses the new DNS record
(exit 2).  Since 0.1.1 both constants carry the bundle of the second log (bytes
exactly as in DNS and the README) and ``PLACEHOLDER`` is False.  Every command holds
the pinned policy against it (by domain, or by log origin when the policy has no
domain) and refuses a policy it contradicts; and ``policy init --from-dns`` alone
meets the default of two independent key sources.
"""

from __future__ import annotations

PLACEHOLDER = False

#: The domain whose bundle this is.
AICS_TRUST_BUNDLE_DOMAIN = "wesupport-ai.com"

#: JCS bytes of the bundle, exactly as published in DNS (base64url-decoded) and the README.
AICS_TRUST_BUNDLE: bytes | None = b'{"bootstrap_card_hash":"badee5e4b16f3d588d994644e5b967b3744c6f80d215131ab504043f0d014f75","log_vkey":"api.wesupport-ai.com/tiles+f7c6d025+AUs5PfhSER6s7+ZmhksZyFMyLKNcDHG+Nb+O+tpx9Yxm","origin":"api.wesupport-ai.com/tiles","owner_kid":"did:key:z6MkiN89VfP5ZqFRC9epYQNjDyXQvYxrGn11r4Wrf6dvVb6K","policy_kid":"did:key:z6Mkmj7CCan3UbWx2nKYMg3jbpA5zuugNLf4AtpasXG9pAwY","v":1}'

#: ``hexH(J(bundle))``: lowercase hex SHA-256 of AICS_TRUST_BUNDLE.
AICS_TRUST_BUNDLE_SHA256: str | None = 'eada27995662f578ac1729f54f5621e9ea79addaf03f63ecba96758fb46589ca'
