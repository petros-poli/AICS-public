"""The trust bundle shipped inside the ``aics-cli`` package on PyPI.

One of the three places the instance publishes its out-of-band trust bundle
(docs/spec/AICS-1.md §6.4; docs/DESIGN.md §4.2 item 6): DNS TXT
``_aics.<domain>``, this constant, and a labelled block in the public README.
All three carry the same JCS bytes::

    {"bootstrap_card_hash":...,"log_vkey":...,"origin":...,"owner_kid":...,"policy_kid":...,"v":1}

and README and PyPI also carry their SHA-256 (``AICS_TRUST_BUNDLE_SHA256``).

PLACEHOLDER was True until the production genesis of 2026-10-19; while it is
True the constant is ``None`` and ``aics policy init`` and ``aics policy diff``
report it as "placeholder" - not published, never counted as agreement.  Since
that day both constants carry the published bundle (bytes exactly as in DNS
and the README) and ``PLACEHOLDER`` is False.  From then on every command holds the pinned policy against
it (by domain, or by log origin when the policy has no domain) and refuses a
policy it contradicts; and ``policy init --from-dns`` alone meets the default
of two independent key sources.  The banner should advertise the ``aics
verify`` commands only once that release is out.
"""

from __future__ import annotations

PLACEHOLDER = False

#: The domain whose bundle this is.
AICS_TRUST_BUNDLE_DOMAIN = "wesupport-ai.com"

#: JCS bytes of the bundle, exactly as published in DNS (base64url-decoded) and the README.
AICS_TRUST_BUNDLE: bytes | None = b'{"bootstrap_card_hash":"80dcd2abd1c8e51c54961336c0f5da4f416d7e97c7825aaf35003e8ff0dc6c44","log_vkey":"api.wesupport-ai.com/tiles+0e2f3a1e+ASx//oWlf4UBmbnXHfpMCsF2NrQOZuN32Q25NiTBC7fV","origin":"api.wesupport-ai.com/tiles","owner_kid":"did:key:z6MkiN89VfP5ZqFRC9epYQNjDyXQvYxrGn11r4Wrf6dvVb6K","policy_kid":"did:key:z6MkhhjWtmdwmSmAZGq1kkc8EiC1u3GmQ4eS8EEvTKfbKcze","v":1}'

#: ``hexH(J(bundle))``: lowercase hex SHA-256 of AICS_TRUST_BUNDLE.
AICS_TRUST_BUNDLE_SHA256: str | None = 'bc234cc34b1b0941d0e833c41112109fe7fe020cebbba9f58f98f3a59448da0c'
