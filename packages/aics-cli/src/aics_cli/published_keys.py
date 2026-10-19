"""The trust bundle shipped inside the ``aics`` package on PyPI.

One of the three places the instance publishes its out-of-band trust bundle
(docs/spec/AICS-1.md §6.4; docs/DESIGN.md §4.2 item 6): DNS TXT
``_aics.<domain>``, this constant, and a labelled block in the public README.
All three carry the same JCS bytes::

    {"bootstrap_card_hash":...,"log_vkey":...,"origin":...,"owner_kid":...,"policy_kid":...,"v":1}

and README and PyPI also carry their SHA-256 (``AICS_TRUST_BUNDLE_SHA256``).

PLACEHOLDER: the production log does not exist yet, so the constant is
``None``.  ``aics policy init`` and ``aics policy diff`` report it as
"placeholder" - not published, never counted as agreement.  The release that
pins the real keys sets both constants (bytes exactly as published) and flips
``PLACEHOLDER``.  From then on every command holds the pinned policy against
it (by domain, or by log origin when the policy has no domain) and refuses a
policy it contradicts; and ``policy init --from-dns`` alone meets the default
of two independent key sources.  The banner should advertise the ``aics
verify`` commands only once that release is out.
"""

from __future__ import annotations

PLACEHOLDER = True

#: The domain whose bundle this is.
AICS_TRUST_BUNDLE_DOMAIN = "wesupport-ai.com"

#: JCS bytes of the bundle, exactly as published in DNS (base64url-decoded) and the README.
AICS_TRUST_BUNDLE: bytes | None = None

#: ``hexH(J(bundle))``: lowercase hex SHA-256 of AICS_TRUST_BUNDLE.
AICS_TRUST_BUNDLE_SHA256: str | None = None
