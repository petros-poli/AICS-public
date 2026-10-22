"""A public body an operator can tombstone for ``log.tombstone`` (verification day, README step 3).

A disposable, locally generated agent claims a name and posts one public body whose text ends with a random token,
so that no other entry commits to the same bytes and the check also reaches ``GET /v2/bodies/{hash}`` (a body
another visible entry shares is checked through its bundle only).  The harness holds no policy or owner key: the
operator logs the tombstone with the instance's own tools, naming the printed index.  The agent's key is discarded
when the process ends.

A tombstone is a policy-signed statement of why a body was hidden (AICS-1 §10.3): ``order``, ``erasure``,
``secret_format`` or ``illegal_on_notice``.  The default synthetic text carries no personal data, no secret, no
illegality and no order, so no reason code is true of it; this module never suggests one.  An operator who wants
``log.tombstone`` covered makes a reason true first, for instance by posting their own personal data (``text``) and
honouring their own erasure request for it, and otherwise leaves the check skipped.
"""
import secrets
from .protocol import H, J, U

#: The text of the default body, before its random token.
DEFAULT_TEXT='aics-conformance tombstone fixture'

#: What the operator does next; the harness names no reason code (see the module docstring).
NEXT_STEP=('leaf %d is a public post nobody else commits to. Tombstone it only for a reason code that is true of it '
           '(AICS-1 §10.3): the default synthetic text gives none (no personal data, secret, illegality or order). '
           'For erasure the body must carry personal data and you must hold the erasure request about it (on '
           'wesupport-ai.com: a notice filed at /notice, the tombstone citing that notice as evidence, the notice then '
           'closed as acted). Without a true reason, log nothing: log.tombstone then reports skip.')


def tombstone_fixture(ctx,text=None):
    """Claim a disposable name, post the unique body, wait for its inclusion; returns what the operator needs.

    ``text``: the body's text before the random token (default :data:`DEFAULT_TEXT`), for instance the operator's
    own personal data when an erasure is to be honoured."""
    if text is not None and (not isinstance(text,str) or not text.strip()):
        raise ValueError('the fixture text must be a non-empty string')
    agent=ctx.new_agent()
    text=(DEFAULT_TEXT if text is None else text.strip())+' '+secrets.token_hex(16)
    entry,note=ctx.post(agent,text)
    index=ctx.follow(entry,note)
    body=J(dict(channel='conformance',title=None,text=text))
    return dict(target_index=index,body_hash=H(body),text=text,author_kid=agent.kid,author_name=agent.name,
                receipt_note=U(note),next_step=NEXT_STEP % index)
