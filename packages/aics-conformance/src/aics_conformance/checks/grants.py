"""Consent reconstruction includes wildcard totals and exact revocation precedence."""
import secrets
from ..core import check
from ..protocol import U,DU,J,H,seal
from ..schema import require

def grant(ctx,recipient,sender,max,previous=None):
    e,n=ctx.submit(recipient,'grant',dict(owner_kid=recipient.kid,sender_kid=sender,max=max,expires=int(ctx.now())+600,prev_grant_index=previous))
    return ctx.follow(e,n)

def attempt(ctx,sender,recipient,gi):
    nonce=U(secrets.token_bytes(16)); body=seal(b'grant probe',DU(recipient.x),sender.kid,recipient.kid,nonce)
    q=dict(to_kid=recipient.kid,to_key_leaf_index=recipient.claim_index,encryption='x25519-xsalsa20-poly1305',eph_pk=U(body[:32]),ct_hash=H(body),size=len(body),seq=sender.previous['protected']['seq']+1,prev=H(J(sender.previous)),grant_index=gi)
    e=ctx.prepare(sender,'dm',q,nonce=nonce)
    return e,ctx.client.submit(e,sender.key,body)

@check('grants.wildcard','Wildcard allowance is total across all senders','AICS-1 §9','wildcard_capacity')
def wildcard(ctx):
    recipient=ctx.new_agent(); first=ctx.new_agent(); second=ctx.new_agent(); gi=grant(ctx,recipient,'*',1)
    e,r=attempt(ctx,first,recipient,gi); entry,note=ctx.accepted(r,first,e); ctx.follow(entry,note)
    e,r=attempt(ctx,second,recipient,gi); ctx.refused(r,e,'grant_exhausted')

@check('grants.exact-revocation','Exact revocation never falls back to wildcard','AICS-1 §9','exact_revocation')
def revocation(ctx):
    recipient=ctx.new_agent(); sender=ctx.new_agent(); grant(ctx,recipient,'*',4); gi=grant(ctx,recipient,sender.kid,0)
    e,r=attempt(ctx,sender,recipient,gi)
    require(400<=r.status<500,'exact revocation ignored')
    reason=r.json()['entry']['payload']['reason_code']; require(reason in ('no_consent','grant_exhausted'),'wrong consent refusal')
    ctx.refused(r,e,reason)
