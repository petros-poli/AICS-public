import secrets
from ..core import check
from ..protocol import J,H,U,DU,seal
from ..schema import require


def post_attempt(ctx,a,text='negative-case synthetic body',**kwargs):
    b=J(dict(channel='conformance',title=None,text=text)); q=dict(channel_sha256=H(b'conformance'),parent_index=None,body_hash=H(b),size=len(b),title_sha256=None)
    return ctx.prepare(a,'post',q,**kwargs),b

@check('negative.bad-signature','Bad signature is refused with authenticated refusal leaf','AICS-1 §§4,10.2,12.1','accept_bad_signature')
def bad_signature(ctx):
    a=ctx.new_agent(); e,b=post_attempt(ctx,a); e['sig']=U(bytes(64)); r=ctx.client.submit(e,a.key,b)
    ctx.refused(r,e,'bad_signature',authenticated=False)

@check('negative.replay','Identical request replay is refused and linked to conflict','AICS-1 §§4.3,10.2','accept_replay')
def replay(ctx):
    a=ctx.new_agent(); e,b=post_attempt(ctx,a); r=ctx.client.submit(e,a.key,b); entry,note=ctx.accepted(r,a,e); i=ctx.follow(entry,note)
    result=ctx.refused(ctx.client.submit(e,a.key,b),e,'replay'); q=result['payload']
    require(q['conflict_index']==i and q['receipt_hash']==H(note),'replay evidence lost original acceptance/receipt')

@check('negative.stale','Stale created is refused with a leaf','AICS-1 §§4.3,10.2','accept_stale')
def stale(ctx):
    a=ctx.new_agent(); e,b=post_attempt(ctx,a,created=int(ctx.now())-301)
    # The envelope and HTTP signature remain cryptographically valid, though expired.
    ctx.refused(ctx.client.submit(e,a.key,b),e,'expired')


def private_attempt(ctx,*,clear=False):
    a=ctx.new_agent(); recipient=ctx.new_agent(); nonce=U(secrets.token_bytes(16))
    if clear:
        grant,note=ctx.submit(recipient,'grant',dict(owner_kid=recipient.kid,sender_kid=a.kid,max=1,expires=int(ctx.now())+600,prev_grant_index=None)); gi=ctx.follow(grant,note)
        body=b'private plaintext must be refused'; scheme='cleartext'; eph=None
    else:
        gi=recipient.claim_index; body=seal(b'closed inbox probe',DU(recipient.x),a.kid,recipient.kid,nonce); scheme='x25519-xsalsa20-poly1305'; eph=U(body[:32])
    q=dict(to_kid=recipient.kid,to_key_leaf_index=recipient.claim_index,encryption=scheme,eph_pk=eph,ct_hash=H(body),size=len(body),seq=1,prev=H(J(a.previous)),grant_index=gi)
    return a,ctx.prepare(a,'dm',q,nonce=nonce),body

@check('negative.cleartext','Cleartext private message refused and logged','AICS-1 §§8.1,10.2','cleartext')
def cleartext(ctx):
    a,e,b=private_attempt(ctx,clear=True); ctx.refused(ctx.client.submit(e,a.key,b),e,'unsupported_scheme')

@check('negative.closed-inbox','New inbox is closed; rejected message leaves evidence','AICS-1 §§9,10.2','open_inbox')
def closed(ctx):
    a,e,b=private_attempt(ctx); ctx.refused(ctx.client.submit(e,a.key,b),e,'no_consent')

@check('negative.secret','Published secret format refused, logged, body unavailable','AICS-1 §10.2','retain_secret')
def secret(ctx):
    a=ctx.new_agent(); card=ctx.client.get('card',pages=True)
    require(ctx.policy.secret_pattern_id in {p['id'] for p in card['secret_patterns']},'configured secret test format is not published')
    e,b=post_attempt(ctx,a,ctx.policy.secret_sample)
    ctx.refused(ctx.client.submit(e,a.key,b),e,'secret_format:'+ctx.policy.secret_pattern_id)
    r=ctx.client.body(H(b)); require(r.status in (404,410),'refused secret body retained by body service')
    raw,h=ctx.scan(validate=False)
    for entry in raw: require(ctx.policy.secret_sample.encode() not in entry and U(b).encode() not in entry,'refused body retained in leaf')
    return dict(retention_evidence='Body service and complete leaves checked; inaccessible internal storage requires operator inspection.')
