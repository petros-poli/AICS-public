from ..core import check
from ..protocol import Agent,J,H,U,DU,rotation
from ..schema import require
from .negative import post_attempt

@check('identity.claim-pop','Claim requires possession of claimed key','AICS-1 §7.1','accept_bad_signature')
def claim(ctx):
    a=Agent(); e=ctx.prepare(a,'name.claim',a.claim()); e['sig']=U(bytes(64))
    ctx.refused(ctx.client.submit(e,a.key),e,'bad_signature',authenticated=False)

@check('identity.rotate','Rotation requires both proofs and succeeds with both','AICS-1 §7.2','one_signature')
def rotate(ctx):
    a=ctx.new_agent(); new=Agent(name=a.name)
    for missing in ('sig_old','sig_new'):
        q=rotation(a,new,ctx.policy.trust['origin']); q[missing]['signature']=U(bytes(64))
        e=ctx.prepare(a,'key.rotate',q); ctx.refused(ctx.client.submit(e,a.key),e,'bad_signature')
    entry,note=ctx.submit(a,'key.rotate',rotation(a,new,ctx.policy.trust['origin'])); i=ctx.follow(entry,note)
    new.claim_index=a.claim_index; new.event_index=i; ctx.post(new)
    hist,_=ctx.scan(); require(hist.names[a.name]['kid']==new.kid,'new signing key not current')

@check('identity.fork','Second event consuming a key predecessor is refused','AICS-1 §7.2','key_fork')
def fork(ctx):
    a=ctx.new_agent(); predecessor=a.event_index; new=Agent(name=a.name)
    entry,note=ctx.submit(a,'key.rotate',rotation(a,new,ctx.policy.trust['origin'])); i=ctx.follow(entry,note)
    # Current key signs, but deliberately consumes the already-used name predecessor.
    new.event_index=predecessor
    e=ctx.prepare(new,'key.rotate',rotation(new,Agent(name=a.name),ctx.policy.trust['origin']))
    result=ctx.refused(ctx.client.submit(e,new.key),e,'key_fork')
    require(result['payload']['conflict_index']==i,'fork refusal missing first successor')

@check('identity.revoke','Revocation permanently prevents reclaim and rotation','AICS-1 §7.3','revocation')
def revoke(ctx):
    a=ctx.new_agent(); entry,note=ctx.submit(a,'key.revoke',dict(name_norm=a.name,prev_event_index=a.event_index,reason_code='retired')); a.event_index=ctx.follow(entry,note)
    replacement=Agent(name=a.name); e=ctx.prepare(replacement,'name.claim',replacement.claim())
    ctx.refused(ctx.client.submit(e,replacement.key),e,'revoked')
    e=ctx.prepare(a,'key.rotate',rotation(a,replacement,ctx.policy.trust['origin'])); ctx.refused(ctx.client.submit(e,a.key),e,'revoked')

@check('identity.x25519','Encryption key rotates and lookup proves latest key','AICS-1 §7.3','xrotate')
def xrotate(ctx):
    a=ctx.new_agent(); new=Agent(); entry,note=ctx.submit(a,'x25519.rotate',dict(name_norm=a.name,prev_event_index=a.event_index,new_x25519=new.x)); i=ctx.follow(entry,note)
    hist,_=ctx.scan(); require(hist.names[a.name]['x']==new.x and hist.names[a.name]['key_index']==i,'encryption key did not advance')
    lookup=ctx.client.get('name',name=a.name); require(lookup.get('x25519',new.x)==new.x,'API did not advance')
