from ..core import check
from ..client import Tiles
from .. import verify
from ..protocol import H,U,strict_json
from ..schema import require
@check('G5','Single-view gossip across origin, mirrors and time','AICS-1 §§6.3,14.6','split_view')
def gossip(ctx):
    # §14.6 steps 1-2: every view is authenticated by origin and log signature, and the views are compared before
    # any witness policy is applied.  Equal sizes with different roots, or a prefix that does not match, are
    # split-view evidence whether or not a note met its witness policy (stated per note in the evidence); the policy
    # decides acceptance and freshness (§6.3), required once no split is found.
    origin=ctx.head(accept=False); sources=[(origin,ctx.tiles)]
    for url in ctx.policy.mirrors:
        source=Tiles(url,transport=ctx.client.transport); sources.append((ctx.head(source,accept=False),source))
    if ctx.policy.saved_checkpoint:
        saved=verify.head(ctx.policy.saved_checkpoint,ctx.policy,ctx.now(),historical=True); sources.append((saved,ctx.tiles)); ctx.evidence.setdefault('checkpoint_notes',[]).append(U(saved.raw))
    raw,new=ctx.scan(ctx.head(accept=False),validate=False); sources.append((new,ctx.tiles))
    ctx.evidence['witness_policy_met']=[dict(checkpoint_note_hash=H(h.raw),size=h.cp.size,met=h.witness_policy_met,reason=h.witness_error) for h,_ in sources]
    for pos,(a,sa) in enumerate(sources):
        for b,sb in sources[pos+1:]:
            if a.cp.size==b.cp.size: verify.continuity(a,b,[],current=False)
            else:
                big,source=(a,sa) if a.cp.size>b.cp.size else (b,sb)
                prefix,_=ctx.scan(big,source,validate=False); verify.continuity(a,b,prefix,current=False)
    verify.continuity(origin,new,raw)
    for h,_ in sources: require(h.witness_policy_met,h.witness_error)
    known={H(h.raw):h for h,_ in sources}|ctx.heads; unresolved=[]
    for leaf in raw:
        seen=strict_json(leaf)['payload']['envelope']['protected']['seen']
        if seen:
            if seen['checkpoint_note_hash'] not in known: unresolved.append(seen)
            else: require(known[seen['checkpoint_note_hash']].cp.size==seen['size'],'gossip pointer size differs from note')
    return dict(views=len(sources),unresolved_gossip_pointers=unresolved,verification='unproven' if unresolved else 'valid',single_view_prevention='unproven; requires honest quorum intersection')
