from ..core import check
from ..client import Tiles
from .. import verify
from ..protocol import H,U,strict_json
from ..schema import require


def views(ctx,source):
    """The current notes ``source`` serves, each authenticated by origin and log signature only (§14.6 step 1).

    One note; at a positive quorum, every distinct note fetched until one meets the pinned witness policy, for at
    most ``witness_wait_seconds`` (a log signs and publishes before its witnesses cosign, and a mirror's cache can
    hold that note a while).  Every one is a view to compare; the last decides whether the source met the policy."""
    pauses=ctx.witness_pauses(); fetched=[]
    while True:
        h=ctx.head(source,accept=False)
        if not fetched or fetched[-1].raw!=h.raw: fetched.append(h)
        if h.witness_policy_met or not next(pauses,False): return fetched


@check('G5','Single-view gossip across origin, mirrors and time','AICS-1 §§6.3,14.6','split_view')
def gossip(ctx):
    # §14.6 steps 1-2: every view is authenticated by origin and log signature, and the views are compared before
    # any witness policy is applied.  Equal sizes with different roots, or a prefix that does not match, are
    # split-view evidence whether or not a note met its witness policy (stated per note in the evidence); the policy
    # decides acceptance and freshness (§6.3), required once no split is found.
    first=views(ctx,ctx.tiles); origin=first[0]; groups=[[(h,ctx.tiles) for h in first]]
    for url in ctx.policy.mirrors:
        source=Tiles(url,transport=ctx.client.transport); groups.append([(h,source) for h in views(ctx,source)])
    if ctx.policy.saved_checkpoint:
        saved=verify.head(ctx.policy.saved_checkpoint,ctx.policy,ctx.now(),historical=True); groups.append([(saved,ctx.tiles)]); ctx.evidence.setdefault('checkpoint_notes',[]).append(U(saved.raw))
    latest=views(ctx,ctx.tiles); raw,new=ctx.scan(latest[-1],validate=False); groups.append([(h,ctx.tiles) for h in latest])
    sources=[pair for group in groups for pair in group]
    ctx.evidence['witness_policy_met']=[dict(checkpoint_note_hash=H(h.raw),size=h.cp.size,met=h.witness_policy_met,reason=h.witness_error) for h,_ in sources]
    for pos,(a,sa) in enumerate(sources):
        for b,sb in sources[pos+1:]:
            if a.cp.size==b.cp.size: verify.continuity(a,b,[],current=False)
            else:
                big,source=(a,sa) if a.cp.size>b.cp.size else (b,sb)
                prefix,_=ctx.scan(big,source,validate=False); verify.continuity(a,b,prefix,current=False)
    verify.continuity(origin,new,raw)
    for group in groups: h=group[-1][0]; require(h.witness_policy_met,h.witness_error)
    known={H(h.raw):h for h,_ in sources}|ctx.heads; unresolved=[]
    for leaf in raw:
        seen=strict_json(leaf)['payload']['envelope']['protected']['seen']
        if seen:
            if seen['checkpoint_note_hash'] not in known: unresolved.append(seen)
            else: require(known[seen['checkpoint_note_hash']].cp.size==seen['size'],'gossip pointer size differs from note')
    return dict(views=len(sources),unresolved_gossip_pointers=unresolved,verification='unproven' if unresolved else 'valid',single_view_prevention='unproven; requires honest quorum intersection')
