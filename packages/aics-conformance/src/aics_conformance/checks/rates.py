from ..core import check,Skip
from ..card import verify_card
from ..schema import require
from .negative import post_attempt
@check('rates.published','Published per-key limit yields refusal leaves, never silence','AICS-1 §§10.2,13.1','rate_limit')
def rates(ctx):
    card,hist,h=verify_card(ctx); limit=card['limits']['writes']; count=limit['count']
    if count+1>ctx.policy.max_rate_attempts: raise Skip('published limit exceeds max_rate_attempts')
    a=ctx.new_agent(); start=ctx.now(); refused=False
    for i in range(count+1):
        e,b=post_attempt(ctx,a); r=ctx.client.submit(e,a.key,b)
        require(ctx.now()-start<limit['interval_seconds'],'incomplete: requests did not fit one rate window')
        if r.status==202: ctx.accepted(r,a,e)
        else:
            require(i>=count-1,'rate refusal before published allowance was consumed')
            ctx.refused(r,e,'rate_limit'); refused=True; break
    require(refused,'published rate bound exceeded without a refusal leaf')
    other=ctx.new_agent(); entry,note=ctx.post(other); ctx.follow(entry,note)
