from ..core import check
from ..protocol import DU
from .. import verify
@check('G1','Authentic message authorship through complete key history','AICS-1 §§7,14.3','authorship')
def authorship(ctx):
    sender,recipient,entry,note,i,ct,content=ctx.dm_fixture(); b=ctx.client.get('entry',index=i)
    h=verify.head(DU(b['checkpoint_note']),ctx.policy,ctx.now(),historical=True); raw,_=ctx.scan(h,validate=False)
    hist,e=verify.bundle(b,ctx.policy,ctx.now(),prefix=raw)
    return dict(index=i,actor_kid=e['actor_kid'],assumptions=['key possession; exclusive custody is not proven'])
