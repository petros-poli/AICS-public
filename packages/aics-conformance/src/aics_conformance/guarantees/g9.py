from ..core import check
from ..protocol import DU,H
from .. import adapter,verify
from ..schema import require
@check('G9','Inbox completeness and consent reconstructed from all tiles','AICS-1 §§9,14.3','inbox_drop')
def inbox(ctx):
    sender,recipient,entry,note,i,ct,content=ctx.dm_fixture(); api=ctx.client.get('inbox',kid=recipient.kid,params={'from':0}); ids,note=adapter.lookup(api)
    h=verify.head(DU(note),ctx.policy,ctx.now()); hist,h=ctx.scan(h)
    expected=[j for j,e in enumerate(hist.entries) if e['type']=='dm' and e['payload']['to_kid']==recipient.kid]
    require(ids==expected,'API inbox omits/reorders/adds logged messages')
    return dict(indices=expected,checkpoint_hash=H(h.raw),scope='metadata completeness at API checkpoint, not timely body delivery')
