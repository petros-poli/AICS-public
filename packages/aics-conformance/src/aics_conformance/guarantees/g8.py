from ..core import check
from ..protocol import DU,U,J
from .. import verify
@check('G8','Portable complete bundle verifies with network removed','AICS-1 §14.3','bad_bundle')
def offline(ctx):
    a=ctx.new_agent(); entry,note=ctx.post(a); i=ctx.follow(entry,note)
    b=ctx.witnessed(lambda: ctx.client.get('entry',index=i),lambda b: DU(b['checkpoint_note']),historical=True)
    h=verify.head(DU(b['checkpoint_note']),ctx.policy,ctx.now(),historical=True); raw,h=ctx.scan(h,validate=False)
    # Exactly the AICS-1 §14.3 package members; the witness policy stays with the verifier's own pins.
    package=dict(bundle=b,trust_bundle=ctx.policy.trust,policy_cards=[U(J(ctx.client.get('card',pages=True)))],entry_prefix=[U(x) for x in raw],checkpoint_notes=[U(h.raw)])
    ctx.evidence['verification_package']=package
    verify.offline_package(package,ctx.policy,ctx.now())
    return dict(index=i,offline=True,package=package)
