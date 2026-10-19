from ..core import check
from ..checks.log import proofs
@check('G2','Tamper-evident total order from authenticated tiles','AICS-1 §§6,14.1–14.2','bad_proof')
def order(ctx): return proofs(ctx)
