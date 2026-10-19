from ..core import check
from ..checks.log import receipt
@check('G4','Receipt promises followed through to exact leaves','AICS-1 §§10.1,14.4','dropped_receipt')
def followthrough(ctx): return receipt(ctx)
