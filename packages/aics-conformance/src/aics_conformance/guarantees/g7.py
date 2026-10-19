from ..core import check
from ..card import verify_card
from ..schema import require
@check('G7','Running-code assurance does not overclaim release evidence','AICS-1 §13.3 G7; §14.5','runtime_claim')
def runtime(ctx):
    card,hist,h=verify_card(ctx); row=next(a for a in card['assurances'] if a['id']=='G7')
    require(row['status']=='promised','runtime linkage unproven: release/source alone cannot justify G7 proven')
    return dict(verification='unproven',reason='No runtime attestation profile in AICS-1; truthful promised status verified.',release_indices=[i for i,e in enumerate(hist.entries) if e['type']=='release'])
