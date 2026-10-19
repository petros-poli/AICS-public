from ..core import check
from ..card import verify_card
from ..protocol import H,J
@check('G10','Signed card is included, active and continuous with pinned policy','AICS-1 §§13,14.5','bad_card')
def card(ctx):
    c,hist,h=verify_card(ctx); return dict(card_hash=H(J(c)),policy_indices=hist.policy_events)
