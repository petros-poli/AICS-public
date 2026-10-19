import copy
import json
import pytest
from aics_identity import keys
from aics_tlog import (MerkleTree, Note, Checkpoint, parse_note, parse_checkpoint, parse_vkey, verify_note, leaf_hash,
    cosignature_vkey, format_vkey, sign_checkpoint, sign_cosignature)
from aics_conformance.protocol import DU,J,H,U,Agent,envelope,open_message
from aics_conformance import checks, guarantees, verify  # noqa: F401 (checks and guarantees register CHECKS)
from aics_conformance.core import CHECKS
from aics_conformance.fakes import FakeServer


def check(id): return next(c for c in CHECKS if c.id==id)

def test_split_evidence_verifies_without_server():
    s=FakeServer('split_view'); result=check('G5').run(s.context()); evidence=result['details']['evidence']
    notes=[parse_note(DU(n)) for n in evidence['checkpoint_notes']]
    key=parse_vkey(evidence['trust_bundle']['log_vkey'])
    assert all(verify_note(n,[key]) for n in notes)
    heads=[parse_checkpoint(n.text) for n in notes]
    assert heads[0].size==heads[1].size and heads[0].root!=heads[1].root


def witnessed(server, *, mirror_cosigned):
    """Pin one witness at quorum 1; it cosigns what the origin serves, the mirror's note is log-signed only unless
    ``mirror_cosigned``."""
    w=keys.generate_keypair(); honest=server.checkpoint
    def cosign(raw):
        note=parse_note(raw); cp=parse_checkpoint(note.text)
        _,sig=sign_cosignature(w,'witness',int(server.now),cp.origin,cp.size,cp.root)
        return Note(note.text,note.signatures+(sig,)).to_bytes()
    server.checkpoint=lambda mirror=False: cosign(honest(mirror)) if mirror_cosigned or not mirror else honest(mirror)
    ctx=server.context(); ctx.policy.witness_vkeys=[format_vkey(cosignature_vkey('witness',w.public_key()))]; ctx.policy.quorum=1
    return ctx


def test_unwitnessed_equivocation_is_a_split_view(server):
    """AICS-1 §14.6 step 2: a log-signed note of equal size and another root is evidence of equivocation whether or
    not it met its witness policy; G5 says split-proven and states which note met the policy."""
    server.faults.add('split_view'); result=check('G5').run(witnessed(server,mirror_cosigned=False)); d=result['details']
    assert (result['verdict'],d['verification'])==('fail','invalid') and d['reason'].startswith('split-proven'),d['reason']
    met=d['evidence']['witness_policy_met']; missed=[m for m in met if not m['met']]
    assert len(missed)==1 and 'quorum not met' in missed[0]['reason'] and len(met)>len(missed)
    notes={DU(n) for n in d['evidence']['checkpoint_notes']}
    assert {parse_checkpoint(parse_note(n).text).root for n in notes}>={bytes(32)}  # the conflicting note is kept


def test_unwitnessed_consistent_mirror_fails_the_witness_policy_not_as_a_split(server):
    result=check('G5').run(witnessed(server,mirror_cosigned=False)); d=result['details']
    assert result['verdict']=='fail' and d['reason'].startswith('quorum not met'),d['reason']
    assert check('G5').run(witnessed(FakeServer(),mirror_cosigned=True))['verdict']=='pass'


def test_historical_heads_are_log_authenticated_and_state_their_witness_policy(server):
    ctx=witnessed(server,mirror_cosigned=False); log_only=server.checkpoint(True)
    with pytest.raises(ValueError,match='quorum not met'): verify.head(log_only,ctx.policy,ctx.now())
    h=verify.head(log_only,ctx.policy,ctx.now(),historical=True)
    assert (h.witness_policy_met,h.cp.size)==(False,len(server.entries)) and 'quorum not met' in h.witness_error
    assert verify.head(server.checkpoint(),ctx.policy,ctx.now(),historical=True).witness_policy_met
    foreign=sign_checkpoint(Checkpoint(server.origin,1,bytes(32)),keys.generate_keypair(),server.origin).to_bytes()
    with pytest.raises(ValueError,match='no signature from log key'): verify.head(foreign,ctx.policy,ctx.now(),historical=True)
    b=server.bundle(3); prefix=[J(e) for e in server.entries]
    verify.bundle(b,ctx.policy,ctx.now(),prefix=prefix)
    with pytest.raises(ValueError,match='quorum not met'):  # §14.3: a bundle's checkpoint still needs its witnesses
        verify.bundle({**b,'checkpoint_note':U(log_only)},ctx.policy,ctx.now(),prefix=prefix)


def test_receipt_breach_contains_complete_absence_and_clock_evidence():
    s=FakeServer('dropped_receipt'); result=check('G4').run(s.context()); evidence=result['details']['evidence']
    raw=[DU(x) for x in evidence['entry_prefix']]; entry=json.loads(DU(evidence['entry']))
    receipt=verify.receipt(DU(evidence['receipt']),entry,s.configuration())
    cp=parse_checkpoint(parse_note(DU(evidence['checkpoint_notes'][-1])).text)
    assert MerkleTree(raw).root()==cp.root and len(raw)==cp.size
    assert all(leaf_hash(x).hex()!=receipt['entry_hash'] for x in raw)
    assert evidence['timing_evidence']['observed_at']>receipt['submitted_at']+90
    assert evidence['timing_evidence']['clock_dependent'] is True


def test_missing_tiles_is_incomplete_not_split(server):
    ctx=server.context(); server.faults.add('dropped_receipt')
    server.resources=lambda: {}
    r=check('G4').run(ctx)
    assert r['verdict']=='fail'
    assert 'split-proven' not in r['details']['reason']


def test_unequal_size_constructive_fork(ctx):
    a=ctx.head(); raw=list(ctx.scan(a,validate=False)[0]); raw.append(b'new')
    from aics_tlog import sign_checkpoint,Checkpoint
    s=ctx.client.transport
    b=verify.head(sign_checkpoint(Checkpoint(s.origin,len(raw),MerkleTree(raw).root()),s.log,s.origin).to_bytes(),ctx.policy,ctx.now())
    verify.continuity(a,b,raw)
    bad=copy.copy(a); bad.cp=Checkpoint(s.origin,a.cp.size,bytes(32))
    with pytest.raises(ValueError,match='conflicting prefix'): verify.continuity(bad,b,raw)


def test_no_private_key_in_serializable_report(ctx):
    result=check('G8').run(ctx); assert result['verdict']=='pass'
    text=json.dumps(result)
    assert 'private_seed' not in text and 'private_key' not in text
    package=result['details']['package']
    verify.bundle(package['bundle'],ctx.policy,ctx.now(),prefix=[DU(x) for x in package['entry_prefix']])

@pytest.mark.parametrize('field',['from_kid','to_kid','envelope_nonce'])
def test_inner_binding_rejects_validly_signed_rewrap(ctx,field):
    sender,recipient,entry,note,i,ct,content=ctx.dm_fixture(); original=entry['payload']['envelope']; other=Agent()
    q=copy.deepcopy(original['payload']); nonce=original['protected']['nonce']; signer=sender
    if field=='from_kid': signer=other
    elif field=='to_kid': q['to_kid']=other.kid
    else: nonce=U(bytes(16))
    rewritten=envelope(signer,ctx.policy.trust['origin'],'dm',q,int(ctx.now()),nonce=nonce)
    with pytest.raises(ValueError,match='inner-header'): open_message(rewritten,ct,recipient.encryption_key)


def test_receipt_wrong_mmd_is_rejected():
    result=check('log.receipt').run(FakeServer('bad_receipt').context())
    assert result['verdict']=='fail' and 'MMD' in result['details']['reason']


def test_missing_refusal_fails_not_skip():
    result=check('negative.bad-signature').run(FakeServer('missing_refusal').context())
    assert result['verdict']=='fail'


def test_unconfigured_restart_is_skip(ctx):
    ctx.restart=None; ctx.policy.saved_checkpoint=None
    assert check('G3').run(ctx)['verdict']=='skip'


def test_saved_offline_package_rejects_replaced_trust(ctx):
    result=check('G8').run(ctx); assert result['verdict']=='pass'
    package=result['details']['package']; verify.offline_package(package,ctx.policy,ctx.now())
    tampered=copy.deepcopy(package); tampered['trust_bundle']['origin']='attacker.example'
    with pytest.raises(ValueError,match='independent pins'): verify.offline_package(tampered,ctx.policy,ctx.now())
