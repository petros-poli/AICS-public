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


def lagging_witness(server, *, lag, bundles=True, cosigned_now=True):
    """Pin one witness at quorum 1 that cosigns each new size ``lag`` fake seconds after it first appears, as a real
    log publishes its checkpoint before the witness answers.  ``bundles`` False: bundles keep the log-signed note of
    the whole tree (the aics-server behaviour before 2026-10-20), whatever the witness cosigned.  ``cosigned_now``:
    the head of the fixture (also the saved checkpoint) was cosigned long ago."""
    w=keys.generate_keypair(); honest=server.checkpoint; honest_bundle=server.bundle
    first_seen={len(server.entries):server.now-lag} if cosigned_now else {}
    def note(mirror=False):
        raw=honest(mirror); n=parse_note(raw); cp=parse_checkpoint(n.text)
        seen=first_seen.setdefault(cp.size,server.now)
        if server.now-seen<lag: return raw
        _,sig=sign_cosignature(w,'witness',int(server.now),cp.origin,cp.size,cp.root)
        return Note(n.text,n.signatures+(sig,)).to_bytes()
    server.checkpoint=note
    if not bundles:
        def log_only_bundle(i):
            server.checkpoint=honest
            try: return honest_bundle(i)
            finally: server.checkpoint=note
        server.bundle=log_only_bundle
    ctx=server.context(); ctx.policy.witness_vkeys=[format_vkey(cosignature_vkey('witness',w.public_key()))]; ctx.policy.quorum=1
    return ctx


def test_a_current_head_is_awaited_until_its_witness_cosigns(server):
    ctx=lagging_witness(server,lag=3,cosigned_now=False); started=server.now
    h=ctx.head(); assert h.witness_policy_met and server.now-started==3
    assert len(ctx.evidence['checkpoint_notes'])==4  # every note fetched is kept as evidence
    ctx2=lagging_witness(FakeServer(),lag=3,cosigned_now=False); ctx2.policy.witness_wait_seconds=0
    with pytest.raises(ValueError,match='quorum not met'): ctx2.head()


def test_the_witness_wait_is_bounded_and_ignored_at_quorum_zero(server):
    ctx=lagging_witness(server,lag=10**6,cosigned_now=False); ctx.policy.witness_wait_seconds=5; started=server.now
    with pytest.raises(ValueError,match='quorum not met'): ctx.head()
    assert server.now-started==5
    plain=FakeServer(); qctx=plain.context(); before=plain.now
    assert qctx.head().witness_policy_met and plain.now==before  # quorum 0: log signatures alone, no wait


def frozen(ctx, server):
    """A pinned clock and a sleep that does nothing, as aics-interop's drivers give the harness."""
    at=server.now; ctx.now=lambda: at; ctx.sleep=lambda s: None
    return ctx


def test_witness_waits_end_with_a_frozen_clock(server):
    # A wait bounded only by the clock's reading never ends when the clock does not move (the aics-interop suite
    # hung in such a loop): it is also bounded by the steps that fit in witness_wait_seconds.
    ctx=frozen(lagging_witness(server,lag=10**6,cosigned_now=False),server)
    with pytest.raises(ValueError,match='quorum not met'): ctx.head()
    assert len(ctx.evidence['checkpoint_notes'])==31  # the first fetch and 30 one-second pauses
    with pytest.raises(ValueError,match='quorum not met'):
        check_bundle=ctx.witnessed(lambda: server.bundle(3),lambda b: DU(b['checkpoint_note']))
        verify.head(DU(check_bundle['checkpoint_note']),ctx.policy,ctx.now())
    other=FakeServer(); result=check('G5').run(frozen(lagging_witness(other,lag=10**6,cosigned_now=False),other))
    assert result['verdict']=='fail' and 'quorum not met' in result['details']['reason']


def test_the_restart_wait_ends_with_a_frozen_clock():
    server=BootingServer(10**6); ctx=frozen(server.context(),server); ctx.policy.restart_ready_seconds=5
    result=check('G3').run(ctx)
    assert result['verdict']=='fail' and 'not ready' in result['details']['reason']
    assert server.down==10**6-6  # the first try and five pauses


@pytest.mark.parametrize('guarantee',['G1','G4','G5','G6','G8','G9'])
def test_guarantees_pass_at_quorum_one_with_a_witness_that_cosigns_late(guarantee):
    result=check(guarantee).run(lagging_witness(FakeServer(),lag=2))
    assert result['verdict']=='pass',result['details']


@pytest.mark.parametrize('guarantee',['G1','G6','G8'])
def test_bundles_whose_checkpoint_never_carries_the_quorum_fail(guarantee):
    # The deviation the pre-launch run found: a bundle proven against a log-signed note can never meet quorum 1.
    result=check(guarantee).run(lagging_witness(FakeServer(),lag=2,bundles=False))
    assert result['verdict']=='fail' and 'quorum not met' in result['details']['reason'],result['details']


def test_a_view_is_awaited_and_every_distinct_view_is_compared(server):
    # The origin first serves the log-signed note, then the cosigned one: both are views (the first was log-signed,
    # so it is compared for a split), and the origin met the policy with the second.
    ctx=lagging_witness(server,lag=4,cosigned_now=False); ctx.policy.saved_checkpoint=None
    result=check('G5').run(ctx)
    assert result['verdict']=='pass',result['details']
    assert result['details']['views']==4  # origin twice (log-signed, then cosigned), the mirror, the latest head
    server.faults.add('split_view')  # a conflicting mirror view still fails as a split, waited for or not
    result=check('G5').run(lagging_witness(server,lag=4))
    assert result['verdict']=='fail' and result['details']['reason'].startswith('split-proven'),result['details']


@pytest.mark.parametrize('witnessed',[False,True])
@pytest.mark.parametrize('guarantee',['G4','log.receipt'])
def test_receipt_timing_is_labelled_by_the_harness_clock_at_every_quorum(guarantee,witnessed):
    # AICS-1 §14.4 step 3: the inclusion observation is timed by this harness's own clock, so the conclusion is
    # clock-dependent whatever the pinned quorum; at quorum 1 a witness cosigned the head, it did not time this
    # observation (a founder-run witness's time is not independent evidence either).
    from aics_conformance.core import LOCAL_CLOCK
    server=FakeServer(); ctx=lagging_witness(server,lag=2) if witnessed else server.context()
    result=check(guarantee).run(ctx)
    assert result['verdict']=='pass',result['details']
    timing=result['details']['timing']
    assert timing['clock']==LOCAL_CLOCK and 'clock-dependent' in timing['clock'] and 'witness' not in timing['clock']
    assert timing['met_deadline'] is True and timing['observed_at']<=timing['deadline']
    assert ctx.policy.quorum==(1 if witnessed else 0)


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


class BootingServer(FakeServer):
    """After the restart the instance answers 502 to its next ``down`` checkpoint requests, as a proxy does while the
    restarted app is still starting (``docker compose restart`` returns before the app listens)."""
    def __init__(self,down,*faults): super().__init__(*faults); self.down=down
    def request(self,method,url,body=None,headers=None):
        if self.after_restart and self.down and url.endswith('/checkpoint'):
            self.down-=1; return __import__('aics_conformance.client',fromlist=['Response']).Response(502,b'booting',{})
        return super().request(method,url,body,headers)


def test_restart_readiness_is_waited_out_within_the_bound():
    server=BootingServer(3); ctx=server.context(); ctx.policy.restart_ready_seconds=30
    result=check('G3').run(ctx)
    assert result['verdict']=='pass',result['details']
    assert result['details']['restart']=='executed' and result['details']['ready_after_seconds']==3


def test_restart_unavailability_without_a_wait_is_incomplete_not_success():
    result=check('G3').run(BootingServer(3).context())  # restart_ready_seconds 0: the command must return once ready
    assert result['verdict']=='fail' and result['details']['verification']=='incomplete'
    assert 'not ready' in result['details']['reason']


def test_restart_readiness_wait_is_bounded():
    server=BootingServer(10**6); ctx=server.context(); ctx.policy.restart_ready_seconds=5
    result=check('G3').run(ctx)
    assert result['verdict']=='fail' and result['details']['verification']=='incomplete'
    assert 'not ready 5 s after the restart (restart_ready_seconds 5)' in result['details']['reason']
    assert server.down>10**6-10  # it stopped polling at the bound


def test_restart_readiness_wait_does_not_excuse_a_rollback():
    # The rolled-back head served once the instance answers fails G3 exactly as it does without a boot delay.
    server=BootingServer(2,'restart_rollback'); ctx=server.context(); ctx.policy.restart_ready_seconds=30
    result=check('G3').run(ctx); plain=check('G3').run(FakeServer('restart_rollback').context())
    assert result['verdict']==plain['verdict']=='fail' and server.down==0
    assert result['details']['reason']==plain['details']['reason'] and 'not ready' not in result['details']['reason']


def test_restart_command_argv_runs_then_waits(tmp_path):
    import sys
    marker=tmp_path/'restarted'
    server=FakeServer(); ctx=server.context(); ctx.restart=None
    ctx.policy.restart_command=[sys.executable,'-c',f'open({str(marker)!r},"w").close()']; ctx.policy.restart_ready_seconds=10
    result=check('G3').run(ctx)
    assert result['verdict']=='pass' and result['details']['restart']=='executed' and marker.exists()


@pytest.mark.parametrize('settings',[dict(restart_ready_seconds=-1),dict(restart_ready_seconds=601),dict(restart_ready_seconds=True),
                                     dict(restart_ready_seconds='90'),dict(restart_command='ssh host restart'),dict(restart_command=[]),
                                     dict(restart_command=['ssh','']),dict(restart_command=['ssh',3])])
def test_restart_settings_are_validated(settings):
    from aics_conformance.policy import Policy
    with pytest.raises(ValueError,match='restart_'):
        Policy(copy.deepcopy(FakeServer().trust),**settings)


def test_saved_offline_package_rejects_replaced_trust(ctx):
    result=check('G8').run(ctx); assert result['verdict']=='pass'
    package=result['details']['package']; verify.offline_package(package,ctx.policy,ctx.now())
    tampered=copy.deepcopy(package); tampered['trust_bundle']['origin']='attacker.example'
    with pytest.raises(ValueError,match='independent pins'): verify.offline_package(tampered,ctx.policy,ctx.now())
