import copy
import pytest
from aics_tlog import Note,Checkpoint,sign_checkpoint,sign_note,cosignature_vkey,sign_cosignature,format_vkey
from aics_identity import keys
from aics_conformance import verify
from aics_conformance.protocol import DU,J,H,U,Agent,envelope,strict_json
from aics_conformance.schema import validate_entry
from aics_conformance.core import CHECKS

@pytest.mark.parametrize('member,value',[
 ('subject','plaintext'),('text','plaintext'),('title','plaintext'),('options',['plaintext']),('reason','plaintext'),('url','https://example.test')])
def test_free_text_rejected_on_leaf_and_inside_envelope(server,member,value):
    for nested in (False,True):
        e=copy.deepcopy(server.entries[3]); e['payload'][member]=value
        if nested: e['payload']['envelope']['payload'][member]=value
        with pytest.raises(ValueError): validate_entry(e,server.origin)

@pytest.mark.parametrize('field,value',[('body_hash','not a hash'),('channel_sha256','eA'),('title_sha256','encoded prose'),('size',True)])
def test_free_text_cannot_hide_in_allowed_metadata_field(server,field,value):
    e=copy.deepcopy(server.entries[3]); e['payload'][field]=value; e['payload']['envelope']['payload'][field]=value
    with pytest.raises(ValueError): validate_entry(e,server.origin)


def test_duplicate_json_members_rejected():
    with pytest.raises(ValueError,match='duplicate'): strict_json(b'{"x":1,"x":2}')


def test_noncanonical_base64_rejected():
    for value in ('YQ==','YR','YQ\n','YQ='):
        with pytest.raises(ValueError): DU(value)


def test_recognized_bad_witness_rejected_and_fresh_quorum_required(server):
    p=server.configuration(); w=keys.generate_keypair(); vk=cosignature_vkey('witness',w.public_key()); p.witness_vkeys=[format_vkey(vk)]; p.quorum=1
    from aics_tlog import parse_note
    note=parse_note(server.checkpoint())
    with pytest.raises(ValueError): verify.head(note.to_bytes(),p,server.now)
    from aics_tlog import parse_checkpoint
    cp=parse_checkpoint(note.text)
    _,sig=sign_cosignature(w,'witness',int(server.now),cp.origin,cp.size,cp.root)
    good=Note(note.text,note.signatures+(sig,)).to_bytes(); verify.head(good,p,server.now)
    with pytest.raises(ValueError): verify.head(good,p,server.now+301)
    assert verify.head(good,p,server.now+301,historical=True).witness_policy_met  # archived: freshness ignored, quorum counted
    assert not verify.head(note.to_bytes(),p,server.now,historical=True).witness_policy_met


def test_signature_set_difference_is_not_a_fork(server):
    p=server.configuration(); a=verify.head(server.checkpoint(),p,server.now)
    from aics_tlog import parse_note
    n=parse_note(a.raw); unknown=keys.generate_keypair(); more=Note(n.text,n.signatures+(sign_note(n.text,unknown,'unknown'),))
    b=verify.head(more.to_bytes(),p,server.now); assert H(a.raw)!=H(b.raw)
    verify.continuity(a,b,[])


def test_missing_http_signature_rejected_with_leaf(ctx):
    from aics_conformance.checks.negative import post_attempt
    a=ctx.new_agent(); e,b=post_attempt(ctx,a)
    r=ctx.client.submit(e,a.key,b,headers={'Content-Type':'application/json'})
    ctx.refused(r,e,'bad_signature',authenticated=False)


def test_bad_proof_does_not_get_classified_as_split(ctx):
    ctx.client.transport.faults.add('bad_proof'); c=next(c for c in CHECKS if c.id=='log.proofs'); result=c.run(ctx)
    assert result['verdict']=='fail'
    assert 'split-proven' not in result['details']['reason']


def test_scan_cap_is_explicit_skip(ctx):
    ctx.policy.max_scan_entries=1; c=next(c for c in CHECKS if c.id=='log.metadata')
    assert c.run(ctx)['verdict']=='skip'

@pytest.mark.parametrize('corrupt',[False,True])
def test_secret_upgrade_history_uses_policy_attestation_and_new_key(server,corrupt):
    # Historical verifier fixtures include no actual secret or private-key material.
    old='unverified:'+U(bytes(range(16))); name='upgrade-fixture'; index=len(server.entries); agent=Agent(name=name)
    q=dict(name_norm=name,prev_event_index=None,ed25519=None,x25519=None,tier='unverified',recovery_kid=None,recovery_pop=None,initial_grant=None)
    e=envelope(agent,server.origin,'name.claim',q,int(server.now)); e['protected'].update(alg='none',kid=old); e['auth']={'scheme':'shared-secret'}; e['sig']=None
    att=dict(actor_kid=old,envelope_hash=H(J(e)),origin=server.origin,ts=int(server.now),type='name.claim')
    entry=dict(v=2,origin=server.origin,type='name.claim',actor_kid=old,ts=int(server.now),payload=dict(envelope=e,**q,attestation=U(server.policy_actor.key.sign(b'AICS-1 secret-attestation\n'+J(att)))))
    server.append(entry)
    r=dict(origin=server.origin,mode='upgrade',name_norm=name,prev_event_index=index,new_ed25519=agent.ed,new_x25519=agent.x,new_tier='verified')
    q={k:v for k,v in r.items() if k!='origin'}|dict(sig_old=None,sig_new=dict(scheme='ed25519',signature=U(agent.key.sign(b'AICS-1 key.rotate\n'+J(r)))),secret_check=U(server.policy_actor.key.sign(b'AICS-1 upgrade-check\n'+J(r))))
    if corrupt: q['secret_check']=U(bytes(64))
    e=envelope(agent,server.origin,'key.rotate',q,int(server.now)); server.append(dict(v=2,origin=server.origin,type='key.rotate',actor_kid=agent.kid,ts=int(server.now),payload=dict(envelope=e,**q)))
    if corrupt:
        from cryptography.exceptions import InvalidSignature
        with pytest.raises(InvalidSignature): verify.History([J(e) for e in server.entries],server.configuration())
    else:
        hist=verify.History([J(e) for e in server.entries],server.configuration()); assert hist.names[name]['kid']==agent.kid


def test_rotation_proof_sshsig_public_api_order():
    from aics_identity.sshsig import sign_sshsig,parse_sshsig
    agent=Agent(); data=b'AICS-1 key.rotate\nexact canonical payload'
    proof=dict(scheme='sshsig',signature=U(parse_sshsig(sign_sshsig(data,agent.key)).to_blob()))
    verify.proof_signature(proof,agent.key.public_key(),data)
    with pytest.raises(ValueError): verify.proof_signature(proof,agent.key.public_key(),data+b'x')
