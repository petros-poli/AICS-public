"""Checks, bounded scans, receipts and portable failure evidence."""
import math
import time
import traceback
from dataclasses import dataclass
from aics_tlog import MerkleTree, leaf_hash, inclusion_proof_from_tiles
from .client import JSONClient, Tiles, TCPGate
from .protocol import Agent, J, H, U, DU, envelope, seal, strict_json
from .schema import require
from . import adapter, verify

class Skip(Exception): pass

#: How a receipt's inclusion observation is timed (:meth:`Context.follow`): by this harness's own recorded clock, at
#: every witness quorum.  AICS-1 §14.4 step 3 labels such a conclusion clock-dependent; only the breach branch, which
#: compares the counted witness timestamps with ``deadline+30``, can be independently timed.
LOCAL_CLOCK='local; clock-dependent (AICS-1 §14.4 step 3)'

@dataclass
class Check:
    id: str
    title: str
    spec_ref: str
    function: object
    fault: str
    def run(self,ctx):
        ctx.evidence={}; start=len(ctx.client.transcript)
        try:
            detail=self.function(ctx) or {}; verdict='pass'
            detail={'verification':'valid',**detail}
        except Skip as exc: verdict='skip'; detail=dict(verification='unproven',reason=str(exc))
        except Exception as exc:
            verdict='fail'; message=str(exc) or type(exc).__name__
            status='stale' if 'stale checkpoint' in message else 'incomplete' if isinstance(exc,(OSError,TimeoutError,EOFError)) or 'incomplete' in message or 'unproven' in message else 'invalid'
            detail=dict(verification=status,reason=message,error_type=type(exc).__name__)
            detail['evidence']={'trust_bundle':ctx.policy.trust,'witness_policy':{'vkeys':ctx.policy.witness_vkeys,'quorum':ctx.policy.quorum,'max_checkpoint_age':ctx.policy.max_checkpoint_age},
                **ctx.evidence,'transcript':ctx.client.transcript[start:]}
        return dict(id=self.id,title=self.title,spec_ref=self.spec_ref,verdict=verdict,details=detail)

CHECKS=[]
def check(id,title,spec_ref,fault):
    def deco(fn):
        CHECKS.append(Check(id,title,spec_ref,fn,fault)); return fn
    return deco

class Context:
    def __init__(self, client, tiles, policy, *, gate=None, clock=None, sleep=None, restart=None):
        self.client=client; self.tiles=tiles; self.policy=policy; self.gate_target=gate
        self.now=clock or time.time; self.sleep=sleep or time.sleep; self.restart=restart; self.evidence={}; self.heads={}; self.submissions={}
    def head(self,source=None,*,historical=False,accept=True):
        """Fetch and verify a checkpoint note (verify.head).  With ``accept=False`` it is only authenticated by
        origin and log signature, its witness policy recorded (verify.authenticate): AICS-1 §14.6 compares
        log-signed views before the witness policy decides acceptance.  Only accepted heads are kept in ``heads``.

        A current head that the log signed but that misses a positive witness quorum is fetched again, for at most
        ``witness_wait_seconds`` (:meth:`witness_wait`): a log publishes a checkpoint before its witnesses cosign
        it (AICS-1 §6.3 forbids accepting it, not waiting for its cosignature).  Every note fetched is evidence."""
        tiles=source or self.tiles; pauses=self.witness_pauses()
        while True:
            raw=tiles.checkpoint()
            self.evidence.setdefault('checkpoint_notes',[]).append(U(raw))
            self.evidence.setdefault('observations',[]).append({'note_hash':H(raw),'at':self.now(),'source':tiles.url})
            h=verify.authenticate(raw,self.policy,self.now(),historical=historical)
            if h.witness_policy_met or historical or not accept or not next(pauses,False): break
        if accept and not historical: require(h.witness_policy_met,h.witness_error)
        if h.witness_policy_met: self.heads[H(raw)]=h
        return h
    def pauses(self,budget):
        """The waits of a bounded retry loop: each step sleeps one poll interval and yields True, for ``budget``
        seconds in all by the context's clock and never more steps than fit in it, so a frozen clock (a test's
        pinned one, a no-op sleep) ends the loop too.  A budget of 0 yields nothing."""
        started=self.now(); steps=math.ceil(budget/self.policy.poll_seconds) if budget>0 else 0
        def steps_left():
            for _ in range(steps):
                waited=self.now()-started
                if waited>=budget: return
                self.sleep(min(self.policy.poll_seconds,budget-waited)); yield True
        return steps_left()
    def witness_pauses(self):
        """:meth:`pauses` for a note that the log signed but that misses the pinned witness policy:
        ``witness_wait_seconds`` at a positive quorum, none at quorum 0."""
        return self.pauses(self.policy.witness_wait_seconds if self.policy.quorum else 0)
    def witnessed(self,fetch,note_of,*,historical=False):
        """``fetch()`` (a bundle or a lookup) again while the checkpoint note it states (``note_of(result)``, bytes)
        is signed by the log but misses the pinned witness policy, at most ``witness_wait_seconds`` and only at a
        positive quorum: a server states lookups and proofs at checkpoints its witnesses may not have cosigned yet.
        A note the log did not sign raises at once.  The caller verifies the result exactly as without a wait."""
        pauses=self.witness_pauses()
        while True:
            obj=fetch(); h=verify.authenticate(note_of(obj),self.policy,self.now(),historical=historical)
            if h.witness_policy_met or not next(pauses,False): return obj
    def scan(self,h=None,source=None,*,validate=True):
        h=h or self.head(); source=source or self.tiles
        if h.cp.size>self.policy.max_scan_entries: raise Skip('complete scan exceeds configured max_scan_entries; raise limit')
        reader=source.authenticated(h.cp); reader.check_root()
        entries=[]; self.evidence['entry_prefix']=[]
        for i in range(h.cp.size):
            raw=reader.entry(i); entries.append(raw); self.evidence['entry_prefix'].append(U(raw))
        require(MerkleTree(entries).root()==h.cp.root,'authenticated scan root')
        return (verify.History(entries,self.policy) if validate else entries),h
    def prepare(self,agent,typ,q,body=None,**kw):
        h=self.head(); seen=dict(checkpoint_note_hash=H(h.raw),size=h.cp.size)
        e=envelope(agent,self.policy.trust['origin'],typ,q,int(self.now()),seen=seen,**kw)
        self.submissions[H(J(e))]=h
        return e
    def submit(self,agent,typ,q,body=None,**kw):
        e=self.prepare(agent,typ,q,body,**kw); r=self.client.submit(e,agent.key,body)
        return self.accepted(r,agent,e)
    def accepted(self,r,agent=None,e=None):
        require(r.status==202,f'expected accepted write, HTTP {r.status}: {r.text()[:200]}')
        obj=r.json(); entry=adapter.field(obj,'entry'); note=DU(adapter.field(obj,'receipt_note'))
        if e is not None: require(entry['payload']['envelope']==e,'server changed signed envelope')
        verify.receipt(note,entry,self.policy)
        if agent is not None: agent.previous=e
        return entry,note
    def new_agent(self):
        a=Agent(); entry,note=self.submit(a,'name.claim',a.claim()); i=self.follow(entry,note)
        a.claim_index=i; a.event_index=i; return a
    def post(self,a,text='conformance synthetic public body'):
        body=J(dict(channel='conformance',title=None,text=text))
        q=dict(channel_sha256=H(b'conformance'),parent_index=None,body_hash=H(body),size=len(body),title_sha256=None)
        return self.submit(a,'post',q,body)
    def follow(self,entry,note):
        r=verify.receipt(note,entry,self.policy); deadline=r['submitted_at']+60
        self.evidence['receipt']=U(note); self.evidence['entry']=U(J(entry)); started=self.now()
        self.evidence['timing_evidence']={'started_at':started,'deadline':deadline,'clock':LOCAL_CLOCK}
        while True:
            raw,h=self.scan(validate=False)
            pre=self.submissions.get(H(J(entry['payload']['envelope'])))
            if pre is not None:
                verify.continuity(pre,h,raw)
                self.evidence['pre_submission_checkpoint']=U(pre.raw)
            digest=leaf_hash(J(entry)); matches=[i for i,b in enumerate(raw) if leaf_hash(b)==digest]
            if matches:
                self.evidence['inclusion_proof']=[__import__('base64').b64encode(x).decode() for x in MerkleTree(raw).inclusion_proof(matches[0])]
                # The observation is timed by this harness's own clock at every quorum: a witness timestamp of the
                # head says when that head was cosigned, not when this inclusion was first observed.
                self.evidence['timing_evidence']=dict(observed_at=self.now(),deadline=deadline,clock=LOCAL_CLOCK,met_deadline=self.now()<=deadline)
                require(self.now()<=deadline,'eventual inclusion observed, deadline compliance unproven (no deadline observation)')
                return matches[0]
            independently_timed=bool(h.timestamps) and min(h.timestamps.values())>deadline+30
            adequately_timed=independently_timed or self.policy.quorum==0 and self.now()>deadline+30
            if adequately_timed:
                self.evidence['timing_evidence']=dict(observed_at=self.now(),deadline=deadline,witness_timestamps=h.timestamps,clock_dependent=not independently_timed)
                raise ValueError('receipt breach: exact leaf absent from complete authenticated post-deadline scan')
            if self.now()-started>=self.policy.receipt_wait_seconds: raise ValueError('receipt incomplete: no adequately timed inclusion/absence evidence')
            self.sleep(min(self.policy.poll_seconds,self.policy.receipt_wait_seconds-(self.now()-started)))
    def refused(self,r,e,reason,*,authenticated=True):
        self.evidence['attempted_envelope']=U(J(e))
        require(400<=r.status<500,'submission was not refused')
        obj=r.json(); entry=adapter.field(obj,'entry'); q=entry['payload']; note=DU(adapter.field(obj,'receipt_note'))
        require(entry['type']=='refusal' and q['reason_code']==reason,'wrong refusal reason/type')
        require(q['envelope_hash']==H(J(e)) and q['request_hash'] is None,'refusal commitment')
        p=e['protected']
        require(q['attempt_kid']==(p['kid'] if authenticated else None) and q['attempt_nonce']==(p['nonce'] if authenticated else None) and q['attempt_expires']==(p['expires'] if authenticated else None),'unauthenticated or missing refusal identity')
        i=self.follow(entry,note); hist,h=self.scan(); require(hist.entries[i]==entry,'refusal not authenticated')
        return entry
    def dm_fixture(self):
        sender=self.new_agent(); recipient=self.new_agent()
        grant,note=self.submit(recipient,'grant',dict(owner_kid=recipient.kid,sender_kid=sender.kid,max=4,expires=int(self.now())+600,prev_grant_index=None))
        gi=self.follow(grant,note)
        nonce=U(__import__('secrets').token_bytes(16)); content=b'conformance private message'
        ct=seal(content,DU(recipient.x),sender.kid,recipient.kid,nonce)
        q=dict(to_kid=recipient.kid,to_key_leaf_index=recipient.claim_index,encryption='x25519-xsalsa20-poly1305',eph_pk=U(ct[:32]),ct_hash=H(ct),size=len(ct),
               seq=sender.previous['protected']['seq']+1,prev=H(J(sender.previous)),grant_index=gi)
        entry,note=self.submit(sender,'dm',q,ct,nonce=nonce); i=self.follow(entry,note)
        return sender,recipient,entry,note,i,ct,content
    def tcp(self,plain=False):
        if hasattr(self.client.transport,'tcp_gate'): return self.client.transport.tcp_gate(plain)
        target=self.policy.gate_plain if plain else self.gate_target
        if plain and not target and self.gate_target:
            host,port=self.gate_target.rsplit(':',1)
            # 7701 is the plaintext port only beside the deployment profile's 7700: a card names the instance's own two
            # gate ports (AICS-1 §13.1), and staging's TLS gate on 7800 shares its address with production's 7701.
            if port!='7700': raise Skip("plaintext TCP target not configured: set gate_plain to this instance's own host:port")
            target=host+':7701'
        if not target: raise Skip('TCP target not configured')
        return TCPGate(target,tls=False if plain else None)
