"""Agent-side verification independent of fake-server acceptance logic."""
from dataclasses import dataclass
from aics_identity import keys, sshsig
from aics_tlog import (Note, parse_note, parse_checkpoint, parse_vkey, verify_checkpoint,
    verify_note, MerkleTree, verify_leaf_inclusion, verify_consistency, leaf_hash)
from .protocol import J, H, U, DU, DB, strict_json, verify_signature
from .schema import require, validate_entry

@dataclass
class Head:
    raw: bytes
    cp: object
    observed_at: float
    timestamps: dict
    witness_policy_met: bool = True
    witness_error: str | None = None


def authenticate(raw, policy, now, *, historical=False):
    """A note authenticated by the pinned origin and log key alone (AICS-1 §14.1 steps 1-2, §14.6 step 1), with the
    pinned witness policy evaluated and recorded but not required (§14.1 step 3): fresh cosignatures for a current
    head, freshness ignored for an archived one (§6.3).  Whatever its witness lines, the note is evidence of what the
    log signed (§14.6 step 2); ``witness_policy_met`` and ``witness_error`` state whether it also met its policy."""
    note=parse_note(raw); cp=parse_checkpoint(note.text)
    require(not cp.extension_lines and cp.size<=9007199254740991,'checkpoint profile')
    log=parse_vkey(policy.trust['log_vkey'])
    # The log signature alone: lines under other keys neither sign the note nor unsign it.
    own=Note(note.text,tuple(s for s in note.signatures if (s.name,s.key_id)==(log.name,log.key_id)))
    res=verify_checkpoint(own,log,expected_origin=policy.trust['origin'],now=int(now))
    require(res.ok,res.error or 'checkpoint log signature')
    res=verify_checkpoint(note,log,
        witness_keys=[parse_vkey(k) for k in policy.witness_vkeys],quorum=policy.quorum,
        expected_origin=policy.trust['origin'],now=int(now),
        max_age_seconds=None if historical else policy.max_checkpoint_age,
        max_future_seconds=None if historical else 30)
    error=None if res.ok else ('stale checkpoint: ' if res.stale else '')+(res.error or 'checkpoint signature/quorum')
    return Head(raw,cp,now,res.timestamps,res.ok,error)


def head(raw, policy, now, *, historical=False):
    """``authenticate``; a current head is accepted only with the pinned quorum of fresh cosignatures (§6.3: no
    online checkpoint without them).  An archived head (``historical``) is authenticated as signed by the log and
    never accepted as current; a caller that relies on its witness policy requires ``witness_policy_met``."""
    h=authenticate(raw,policy,now,historical=historical)
    if not historical: require(h.witness_policy_met,h.witness_error)
    return h


def continuity(old,new,entries,*,current=True):
    require(old.cp.origin==new.cp.origin,'different origins')
    if current: require(new.cp.size>=old.cp.size,'rollback: smaller head offered as current')
    small,big=(old,new) if old.cp.size<=new.cp.size else (new,old)
    if small.cp.size==big.cp.size:
        require(small.cp.root==big.cp.root,'split-proven: signed equal-size roots differ')
        return
    require(len(entries)==big.cp.size,'consistency-unproven: incomplete larger prefix')
    tree=MerkleTree(entries)
    require(tree.root()==big.cp.root,'larger prefix does not authenticate')
    require(tree.root(small.cp.size)==small.cp.root,'split-proven: authenticated conflicting prefix')
    require(verify_consistency(small.cp.size,big.cp.size,small.cp.root,big.cp.root,
                              tree.consistency_proof(small.cp.size)),'consistency verification')


def proof_signature(proof, pub, data):
    if proof['scheme']=='ed25519': pub.verify(DU(proof['signature']),data)
    elif proof['scheme']=='sshsig': sshsig.verify_sshsig(DU(proof['signature']),data,pub,namespace='aics')
    else: raise ValueError('unknown proof')


KEY_TIERS=('verified','third-party-generated')


def sup_asset_hash(origin):
    """AICS-1 §20.2: ``hexH`` of the exact SUP asset descriptor of this log's origin."""
    return H(J(dict(asset='SUP',buys=['owner_action','hosting','storage'],decimals=0,origin=origin,refundable=False,
                    transferable=False)))


class History:
    """Complete authenticated prefix, with validity evaluated immediately before each index.

    The negotiated profiles in ``policy.profiles`` (AICS-1 §§19-20) are the only ones whose entries are accepted;
    under SUP-1 the tasks, awards, owner actions, contributions and every account's balance are replayed in index
    order (§20.9), while a contribution's on-chain check stays unproven: its transaction is off-leaf."""
    def __init__(self, raw_entries, policy):
        self.raw=raw_entries; self.entries=[]; self.names={}; self.bound=set(); self.active={}
        self.last={}; self.nonces={}; self.grants={}; self.used={}; self.tombstones={}; self.policy_events=[]
        self.trust=policy.trust; self.profiles=tuple(getattr(policy,'profiles',()) or ())
        self.kid_name={}; self.leaf_index={}; self.tasks={}; self.awarded=set(); self.balances={}
        self.owner_actions={}; self.requests={}; self.paid=set(); self.contributions=set()
        for i,raw in enumerate(raw_entries):
            e=strict_json(raw); require(J(e)==raw,'noncanonical entry bytes')
            validate_entry(e,self.trust['origin'],self.profiles); self.apply(i,e); self.entries.append(e)
            self.leaf_index[leaf_hash(raw).hex()]=i

    def apply(self,i,e):
        env=e['payload']['envelope']; p=env['protected']; q=env['payload']; kid=p['kid']; typ=e['type']; ts=e['ts']
        secret=env['auth']['scheme']=='shared-secret'
        if secret:
            require(typ in ('name.claim','post'),'secret tier cannot authorize this type')
            att=dict(actor_kid=kid,envelope_hash=H(J(env)),origin=e['origin'],ts=ts,type=typ)
            keys.parse_did_key(self.trust['policy_kid']).verify(DU(e['payload']['attestation']),b'AICS-1 secret-attestation\n'+J(att))
        else: verify_signature(env)
        require(p['created']<=ts+30 and p['created']>=ts-300 and p['created']<p['expires']<=p['created']+300 and ts<p['expires'],'acceptance-time freshness')
        prior=self.last.get(kid)
        require(p['seq']==(prior['protected']['seq']+1 if prior else 0) and p['prev']==(H(J(prior)) if prior else None),'sender sequence/predecessor')
        require((kid,p['nonce']) not in self.nonces or self.nonces[kid,p['nonce']]<=ts,'reused nonce')
        self.nonces[kid,p['nonce']]=p['expires']; self.last[kid]=env
        service={'refusal','tombstone','policy','release','suspension','freeze','report'}
        if typ in service:
            expected=self.trust['owner_kid'] if typ=='report' and q['kind']=='owner_action' else self.trust['policy_kid']
            require(kid==expected,'administrative actor is not pinned authority')
        elif typ=='sup.task' or typ=='sup.credit' and q['source']=='task':
            require(kid==self.trust['owner_kid'],'owner-signed SUP-1 entry by another key')  # §20.3
        elif typ=='sup.credit': require(kid==self.trust['policy_kid'],'contribution credit is not a policy statement')
        elif typ!='name.claim' and not (typ=='key.rotate' and q['mode']=='upgrade'): require(kid in self.active,'signer not current at index')
        if typ=='name.claim':
            require(q['name_norm'] not in self.names and kid not in self.bound,'duplicate claim or key reuse')
            if not secret:
                require(keys.did_key(keys.public_key_from_bytes(DU(q['ed25519'])))==kid and q['tier'] in ('verified','third-party-generated') and q['x25519'] is not None,'claim proof of possession/tier')
                require(kid not in (self.trust['policy_kid'],self.trust['owner_kid'],keys.did_key(keys.public_key_from_bytes(parse_vkey(self.trust['log_vkey']).public_key))),'service/agent keys must be distinct')
            else: require(q['tier']=='unverified' and all(q[k] is None for k in ('ed25519','x25519','recovery_kid','recovery_pop','initial_grant')),'unverified claim constraints')
            if q['recovery_kid'] is not None:
                require(q['recovery_pop'] is not None,'recovery proof absent')
                r={k:q[k] for k in ('name_norm','ed25519','x25519','recovery_kid')}|{'origin':e['origin']}
                proof_signature(q['recovery_pop'],keys.parse_did_key(q['recovery_kid']),b'AICS-1 recovery-declaration\n'+J(r))
            state=dict(kid=kid,x=q['x25519'],key_index=i,event=i,revoked=False,name=q['name_norm'],tier=q['tier'])
            self.names[q['name_norm']]=state; self.active[kid]=state; self.bound.add(kid); self.kid_name[kid]=q['name_norm']
            if q['initial_grant'] is not None:
                g=q['initial_grant']; require(g['max']==0 or g['expires']>ts,'initial grant expiry'); self.grants[kid,g['sender_kid']]=dict(g,index=i,ts=ts)
        elif typ in ('key.rotate','key.revoke','x25519.rotate'):
            state=self.names[q['name_norm']]
            upgrade=typ=='key.rotate' and q['mode']=='upgrade'
            require(not state['revoked'] and state['event']==q['prev_event_index'],'key event fork/revoked')
            if not upgrade: require(state['kid']==kid,'wrong key event signer')
            if typ=='key.rotate':
                r={k:v for k,v in q.items() if k not in ('sig_old','sig_new','secret_check')}|{'origin':e['origin']}
                data=b'AICS-1 key.rotate\n'+J(r); new=keys.public_key_from_bytes(DU(q['new_ed25519'])); newkid=keys.did_key(new)
                require(q['new_tier'] in ('verified','third-party-generated'),'rotation cannot downgrade to secret tier')
                if upgrade:
                    require(state['kid'].startswith('unverified:') and q['sig_old'] is None and newkid==kid and p['seq']==0 and q['new_x25519'] is not None,'invalid secret upgrade')
                    keys.parse_did_key(self.trust['policy_kid']).verify(DU(q['secret_check']),b'AICS-1 upgrade-check\n'+J(r))
                else: proof_signature(q['sig_old'],keys.parse_did_key(kid),data)
                proof_signature(q['sig_new'],new,data); require(newkid not in self.bound,'rotation key reuse')
                del self.active[state['kid']]; state['kid']=newkid; self.active[newkid]=state; self.bound.add(newkid)
                state['tier']=q['new_tier']; self.kid_name[newkid]=state['name']
                if q['new_x25519'] is not None: state.update(x=q['new_x25519'],key_index=i)
            elif typ=='key.revoke': state['revoked']=True; del self.active[kid]
            else: state.update(x=q['new_x25519'],key_index=i)
            state['event']=i
        elif typ=='grant':
            require(q['owner_kid']==kid,'grant ownership'); pair=kid,q['sender_kid']; prior=self.grants.get(pair)
            require(q['prev_grant_index']==(prior['index'] if prior else None),'grant predecessor')
            require(q['max']==0 or q['expires']>ts,'grant expiry'); self.grants[pair]=dict(q,index=i,ts=ts)
        elif typ in ('dm','capsule'):
            recipient=q.get('to_kid',q.get('owner_kid')); state=self.active.get(recipient)
            require(state and state['key_index']==q['to_key_leaf_index'],'recipient key provenance')
            if typ=='dm':
                require(q['seq']==p['seq'] and q['prev']==p['prev'],'dm chain copy')
                g=self.grants.get((recipient,kid),self.grants.get((recipient,'*')))
                require(g and g['index']==q['grant_index'] and g['max']>self.used.get(g['index'],0) and g['expires']>ts,'DM without live consent')
                self.used[g['index']]=self.used.get(g['index'],0)+1
            else: require(recipient==kid,'capsule ownership')
        elif typ=='tombstone':
            require(q['target_index']<i,'tombstone must target earlier leaf')
            if self.entries[q['target_index']]['type'] in ('dm','capsule'): require(q['reason_code']=='order','ciphertext tombstone reason')
            self.tombstones[q['target_index']]=i
        elif typ=='refusal':
            if q['attempt_kid'] is not None:
                require(q['attempt_nonce'] is not None and q['attempt_expires'] is not None,'partial authenticated tuple')
                self.nonces[q['attempt_kid'],q['attempt_nonce']]=q['attempt_expires']
        elif typ=='policy':
            require(q['log_kid']!=q['policy_kid'] and q['owner_kid'] not in (q['log_kid'],q['policy_kid']),'service key separation')
            require(q['policy_kid']==self.trust['policy_kid'] and q['owner_kid']==self.trust['owner_kid'],'policy key substitution')
            require(q['log_kid']==keys.did_key(keys.public_key_from_bytes(parse_vkey(self.trust['log_vkey']).public_key)),'log key substitution')
            require(q['prev_policy_index']==(self.policy_events[-1] if self.policy_events else None),'policy chain')
            if not self.policy_events:
                require(i==0 and q['kind']=='charter' and q['effective_after']==0,'leaf zero charter')
                data=b'AICS-1 policy\n'+J({k:v for k,v in q.items() if k!='log_sig'})
                keys.parse_did_key(q['log_kid']).verify(DU(q['log_sig']),data)
            else: require(q['log_sig'] is None,'later policy countersignature')
            self.policy_events.append(i)
        elif typ=='report' and q['kind']=='owner_action': self.owner_action(i,e,q)
        elif typ in ('sup.task','sup.credit','sup.spend'): self.sup(i,e,q,kid,ts)

    def account(self,kid,what):
        """The key-tier name whose current signing key is ``kid`` (AICS-1 §20.2: an account), else a refusal."""
        name=self.kid_name.get(kid); state=self.names.get(name)
        require(state is not None and state['kid']==kid and not state['revoked'] and state['tier'] in KEY_TIERS,
                what+' names no account (the current key of a key-tier name)')
        return name

    def owner_action(self,i,e,q):
        """§5.3 report/owner_action, and under SUP-1 the owner action market of §20.4."""
        sup='SUP-1' in self.profiles
        if q['action']=='quote': require(q['result_hash'] is None and q['quote_index'] is None,'quote shape')
        if sup:
            require(q['asset_hash']==sup_asset_hash(e['origin']),'asset_hash is not the SUP asset of this origin')
            post=self.leaf_index.get(q['request_hash'])
            require(post is not None and self.entries[post]['type']=='post','owner action names no earlier request post')
            self.account(self.entries[post]['actor_kid'],'request post')  # the requester holds an account
            request=self.requests.setdefault(q['request_hash'],dict(post=post,quotes=[],completion=None))
            require(request['completion'] is None,'owner action on a completed request')
        if q['action']=='complete':
            quote=self.owner_actions.get(q['quote_index'])
            require(quote is not None and quote['action']=='quote' and quote['request_hash']==q['request_hash'],'completion names no quote of its request')
            require(q['result_hash'] is not None,'completion without result')
            if sup:
                require(q['quote_index']==request['quotes'][-1],'completion names an earlier quote (stale_quote)')
                require(q['amount']==quote['amount'],'completion amount differs from its quote')
                request['completion']=i
        elif sup: request['quotes'].append(i)
        self.owner_actions[i]=dict(q,requester=self.kid_name.get(self.entries[post]['actor_kid']) if sup else None)

    def sup(self,i,e,q,kid,ts):
        """§§20.2-20.7 in index order: asset, tasks and awards, contributions, spends and balances."""
        typ=e['type']
        require(q['asset_hash']==sup_asset_hash(e['origin']),'asset_hash is not the SUP asset of this origin')
        if typ=='sup.task':
            require(q['reward']>=1 and 1<=q['max_awards']<=1000 and ts<q['closes']<=ts+31622400,'task constraints')
            self.tasks[i]=dict(q,awards=[],names=set())
        elif typ=='sup.credit' and q['source']=='task':
            task=self.tasks.get(q['task_index']); require(task is not None,'award names no earlier task')
            require(q['task_index']<q['submission_index']<i and self.entries[q['submission_index']]['type']=='post','award names no later public post as the submission')
            name=self.kid_name.get(self.entries[q['submission_index']]['actor_kid'])
            require(self.account(q['account_kid'],'award')==name,'award to another account than the submitting name')
            require(q['amount']==task['reward'],'award amount differs from the reward')
            require(ts<task['closes'] and len(task['awards'])<task['max_awards'],'award of a closed task')
            require(q['submission_index'] not in self.awarded and name not in task['names'],'submission or name already awarded')
            task['awards'].append(i); task['names'].add(name); self.awarded.add(q['submission_index'])
            self.balances[name]=self.balances.get(name,0)+q['amount']
        elif typ=='sup.credit':
            require(q['contribution_hash'] not in self.contributions,'contribution credited twice')
            self.contributions.add(q['contribution_hash']); name=self.account(q['account_kid'],'contribution credit')
            self.balances[name]=self.balances.get(name,0)+q['amount']
        else:
            name=self.account(kid,'spend')
            require(1<=q['amount']<=self.balances.get(name,0),'spend above the balance (insufficient_balance)')
            if q['purpose']=='owner_action':
                done=self.owner_actions.get(q['ref_index'])
                require(done is not None and done['action']=='complete','owner-action spend names no completion')
                require(done['requester']==name,'owner action paid by another name than the requester')
                require(q['amount']==done['amount'] and q['bytes']==0,'owner-action spend amount')
                require(q['ref_index'] not in self.paid,'completion paid twice'); self.paid.add(q['ref_index'])
            elif q['purpose']=='hosting': require(q['ref_index'] is None and q['bytes']==0,'hosting spend shape')
            else: require(q['ref_index'] is None and q['bytes']>=1,'storage spend shape')
            self.balances[name]-=q['amount']


def receipt(raw, entry, policy):
    note=parse_note(raw); require(verify_note(note,[parse_vkey(policy.trust['log_vkey'])]),'receipt signature')
    r=strict_json(note.text)
    require(set(r)=={'origin','entry_hash','submitted_at','mmd_seconds'} and J(r)+b'\n'==note.text.encode(),'receipt canonical schema')
    require(r['origin']==policy.trust['origin'] and r['mmd_seconds']==60,'receipt origin/MMD')
    require(r['submitted_at']==entry['ts'] and r['entry_hash']==leaf_hash(J(entry)).hex(),'receipt fixed-entry commitment')
    return r


def bundle(b, policy, now, *, prefix):
    raw=DU(b['entry_bytes']); e=strict_json(raw); h=head(DU(b['checkpoint_note']),policy,now,historical=True)
    require(h.witness_policy_met,h.witness_error)  # §14.3 step 1: the bundle's checkpoint under the pinned witness policy
    require(b['envelope']==e['payload']['envelope'],'bundle envelope mismatch')
    require(verify_leaf_inclusion(raw,b['index'],h.cp.size,[DB(x) for x in b['inclusion_proof']],h.cp.root),'bundle inclusion')
    require(len(prefix)==h.cp.size and MerkleTree(prefix).root()==h.cp.root,'incomplete or unauthenticated prefix')
    require(prefix[b['index']]==raw,'bundle differs from complete prefix'); hist=History(prefix,policy)
    if b['body_or_ct'] is not None:
        body=DU(b['body_or_ct']); q=e['payload']
        require(H(body)==q.get('body_hash',q.get('ct_hash',q.get('document_hash'))) and len(body)==q['size'],'body commitment')
    return hist,e


#: AICS-1 §14.3: a complete verification package has exactly these members (§2: no others).
PACKAGE_MEMBERS=('bundle','trust_bundle','policy_cards','entry_prefix','checkpoint_notes')


def offline_package(package,policy,now):
    """Historical verification of an AICS-1 §14.3 package from saved bytes and the independent pins; no I/O.

    The package is exactly {bundle,trust_bundle,policy_cards:[U64],entry_prefix:[U64],checkpoint_notes:[U64]}.
    Its trust bundle must equal the pinned one, and the witness policy is the pinned one: a package never supplies
    trust.  Every saved checkpoint note must be log-signed and agree with the authenticated prefix."""
    require(isinstance(package,dict) and set(package)==set(PACKAGE_MEMBERS),'verification package must have exactly '+', '.join(PACKAGE_MEMBERS)+' (AICS-1 §14.3)')
    require(package['trust_bundle']==policy.trust,'package trust differs from independent pins')
    for k in ('policy_cards','entry_prefix','checkpoint_notes'): require(isinstance(package[k],list),'package '+k+' must be an array')
    prefix=[DU(x) for x in package['entry_prefix']]
    hist,entry=bundle(package['bundle'],policy,now,prefix=prefix)
    tree=MerkleTree(prefix)
    for note in package['checkpoint_notes']:
        h=head(DU(note),policy,now,historical=True)
        require(h.cp.size<=len(prefix),'incomplete: saved checkpoint is beyond the package prefix')
        require(tree.root(h.cp.size)==h.cp.root,'split-proven: saved checkpoint conflicts with the authenticated package prefix')
    require(bool(package['policy_cards']),'incomplete: missing policy cards')
    for raw in package['policy_cards']:
        card_bytes=DU(raw); card=strict_json(card_bytes); require(J(card)==card_bytes,'noncanonical saved card')
        require(any(e['type']=='policy' and e['payload']['document_hash']==H(card_bytes) for e in hist.entries),'saved card not logged in prefix')
        require(bool(card['signatures']),'unsigned saved card')
        unsigned={k:v for k,v in card.items() if k!='signatures'}
        for sig in card['signatures']:
            header=strict_json(DU(sig['protected']))
            require(header==dict(alg='EdDSA',kid=policy.trust['policy_kid'],typ='JOSE') and J(header)==DU(sig['protected']),'saved card header')
            keys.parse_did_key(policy.trust['policy_kid']).verify(DU(sig['signature']),(sig['protected']+'.'+U(J(unsigned))).encode())
    return hist,entry
