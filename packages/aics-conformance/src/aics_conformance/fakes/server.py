import copy
import secrets
import time
from urllib.parse import urlsplit, parse_qs, unquote
from aics_identity import keys, http_signatures
from aics_tlog import MerkleTree, TileWriter, Note, sign_note, sign_checkpoint, Checkpoint, vkey_from_ed25519
from aics_tlog.tiles import tile_path, entry_bundle_path
from ..card import VERSION as CARD_VERSION, SPEC_VERSIONS
from ..client import Response
from ..dialogue import BANNER
from ..protocol import Agent, J, H, U, B, DU, envelope, strict_json, verify_signature
from ..policy import Policy
from ..schema import ENUMS

class FakeReader:
    def __init__(self, server, url): self.server=server; self.url=url
    def read_tile(self,level,index,width): return self.server.resources().get(tile_path(level,index,width))
    def read_entry_bundle(self,index,width): return self.server.resources().get(entry_bundle_path(index,width))

class FakeServer:
    """Faults change actual wire bytes/state, never check verdicts.

    Required toggles: rollback, split_view, swapped_key, dropped_receipt,
    plaintext_field_leak. Additional independent mutants cover every check.
    Fake time advances explicitly; no tests wait for the 60-second MMD.
    """
    def __init__(self, *faults):
        self.faults=set(faults); self.now=int(time.time()); self.origin='fake.example/tiles'
        self.log=keys.generate_keypair(); self.policy_actor=Agent(name='policy'); self.owner=Agent(name='owner')
        self.entries=[]; self.bodies={}; self.names={}; self.last={}; self.nonces={}; self.grants={}; self.used={}
        self.sessions={}; self.hidden={}; self.write_times={}; self.head_calls=0; self.after_restart=False
        from aics_tlog import format_vkey
        self.vkey=format_vkey(vkey_from_ed25519(self.origin,self.log.public_key()))
        self.trust=dict(v=1,origin=self.origin,log_vkey=self.vkey,policy_kid=self.policy_actor.kid,owner_kid=self.owner.kid,bootstrap_card_hash='0'*64)
        charter=J({'spec':'AICS-1','metadata':'permanent','containment':'no execution'})
        q=dict(kind='charter',document_hash=H(charter),size=len(charter),prev_policy_index=None,effective_after=0,not_before=self.now,
               log_kid=keys.did_key(self.log.public_key()),policy_kid=self.policy_actor.kid,owner_kid=self.owner.kid)
        q['log_sig']=U(self.log.sign(b'AICS-1 policy\n'+J(q)))
        self.admin('policy',q,charter)
        self.card=self.make_card(); cb=J(self.card); self.trust['bootstrap_card_hash']=H(cb)
        self.admin('policy',dict(kind='card',document_hash=H(cb),size=len(cb),prev_policy_index=0,effective_after=1,
            not_before=self.now,log_kid=q['log_kid'],policy_kid=q['policy_kid'],owner_kid=q['owner_kid'],log_sig=None),cb)
        a=Agent(); self.fixture_agent=a
        self.accept(envelope(a,self.origin,'name.claim',a.claim(),self.now)); a.previous=self.entries[-1]['payload']['envelope']
        body=J(dict(channel='conformance',title=None,text='synthetic fixture'))
        post=dict(channel_sha256=H(b'conformance'),parent_index=None,body_hash=H(body),size=len(body),title_sha256=None)
        self.accept(envelope(a,self.origin,'post',post,self.now),body)
        self.admin('tombstone',dict(target_index=3,reason_code='erasure',evidence_hash=None,receipt_hash=None))
        self.hidden[3]=4; self.bodies.pop(H(body),None)
        if 'plaintext_field_leak' in self.faults:
            self.entries[3]['payload']['text']='LEAKED PLAINTEXT'
        if 'authorship' in self.faults:
            self.entries[3]['payload']['envelope']['sig']=U(bytes(64))

    def make_card(self):
        c=dict(spec='AICS-1',version=CARD_VERSION,origin=self.origin,issued_at=self.now,expires=self.now+86400,policy_parent_index=0,
            log_vkey=self.vkey,policy_kid=self.policy_actor.kid,owner_kid=self.owner.kid,tile_prefixes=['https://fake/tiles'],api_base='https://fake',
            gate=dict(tls_host='fake',tls_port=7700,plaintext_port=7701,https_url='https://fake/t'),
            proxy=[dict(host='fake',mode='dns-only',tls_termination='origin')],witness_policy=dict(quorum=0,witnesses=[]),
            max_checkpoint_age=300,mmd_seconds=60,policy_notice_seconds=0,
            limits=dict(public_body_bytes=32768,ciphertext_bytes=65536,envelope_window_seconds=300,future_skew_seconds=30,session_idle_seconds=900,
                writes=dict(count=20,interval_seconds=60),registrations=dict(count=20,interval_seconds=60),preidentity=dict(count=1000,interval_seconds=60),flood_suspension_seconds=60),
            retention=dict(dm_seconds=7776000,capsule_max_seconds=31536000,ciphertext_budget_bytes=1000000,eviction='oldest-ts-index'),
            schemes=['x25519-xsalsa20-poly1305'],tiers=['verified','third-party-generated','unverified'],
            # §13.1: the §17.2 registries plus the active secret_format:<id> instance of the one published pattern
            reason_codes={k:list(sorted(ENUMS[k]))+(['secret_format:github_pat'] if k=='refusal' else []) for k in ('refusal','tombstone','suspension','freeze','revocation','outcome')},
            secret_patterns=[dict(id='github_pat',pattern_hash=H(b'ghp_[A-Za-z0-9]{36}'))],
            policies=dict(charter_hash=self.entries[0]['payload']['document_hash'],terms_hash=H(b'terms'),privacy_hash=H(b'privacy')),
            assurances=[dict(id=f'G{i}',status='promised',claim='fixture',assumptions=['local clock'],evidence=[]) for i in range(1,11)]+[
                dict(id=f'N{i}',status='not-offered',claim='excluded',assumptions=[],evidence=[]) for i in range(1,6)],
            spec_versions=dict(SPEC_VERSIONS))
        if 'runtime_claim' in self.faults: c['assurances'][6]['status']='proven'
        protected=U(J(dict(alg='EdDSA',kid=self.policy_actor.kid,typ='JOSE')))
        c['signatures']=[dict(protected=protected,signature=U(self.policy_actor.key.sign((protected+'.'+U(J(c))).encode()))) ]
        return c

    def configuration(self):
        return Policy(copy.deepcopy(self.trust),mirrors=['https://mirror/tiles'],tombstone_index=4,
                      saved_checkpoint=self.checkpoint(),receipt_wait_seconds=95,poll_seconds=1)
    def tile_reader(self,url): return FakeReader(self,url)
    def sleep(self,seconds): self.now+=seconds
    def restart(self): self.after_restart=True
    def resources(self): return TileWriter([J(e) for e in self.entries]).materialise()
    def checkpoint(self, mirror=False):
        self.head_calls+=1; raw=[J(e) for e in self.entries]
        if ('rollback' in self.faults and self.head_calls>2) or ('restart_rollback' in self.faults and self.after_restart): raw=raw[:2]
        tree=MerkleTree(raw); root=tree.root()
        if 'split_view' in self.faults and mirror: root=bytes(32)
        note=sign_checkpoint(Checkpoint(self.origin,len(raw),root),self.log,self.origin).to_bytes()
        if 'bad_checkpoint' in self.faults: note=note.replace(b'\n'+str(len(raw)).encode()+b'\n',b'\n999\n',1)
        return note
    def receipt(self,e):
        text=J(dict(origin=self.origin,entry_hash=__import__('aics_tlog').leaf_hash(J(e)).hex(),submitted_at=e['ts'],mmd_seconds=60)).decode()+'\n'
        if 'bad_receipt' in self.faults: text=text.replace('"mmd_seconds":60','"mmd_seconds":61')
        return Note(text,(sign_note(text,self.log,self.origin),)).to_bytes()
    def append(self,e,body=None):
        i=len(self.entries); self.entries.append(e); env=e['payload']['envelope']; p=env['protected']; q=env['payload']
        self.last[p['kid']]=env; self.nonces[p['kid'],p['nonce']]=(p['expires'],i)
        if body is not None: self.bodies[H(body)]=body
        return i
    def admin(self,typ,q,body=None):
        self.policy_actor.previous=self.last.get(self.policy_actor.kid)
        return self.accept(envelope(self.policy_actor,self.origin,typ,q,int(self.now)),body)
    def accept(self,env,body=None):
        p=env['protected']; q=env['payload']; typ=p['type']; kid=p['kid']; i=len(self.entries)
        e=dict(v=2,origin=self.origin,type=typ,actor_kid=kid,ts=int(self.now),payload=dict(envelope=copy.deepcopy(env),**copy.deepcopy(q)))
        self.append(e,body)
        if typ=='name.claim': self.names[q['name_norm']]=dict(kid=kid,x=q['x25519'],event=i,key_index=i,revoked=False)
        elif typ in ('key.rotate','key.revoke','x25519.rotate'):
            s=self.names[q['name_norm']]; s['event']=i
            if typ=='key.rotate': s.update(kid=keys.did_key(keys.public_key_from_bytes(DU(q['new_ed25519']))),x=q['new_x25519'] or s['x'],key_index=i if q['new_x25519'] else s['key_index'])
            elif typ=='key.revoke': s['revoked']=True
            else: s.update(x=q['new_x25519'],key_index=i)
        elif typ=='grant': self.grants[kid,q['sender_kid']]=dict(q,index=i)
        elif typ=='dm': self.used[q['grant_index']]=self.used.get(q['grant_index'],0)+1
        return e
    def refuse(self,env,reason,*,authenticated=True,conflict=None,body=None):
        if 'missing_refusal' in self.faults: return Response(403,J({'error':reason}),{})
        p=env['protected']; q=dict(envelope_hash=H(J(env)),request_hash=None,attempt_kid=p['kid'] if authenticated else None,
            attempt_nonce=p['nonce'] if authenticated else None,attempt_expires=p['expires'] if authenticated else None,
            reason_code=reason,conflict_index=conflict,receipt_hash=None)
        if reason=='replay' and conflict is not None: q['receipt_hash']=H(self.receipt(self.entries[conflict]))
        e=self.admin('refusal',q)
        if 'retain_secret' in self.faults and body: self.bodies[H(body)]=body
        return Response(403,J(dict(entry=e,receipt_note=U(self.receipt(e)))),{})

    def submit(self,env,body,headers,url,*,gate=False,content=None):
        """Accept or refuse one write.  For POST /v2/entries (``gate`` false) Content-Digest is verified over the
        HTTP content exactly as received (AICS-1 §12.1), never over a re-serialization of the parsed JSON:
        ``content``, or the bytes ``request`` is serving (so that a subclass overriding ``submit`` without this
        keyword keeps the check).  Text-gate writes carry no RFC 9421 signature (§12.1)."""
        if not gate:
            content=content if content is not None else getattr(self,'http_content',None)
            if not isinstance(content,(bytes,bytearray)):
                raise TypeError('FakeServer.submit needs the HTTP request bytes as received: content= (AICS-1 §12.1)')
        p=env['protected']; q=env['payload']; kid=p['kid']; typ=p['type']
        def no(code,**kw): return self.refuse(env,code,body=body,**kw)
        try: verify_signature(env)
        except Exception:
            if 'accept_bad_signature' not in self.faults: return no('bad_signature',authenticated=False)
        if not gate:
            try:
                verified=http_signatures.verify_request('POST',url,headers,bytes(content),
                    resolve_key=keys.parse_did_key,required_components=http_signatures.AICS_COMPONENTS,require_content_digest_covered=True,
                    require_tag='aics',require_nonce=True,now=int(self.now),max_age=None,max_lifetime=None,max_clock_skew=100000)
                if 'http_binding' not in self.faults:
                    assert len(verified)==1
                    v=verified[0]
                    assert (v.label,v.keyid,v.nonce,v.created,v.expires,v.components)==('aics',kid,p['nonce'],p['created'],p['expires'],tuple(http_signatures.AICS_COMPONENTS))
            except Exception:
                if 'bearer' not in self.faults: return no('bad_signature',authenticated=False)
        if p['created']<self.now-300 or p['expires']<=self.now:
            if 'accept_stale' not in self.faults: return no('expired')
        if (kid,p['nonce']) in self.nonces and self.nonces[kid,p['nonce']][0]>self.now:
            if 'accept_replay' not in self.faults: return no('replay',conflict=self.nonces[kid,p['nonce']][1])
        if typ=='name.claim':
            if q['name_norm'] in self.names:
                s=self.names[q['name_norm']]
                if not (s['revoked'] and 'revocation' in self.faults): return no('revoked' if s['revoked'] else 'name_taken',conflict=s['event'])
        elif typ in ('key.rotate','key.revoke','x25519.rotate'):
            s=self.names[q['name_norm']]
            if s['revoked'] and 'revocation' not in self.faults: return no('revoked')
            if s['event']!=q['prev_event_index'] and 'key_fork' not in self.faults: return no('key_fork',conflict=s['event'])
            if typ=='key.rotate' and 'one_signature' not in self.faults:
                try:
                    r={k:v for k,v in q.items() if k not in ('sig_old','sig_new')}|{'origin':self.origin}; data=b'AICS-1 key.rotate\n'+J(r)
                    keys.parse_did_key(kid).verify(DU(q['sig_old']['signature']),data)
                    keys.public_key_from_bytes(DU(q['new_ed25519'])).verify(DU(q['sig_new']['signature']),data)
                except Exception: return no('bad_signature')
            if typ=='x25519.rotate' and 'xrotate' in self.faults: return no('stale_key',conflict=s['event'])
        if typ=='report' and q['kind']=='owner_action' and kid!=self.owner.kid and 'owner' not in self.faults: return no('unknown_key')
        if typ in ('dm','capsule'):
            if q['encryption']!='x25519-xsalsa20-poly1305' and 'cleartext' not in self.faults: return no('unsupported_scheme')
            # §5.3, §13.1: a capsule expires between ts+7776000 (90 days) and ts+capsule_max_seconds
            if typ=='capsule' and not self.now+7776000<=q['expires']<=self.now+self.card['retention']['capsule_max_seconds']: return no('malformed')
            if typ=='dm':
                g=self.grants.get((q['to_kid'],kid),self.grants.get((q['to_kid'],'*')))
                if g and g['max']==0 and 'exact_revocation' in self.faults: g=self.grants.get((q['to_kid'],'*'))
                if not g and 'open_inbox' not in self.faults: return no('no_consent')
                if g and 'wildcard_capacity' not in self.faults and self.used.get(g['index'],0)>=g['max']: return no('grant_exhausted')
        if typ=='post' and body and b'ghp_' in body and 'secret_scan' not in self.faults: return no('secret_format:github_pat')
        times=[t for t in self.write_times.get(kid,[]) if t>self.now-60]
        if len(times)>=self.card['limits']['writes']['count'] and 'rate_limit' not in self.faults: return no('rate_limit')
        self.write_times[kid]=times+[self.now]
        if 'silence' in self.faults and len(times)>=20: raise TimeoutError('simulated silence')
        e=self.accept(env,body)
        if 'dropped_receipt' in self.faults and typ=='post': self.entries.pop()
        return Response(202,J(dict(entry=e,receipt_note=U(self.receipt(e)))),{})

    def bundle(self,i):
        e=self.entries[i]; q=e['payload']; tree=MerkleTree([J(e) for e in self.entries]); digest=q.get('body_hash',q.get('ct_hash',q.get('document_hash')))
        body=self.bodies.get(digest)
        b=dict(entry_bytes=U(J(e)),index=i,inclusion_proof=[B(h) for h in tree.inclusion_proof(i)],checkpoint_note=U(self.checkpoint()),envelope=e['payload']['envelope'],body_or_ct=None if body is None else U(body))
        if 'bad_bundle' in self.faults: b['inclusion_proof']=[B(bytes(32))]
        return b
    def request(self,method,url,body=None,headers=None):
        from .. import adapter
        p=urlsplit(url); path=unquote(p.path); query=parse_qs(p.query,keep_blank_values=True)
        def response(obj,status=200): return Response(status,J(obj),{})
        if path.endswith('/checkpoint'): return Response(200,self.checkpoint(p.hostname=='mirror'),{})
        if '/tile/' in path:
            data=self.resources().get(path[path.index('/tile/')+1:]); return Response(200 if data is not None else 404,data or b'',{})
        if path=='/t':
            from .gate import exchange
            return Response(200,exchange(self,method,body or b'',query).encode(),{})
        if path=='/llms.txt': return Response(200,BANNER.encode(),{})
        if path=='/' and query.get('format')==['json']: return response({'banner':BANNER+'bad' if 'banner' in self.faults else BANNER})
        if path==adapter.path('card'):
            c=copy.deepcopy(self.card)
            if 'bad_card' in self.faults: c['mmd_seconds']=61
            return response(c)
        if path in set(sum(adapter.LEGACY_PROBES.values(),[])):
            if 'keygen' in self.faults: return response({'private_seed_hex':'00'*32})
            if 'bearer' in self.faults: return response({'access_token':'aics_live_test'})
            return response({'error':'removed'},404)
        if path==adapter.path('openapi'): return response({'paths':{adapter.path('submit'):{}},'components':{'securitySchemes':{}}})
        if path==adapter.path('submit') and method=='POST':
            obj=strict_json(body); self.http_content=body  # the binding digests these bytes (submit, AICS-1 §12.1)
            try: return self.submit(obj['envelope'],None if obj['body'] is None else DU(obj['body']),headers or {},url)
            finally: self.http_content=None
        if path.startswith('/v2/entries/'):
            i=int(path.rsplit('/',1)[1]); b=self.bundle(i)
            if 'tombstone_delete' in self.faults and i==3: return response({'error':'gone'},410)
            return response(b)
        if path.startswith('/v2/bodies/'):
            digest=path.rsplit('/',1)[1]
            if digest in self.bodies: return Response(200,self.bodies[digest],{})
            target=next((i for i,e in enumerate(self.entries) if e['payload'].get('body_hash')==digest),None)
            if target in self.hidden: return response(dict(status='hidden',tombstone_index=self.hidden[target],reason_code='erasure'),410)
            return response({'status':'absent'},404)
        if path.startswith('/v2/names/'):
            name=path.rsplit('/',1)[1]; s=self.names[name]
            ids=[i for i,e in enumerate(self.entries) if e['type'] in ('name.claim','key.rotate','key.revoke','x25519.rotate') and e['payload']['name_norm']==name]
            return response(dict(indices=ids,checkpoint_note=U(self.checkpoint()),x25519=U(bytes(32)) if 'swapped_key' in self.faults else s['x'],key_leaf_index=s['key_index']))
        if path.startswith('/v2/inbox/'):
            kid=path.split('/v2/inbox/',1)[1]; start=int(query.get('from',['0'])[0])
            ids=[i for i,e in enumerate(self.entries) if i>=start and e['type']=='dm' and e['payload']['to_kid']==kid]
            return response(dict(indices=[] if 'inbox_drop' in self.faults else ids,checkpoint_note=U(self.checkpoint())))
        if path.startswith('/v2/tlog/index/'):
            from aics_tlog import leaf_hash
            digest=path.rsplit('/',1)[1]
            for i,e in enumerate(self.entries):
                if leaf_hash(J(e)).hex()==digest: return response(dict(entry_hash=digest,index=i))
            return response({'error':'absent'},404)
        if path in ('/v2/tlog/inclusion','/v2/tlog/consistency'):
            tree=MerkleTree([J(e) for e in self.entries])
            if path.endswith('inclusion'):
                i=int(query['index'][0]); n=int(query['size'][0]); proof=tree.inclusion_proof(i,n); result=dict(index=i,size=n)
            else:
                m=int(query['from'][0]); n=int(query['to'][0]); proof=tree.consistency_proof(m,n); result={'from':m,'to':n}
            result['hashes']=[B(bytes(32))] if 'bad_proof' in self.faults else [B(h) for h in proof]
            return response(result)
        if path=='/notice': return response({'status':'received'},202)
        return response({'error':'not_found'},404)

    def tcp_gate(self,plain=False):
        from .gate import exchange
        server=self
        class Gate:
            session=None
            def exchange(self,line=None,**kwargs):
                data=(('session '+self.session+'\n') if self.session else '')+(line or '')+'\n'
                result=exchange(server,'POST',data.encode(),{},plain=plain and 'plain_secret' not in server.faults)
                if result.startswith('session '):
                    first,result=result.split('\n',1); self.session=first[8:]
                return result
            def close(self): pass
        return Gate()

    def context(self):
        from ..core import Context
        from ..client import JSONClient,Tiles
        return Context(JSONClient('https://fake',transport=self),Tiles('https://fake/tiles',transport=self),self.configuration(),clock=lambda:self.now,sleep=self.sleep,restart=self.restart)
