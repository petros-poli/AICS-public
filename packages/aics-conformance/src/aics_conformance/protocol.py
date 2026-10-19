"""Strict profile bytes and local-only cryptography."""
import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field
from aics_identity import canonicalize, keys, linesig
from aics_identity.envelope import envelope_signing_digest
from nacl.public import PrivateKey, PublicKey, SealedBox
from .adapter import VERBS

J = canonicalize

def H(b): return hashlib.sha256(b).hexdigest()
def U(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
def B(b): return base64.b64encode(b).decode('ascii')

def DU(s):
    if not isinstance(s, str): raise ValueError('base64url must be text')
    b = base64.b64decode(s + '=' * (-len(s) % 4), altchars=b'-_', validate=True)
    if U(b) != s: raise ValueError('noncanonical base64url')
    return b

def DB(s):
    b = base64.b64decode(s, validate=True)
    if B(b) != s or len(b) != 32: raise ValueError('noncanonical proof hash')
    return b

def strict_json(raw):
    def pairs(items):
        result = {}
        for k,v in items:
            if k in result: raise ValueError('duplicate JSON member')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

@dataclass
class Agent:
    name: str = field(default_factory=lambda: 'ct-' + secrets.token_hex(8))
    key: object = field(default_factory=keys.generate_keypair)
    encryption_key: object = field(default_factory=PrivateKey.generate)
    previous: dict | None = None
    claim_index: int | None = None
    event_index: int | None = None
    @property
    def kid(self): return keys.did_key(self.key.public_key())
    @property
    def ed(self): return U(self.key.public_key().public_bytes_raw())
    @property
    def x(self): return U(bytes(self.encryption_key.public_key))
    def claim(self):
        return dict(name_norm=self.name, prev_event_index=None, ed25519=self.ed, x25519=self.x,
                    tier='verified', recovery_kid=None, recovery_pop=None, initial_grant=None)

def envelope(agent, origin, typ, payload, now, *, nonce=None, seen=None, created=None):
    p = dict(alg='EdDSA', origin=origin, type=typ, kid=agent.kid,
             created=now if created is None else created, expires=(now if created is None else created)+300,
             nonce=nonce or U(secrets.token_bytes(16)), seq=0 if agent.previous is None else agent.previous['protected']['seq']+1,
             prev=None if agent.previous is None else H(J(agent.previous)), seen=seen)
    return dict(v=1, protected=p, payload=payload, auth={'scheme':'ed25519-jcs'},
                sig=U(agent.key.sign(envelope_signing_digest(p,payload))))

def command(unsigned):
    typ = unsigned['protected']['type']
    verb = next(v for v,t in VERBS.items() if t == typ)
    if typ == 'key.rotate' and unsigned['payload']['mode'] == 'upgrade': verb='claim-upgrade'
    if verb in ('claim','claim-upgrade'):
        return f"{verb} {unsigned['payload']['name_norm']} {H(J(unsigned))}"
    return verb + ' ' + U(J(unsigned))

def sign_text(unsigned, key):
    e = dict(unsigned)
    sig = linesig.sign_line(e['auth']['session'], command(unsigned), key)
    e['sig'] = U(keys.b64_decode_strict(sig))
    return e

def verify_signature(e):
    pub = keys.parse_did_key(e['protected']['kid'])
    if e['auth']['scheme'] == 'ed25519-jcs':
        pub.verify(DU(e['sig']), envelope_signing_digest(e['protected'], e['payload']))
    elif e['auth']['scheme'] in ('text-ed25519','text-sshsig'):
        u = {k:v for k,v in e.items() if k != 'sig'}
        if e['auth']['scheme']=='text-ed25519' and len(DU(e['sig'])) != 64: raise ValueError('not raw Ed25519')
        if e['auth']['scheme']=='text-sshsig' and not DU(e['sig']).startswith(b'SSHSIG'): raise ValueError('not SSHSIG')
        linesig.verify_line(e['auth']['session'], command(u), e['sig'], pub, leeway=False)
    else: raise ValueError('authorship unproven: shared-secret or unknown scheme')

def rotation(old, new, origin, *, predecessor=None):
    r = dict(origin=origin, name_norm=old.name, prev_event_index=old.event_index if predecessor is None else predecessor,
             new_ed25519=new.ed, new_x25519=new.x, new_tier='verified', mode='rotate')
    data = b'AICS-1 key.rotate\n'+J(r)
    return {k:v for k,v in r.items() if k!='origin'} | {
        'sig_old':{'scheme':'ed25519','signature':U(old.key.sign(data))},
        'sig_new':{'scheme':'ed25519','signature':U(new.key.sign(data))}}

def seal(content, recipient_key, sender_kid, recipient_kid, nonce):
    content.decode('utf-8')
    header = J(dict(from_kid=sender_kid,to_kid=recipient_kid,envelope_nonce=nonce))
    return SealedBox(PublicKey(recipient_key)).encrypt(struct.pack('>I',len(header))+header+content)

def open_message(e, ciphertext, private_key):
    """Recipient-side rejection before returning ANY plaintext, including rewraps."""
    verify_signature(e)
    q=e['payload']; p=e['protected']
    if q['encryption']!='x25519-xsalsa20-poly1305': raise ValueError('unsupported scheme')
    if H(ciphertext)!=q['ct_hash'] or len(ciphertext)!=q['size'] or U(ciphertext[:32])!=q['eph_pk']:
        raise ValueError('ciphertext commitment mismatch')
    raw=SealedBox(private_key).decrypt(ciphertext)
    if len(raw)<4: raise ValueError('missing inner header')
    n=int.from_bytes(raw[:4],'big')
    if n>4096 or len(raw)<4+n: raise ValueError('invalid inner framing')
    hb=raw[4:4+n]; h=strict_json(hb)
    expected=dict(from_kid=p['kid'],to_kid=q.get('to_kid',q.get('owner_kid')),envelope_nonce=p['nonce'])
    if h!=expected or J(h)!=hb: raise ValueError('inner-header binding mismatch')
    raw[4+n:].decode('utf-8')
    return raw[4+n:]
