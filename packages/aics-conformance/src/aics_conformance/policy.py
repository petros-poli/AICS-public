"""Operator pins; never initialized from the server under examination."""
import re
from dataclasses import dataclass, field
from pathlib import Path
import tomllib
from aics_identity import keys
from aics_tlog import parse_vkey
from .protocol import strict_json
from .schema import check_profiles

#: AICS-1 §6.4: the trust bundle is exactly {v:1,origin,log_vkey,policy_kid,owner_kid,bootstrap_card_hash}.
TRUST_MEMBERS=('v','origin','log_vkey','policy_kid','owner_kid','bootstrap_card_hash')


def check_trust_bundle(trust):
    """Refuse (ValueError) anything but an AICS-1 trust bundle: exactly the six §6.4 members (§2: unknown members are
    rejected), ``v`` the integer 1, an origin without scheme or trailing slash (§2), an Ed25519 signed-note log key,
    did:key policy and owner keys, the three distinct (§3.1), and a lowercase 64-hex card hash (§2 ``hash``)."""
    if not isinstance(trust,dict): raise ValueError('trust bundle must be a JSON object')
    for k in TRUST_MEMBERS:
        if k not in trust: raise ValueError(f'missing out-of-band {k}')
    unknown=sorted(str(k) for k in set(trust)-set(TRUST_MEMBERS))
    if unknown: raise ValueError('unknown trust bundle members (AICS-1 §2): '+', '.join(unknown))
    if type(trust['v']) is not int or trust['v']!=1: raise ValueError('unsupported trust bundle version: v must be 1')
    origin=trust['origin']
    if not isinstance(origin,str) or not origin or len(origin)>255 or any(not 0x21<=ord(c)<=0x7e or c=='+' for c in origin):
        raise ValueError("origin must be printable ASCII without spaces or '+'")
    if '://' in origin or origin.endswith('/'): raise ValueError('origin must have no scheme and no trailing slash (AICS-1 §2)')
    if not isinstance(trust['log_vkey'],str): raise ValueError('log_vkey must be a string')
    log=parse_vkey(trust['log_vkey'])
    if log.key_type!=1: raise ValueError('log_vkey must be an Ed25519 signed-note key (type 0x01)')
    service=[log.public_key]
    for k in ('policy_kid','owner_kid'):
        if not isinstance(trust[k],str) or not trust[k].startswith('did:key:z'): raise ValueError(f'{k} must be an Ed25519 did:key')
        service.append(keys.public_key_bytes(keys.parse_did_key(trust[k])))
    if len(set(service))!=3: raise ValueError('log, policy and owner keys must be distinct (AICS-1 §3.1)')
    h=trust['bootstrap_card_hash']
    if not isinstance(h,str) or re.fullmatch('[0-9a-f]{64}',h) is None: raise ValueError('bootstrap_card_hash must be 64 lowercase hex characters')


@dataclass
class Policy:
    trust: dict
    pages: str | None = None
    mirrors: list[str] = field(default_factory=list)
    witness_vkeys: list[str] = field(default_factory=list)
    quorum: int = 0
    max_checkpoint_age: int = 300
    max_scan_entries: int = 100000
    poll_seconds: float = 1
    receipt_wait_seconds: float = 95
    secret_sample: str = 'ghp_'+'A'*36
    secret_pattern_id: str = 'github_pat'
    tombstone_index: int | None = None
    saved_checkpoint: bytes | None = None
    saved_card: dict | None = None
    max_rate_attempts: int = 1000
    restart_command: list[str] | None = None
    gate_plain: str | None = None
    #: The negotiated profiles the pinned card activates (AICS-1 §§19-20), e.g. ["SUP-1"] for an AICS-1+SUP-1 card:
    #: the card must name exactly these, and entries of no listed profile are refused (§20: a base-only client
    #: reports an unsupported profile instead of reading its entries as harmless).
    profiles: list[str] = field(default_factory=list)
    def __post_init__(self):
        check_trust_bundle(self.trust)
        self.profiles=list(check_profiles(self.profiles))
        if self.quorum<0 or self.quorum>len(self.witness_vkeys): raise ValueError('invalid witness quorum')
        ks=[parse_vkey(k) for k in self.witness_vkeys]
        if len({k.public_key for k in ks})!=len(ks) or len({k.name for k in ks})!=len(ks): raise ValueError('duplicate witness')
        if any(k.key_type!=4 for k in ks): raise ValueError('witness requires type 04')
        if self.max_checkpoint_age<60 or self.max_scan_entries<1 or self.poll_seconds<=0: raise ValueError('invalid policy bound')

    @classmethod
    def load(cls, path):
        path=Path(path); data=tomllib.loads(path.read_text()); base=path.parent
        trust=strict_json((base/data.pop('trust_file')).read_bytes())
        for k in ('saved_checkpoint','saved_card'):
            if data.get(k):
                raw=(base/data[k]).read_bytes(); data[k]=strict_json(raw) if k=='saved_card' else raw
        return cls(trust=trust,**data)
