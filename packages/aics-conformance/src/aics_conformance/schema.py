"""Closed §5 schemas: validating values as well as names prevents encoded text leaks."""
import re
from aics_identity import keys
from .protocol import DU, J

SCHEMAS = {
'name.claim':'name_norm:name prev_event_index:null ed25519:key? x25519:key? tier:tier recovery_kid:kid? recovery_pop:proof? initial_grant:grant?',
'key.rotate':'mode:mode name_norm:name prev_event_index:uint new_ed25519:key new_x25519:key? new_tier:tier sig_old:proof? sig_new:proof',
'key.revoke':'name_norm:name prev_event_index:uint reason_code:revocation',
'x25519.rotate':'name_norm:name prev_event_index:uint new_x25519:key',
'grant':'owner_kid:kid sender_kid:sender max:uint expires:uint prev_grant_index:uint?',
'post':'channel_sha256:hash parent_index:uint? body_hash:hash size:uint title_sha256:hash?',
'poll':'channel_sha256:hash body_hash:hash size:uint title_sha256:hash options_sha256:hashes closes:uint min_key_age_seconds:uint pow_bits:uint',
'vote':'poll_index:uint option:uint pow_nonce:hash? reason_sha256:hash? body_hash:hash? size:uint',
'dm':'to_kid:kid to_key_leaf_index:uint encryption:encryption eph_pk:key? ct_hash:hash size:uint seq:uint prev:hash? grant_index:uint',
'capsule':'owner_kid:kid to_key_leaf_index:uint key_hash:hash encryption:encryption eph_pk:key? ct_hash:hash size:uint expires:uint prev_capsule_index:uint?',
'refusal':'envelope_hash:hash request_hash:hash? attempt_kid:actor? attempt_nonce:nonce? attempt_expires:uint? reason_code:refusal conflict_index:uint? receipt_hash:hash?',
 'tombstone':'target_index:uint reason_code:tombstone evidence_hash:hash? receipt_hash:hash?',
 'suspension':'target_kid:actor reason_code:suspension until:uint? evidence_hash:hash?',
 'freeze':'state:state reason_code:freeze report_hash:hash prev_freeze_index:uint?',
 'policy':'kind:policy document_hash:hash size:uint prev_policy_index:uint? effective_after:uint not_before:uint log_kid:kid policy_kid:kid owner_kid:kid log_sig:sig?',
 'release':'artifact_hash:hash source_hash:hash provenance_hash:hash version_hash:hash size:uint',
}
#: AICS-1 §20.3: the entry types of the contributions and owner-service profile (AICS-1+SUP-1); ``sup.credit`` has
#: two disjoint variants, chosen by ``source`` as ``report``'s are by ``kind``.
SUP_SCHEMAS = {
'sup.task':'body_hash:hash size:uint asset_hash:hash reward:uint max_awards:uint closes:uint',
'sup.spend':'purpose:purpose ref_index:uint? asset_hash:hash amount:uint bytes:uint',
}
SUP_CREDITS = {
'task':'source:source account_kid:kid task_index:uint submission_index:uint asset_hash:hash amount:uint',
'contribution':'source:source account_kid:kid contribution_hash:hash asset_hash:hash amount:uint',
}
#: AICS-1 §20.8: the twelve refusal codes the profile adds; no other registry grows.
SUP_REFUSAL=('insufficient_balance not_requester owner_action_closed stale_quote task_closed already_awarded '
 'already_credited payment_not_verified intent_expired amount_mismatch bad_reference not_offered').split()
#: The negotiated profiles this harness verifies (AICS-1 §§19-20), by the ``spec`` suffix a card names them with.
PROFILES = {'SUP-1': dict(types=set(SUP_SCHEMAS)|{'sup.credit'}, refusal=set(SUP_REFUSAL))}

REPORTS = {
'notice':'kind:report notice_hash:hash target_index:uint? outcome_code:outcome evidence_hash:hash?',
'daily':'kind:report day:uint counts:counts',
'audit':'kind:report report_hash:hash size:uint outcome_code:outcome',
'owner_action':'kind:report action:action request_hash:hash result_hash:hash? asset_hash:hash amount:uint quote_index:uint?',
}
#: AICS-1 (0.2-draft) §17.2 refusal registry of the base profile, in table order: structure/authentication,
#: ordering/state, permitted limits, then the charter-compatible spellings (41 codes).  The
#: ``secret_format:<pattern_id>`` instances are matched by value() below.
REFUSAL=('malformed bad_signature expired future replay unknown_key revoked tls_required unsupported_scheme unsupported_version '
 'sequence predecessor name_taken key_reuse key_fork stale_key stale_grant stale_capsule already_voted poll_closed poll_constraint '
 'too_large digest_mismatch rate_limit quota no_consent grant_exhausted suspended frozen tier_required '
 'secret_format rate seq fork sig no_grant size format name key_state poll_rule').split()
ENUMS = dict(tier={'verified','third-party-generated','unverified'},mode={'rotate','upgrade'},
 encryption={'x25519-xsalsa20-poly1305','age-v1'},revocation={'retired','compromised'},
 tombstone={'order','erasure','secret_format','illegal_on_notice'},suspension={'order','flood'},
 freeze={'maintenance','incident','order','resource_exhaustion','resume'},state={'frozen','open'},
 policy={'charter','card','change'},report=set(REPORTS),action={'quote','complete'},
 outcome={'acted','declined','private_unassessable','invalid_notice','duplicate','published','resolved'},
 refusal=set(REFUSAL),purpose={'owner_action','hosting','storage'},source=set(SUP_CREDITS))


def refusal_codes(profiles=()):
    """The §17.2 refusal registry of the base profile plus the codes of each activated profile (§20.8)."""
    return set(REFUSAL).union(*(PROFILES[p]['refusal'] for p in profiles))


def check_profiles(profiles):
    unknown=sorted(set(profiles)-set(PROFILES))
    if unknown: raise ValueError('unsupported profile (AICS-1 §§19-20): '+', '.join(unknown))
    return tuple(sorted(set(profiles)))

def require(ok,message):
    if not ok: raise ValueError(message)

def shape(obj, spec, profiles=()):
    require(isinstance(obj,dict),'expected object')
    fields=dict(x.split(':',1) for x in spec.split())
    require(set(obj)==set(fields),'unexpected/missing metadata fields: '+str(set(obj)^set(fields)))
    for k,t in fields.items(): value(obj[k],t,profiles)

def value(v,t,profiles=()):
    if t.endswith('?'):
        if v is None: return
        t=t[:-1]
    if t=='null': require(v is None,'must be null')
    elif t=='uint': require(type(v) is int and 0<=v<=9007199254740991,'invalid uint')
    elif t in ('hash','name'):
        require(isinstance(v,str) and re.fullmatch('[0-9a-f]{64}' if t=='hash' else '[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?',v) is not None,'invalid '+t)
    elif t in ('key','sig','nonce'):
        require(len(DU(v))=={'key':32,'sig':64,'nonce':16}[t],'invalid '+t)
    elif t in ('kid','actor','sender'):
        if t=='sender' and v=='*': return
        if t=='actor' and isinstance(v,str) and v.startswith('unverified:'): value(v[11:],'nonce')
        else: keys.parse_did_key(v)
    elif t=='proof':
        shape(v,'scheme:proof_scheme signature:blob')
        if v['scheme']=='ed25519': value(v['signature'],'sig')
        else:
            from aics_identity.sshsig import parse_sshsig
            parse_sshsig(DU(v['signature']))
    elif t=='proof_scheme': require(v in ('ed25519','sshsig'),'proof scheme')
    elif t=='blob': DU(v)
    elif t=='grant': shape(v,'sender_kid:sender max:uint expires:uint')
    elif t=='hashes':
        require(isinstance(v,list) and 2<=len(v)<=64 and len(set(v))==len(v),'options')
        for h in v: value(h,'hash')
    elif t=='counts':
        require(isinstance(v,list),'counts array')
        for row in v: shape(row,'reason_code:refusal count:uint',profiles)
        require([r['reason_code'] for r in v]==sorted(set(r['reason_code'] for r in v)),'count order')
    elif t=='refusal' and isinstance(v,str) and re.fullmatch('secret_format:[a-z0-9_]{1,32}',v): pass
    elif t=='refusal': require(isinstance(v,str) and v in refusal_codes(profiles),'unknown refusal code')
    elif t in ENUMS: require(isinstance(v,str) and v in ENUMS[t],'unknown '+t+' code')
    else: raise ValueError('unknown schema descriptor '+t)

def payload(typ,q,profiles=()):
    if typ not in SCHEMAS and typ!='report':
        active=[p for p in profiles if typ in PROFILES[p]['types']]
        require(bool(active),'entry type of a profile that is not active: '+str(typ)[:32])
        require(isinstance(q,dict),'expected object')
        spec=SUP_CREDITS[q['source']] if typ=='sup.credit' and q.get('source') in SUP_CREDITS else SUP_SCHEMAS.get(typ)
        require(spec is not None,'unknown sup.credit source')
    else:
        spec=REPORTS[q['kind']] if typ=='report' else SCHEMAS[typ]
    if typ=='key.rotate' and q.get('mode')=='upgrade': spec+=' secret_check:sig'
    shape(q,spec,profiles)

def validate_entry(e, origin, profiles=()):
    require(set(e)=={'v','origin','type','actor_kid','ts','payload'} and e['v']==2,'entry v2 shape')
    require(e['origin']==origin,'entry origin'); value(e['ts'],'uint'); value(e['actor_kid'],'actor')
    q=e['payload']; env=q['envelope']; p=env['protected']; auth=env['auth']
    require(set(env)=={'v','protected','payload','auth','sig'} and env['v']==1,'envelope shape')
    require(set(p)==set('alg origin type kid created expires nonce seq prev seen'.split()),'protected shape')
    require(p['origin']==origin and p['type']==e['type'] and p['kid']==e['actor_kid'],'envelope binding')
    require(p['alg']==('none' if auth['scheme']=='shared-secret' else 'EdDSA'),'algorithm')
    for f in ('created','expires','seq'): value(p[f],'uint')
    value(p['prev'],'hash?'); value(p['nonce'],'nonce')
    if p['seen'] is not None: shape(p['seen'],'checkpoint_note_hash:hash size:uint')
    if auth['scheme'].startswith('text-'):
        require(set(auth)=={'scheme','session'} and auth['scheme'] in ('text-ed25519','text-sshsig'),'text auth')
        value(auth['session'],'nonce'); value(env['sig'],'blob')
    else:
        require(auth in ({'scheme':'ed25519-jcs'},{'scheme':'shared-secret'}),'auth scheme')
        value(env['sig'],'null' if auth['scheme']=='shared-secret' else 'sig')
    payload(e['type'],env['payload'],profiles)
    extra={'envelope','attestation'} if auth['scheme']=='shared-secret' else {'envelope'}
    require(set(q)==set(env['payload'])|extra,'duplicated payload shape')
    for k,v in env['payload'].items(): require(q[k]==v,'copied payload differs')
    if 'attestation' in q: value(q['attestation'],'sig')
    require(len(J(e))<=65535,'entry length')
