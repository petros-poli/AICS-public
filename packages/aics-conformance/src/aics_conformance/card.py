"""Pinned JWS card, logged activation and prior-policy checks (§14.5)."""
import re
from aics_identity import keys
from .protocol import J,H,U,DU,strict_json
from .schema import require, ENUMS, refusal_codes
FIELDS=set('spec version origin issued_at expires policy_parent_index log_vkey policy_kid owner_kid tile_prefixes api_base gate proxy witness_policy max_checkpoint_age mmd_seconds policy_notice_seconds limits retention schemes tiers reason_codes secret_patterns policies assurances spec_versions signatures'.split())
#: AICS-1 (0.2-draft) §13.1: the card version, and the C2SP versions it pins (tlog-checkpoint, signed-note,
#: tlog-cosignature and tlog-witness v1.1.0).  Any other card version is refused, the 0.1-draft card included.
VERSION='0.2-draft'
SPEC_VERSIONS={'tlog-tiles':'1.0.0','tlog-checkpoint':'1.1.0','signed-note':'1.1.0','tlog-cosignature':'1.1.0','tlog-witness':'1.1.0','a2a-card':'1.0.0'}

#: AICS-1 §20.9: the members of an activated card's ``sup``.
SUP_FIELDS={'asset_hash','contributions','intent_seconds','claim_seconds','record_seconds','storage'}


def card_spec(profiles):
    """The ``spec`` of a card activating exactly ``profiles`` (AICS-1 §§13.1, 20.9): ``AICS-1``, ``AICS-1+SUP-1``."""
    return 'AICS-1'+''.join('+'+p for p in profiles)


def verify_sup(c):
    """AICS-1 §20.9: the ``sup`` member of an AICS-1+SUP-1 card."""
    from .verify import sup_asset_hash
    s=c['sup']
    require(isinstance(s,dict) and set(s)==SUP_FIELDS,'sup member schema (AICS-1 §20.9)')
    require(s['asset_hash']==sup_asset_hash(c['origin']),'sup asset_hash is not the SUP asset of the card origin')
    require(isinstance(s['contributions'],list),'sup contributions array')
    networks=[]
    for x in s['contributions']:
        require(isinstance(x,dict) and set(x)=={'network','asset','decimals','address','units_per_sup'},'contribution network schema')
        require(isinstance(x['network'],str) and re.fullmatch('[a-z0-9-]{1,32}',x['network']) is not None,'contribution network id')
        require(all(isinstance(x[k],str) and x[k] for k in ('asset','address')),'contribution asset and address')
        require(type(x['decimals']) is int and x['decimals']>=0 and type(x['units_per_sup']) is int and x['units_per_sup']>=2,'contribution units')
        networks.append(x['network'])
    require(len(set(networks))==len(networks),'each contribution network once')
    require(all(type(s[k]) is int and s[k]>=0 for k in ('intent_seconds','claim_seconds','record_seconds')),'sup windows are uint')
    require(0<s['intent_seconds']<=s['claim_seconds'] and s['record_seconds']<=31536000,'sup windows')
    st=s['storage']
    if st is not None:
        require(isinstance(st,dict) and set(st)=={'free_quota_bytes','unit_bytes','unit_amount'},'sup storage schema')
        require(type(st['free_quota_bytes']) is int and st['free_quota_bytes']>=65536,'free capsule quota below one maximal ciphertext')
        units=(st['unit_bytes'],st['unit_amount'])
        require((units[0] is None)==(units[1] is None) and all(v is None or type(v) is int and v>0 for v in units),'sup storage units')


def verify_card(ctx, card=None):
    c=card if card is not None else ctx.client.get('card',pages=True); ctx.evidence['policy_cards']=[U(J(c))]
    profiles=tuple(getattr(ctx.policy,'profiles',()) or ()); spec=card_spec(profiles)
    require(isinstance(c,dict) and c.get('spec')==spec,f"card profile {str(c.get('spec') if isinstance(c,dict) else None)[:40]!r} is not the pinned {spec!r} (a client reports an unsupported profile, AICS-1 §§19-20)")
    require(set(c)==FIELDS|({'sup'} if 'SUP-1' in profiles else set()),'card exact schema')
    require(c['version']==VERSION,f"card version must be {VERSION!r} (AICS-1 {VERSION} §13.1), not {str(c['version'])[:16]!r}")
    require(c['spec_versions']==SPEC_VERSIONS,f'spec versions: AICS-1 {VERSION} §13.1 pins {SPEC_VERSIONS}')
    for k in ('origin','log_vkey','policy_kid','owner_kid'): require(c[k]==ctx.policy.trust[k],'card replaced pinned '+k)
    require(type(c['issued_at']) is int and type(c['expires']) is int and c['issued_at']<=ctx.now()+30 and c['issued_at']<c['expires'] and ctx.now()<c['expires'],'card time validity')
    unsigned={k:v for k,v in c.items() if k!='signatures'}; require(bool(c['signatures']),'unsigned card')
    for sig in c['signatures']:
        require(set(sig)=={'protected','signature'},'card signature shape'); protected=strict_json(DU(sig['protected']))
        require(J(protected)==DU(sig['protected']) and protected==dict(alg='EdDSA',kid=ctx.policy.trust['policy_kid'],typ='JOSE'),'card protected header')
        keys.parse_did_key(ctx.policy.trust['policy_kid']).verify(DU(sig['signature']),(sig['protected']+'.'+U(J(unsigned))).encode())
    hist,h=ctx.scan(); events=[(i,e) for i,e in enumerate(hist.entries) if e['type']=='policy']; matching=[(i,e) for i,e in events if e['payload']['document_hash']==H(J(c))]
    require(len(matching)==1,'card lacks unique included policy event'); i,e=matching[0]; q=e['payload']
    require(q['kind']=='card' and q['prev_policy_index']==c['policy_parent_index'] and q['size']==len(J(c)),'card policy linkage')
    require(h.cp.size>max(i,q['effective_after']) and ctx.now()>=q['not_before'],'card not active')
    cards=[(j,x) for j,x in events if x['payload']['kind']=='card' and x['payload']['effective_after']<h.cp.size and x['payload']['not_before']<=ctx.now()]
    require(cards[-1][0]==i,'superseded card')
    if ctx.policy.saved_card is None: require(H(J(c))==ctx.policy.trust['bootstrap_card_hash'],'initial card differs from pinned bootstrap hash; supply saved card')
    elif H(J(ctx.policy.saved_card))!=H(J(c)):
        old=ctx.policy.saved_card; require(q['not_before']>=e['ts']+old['policy_notice_seconds'],'card changed without prior notice')
        require(any(j<i and x['payload']['document_hash']==H(J(old)) for j,x in events),'saved card missing from authenticated history')
    require(c['mmd_seconds']==60 and c['max_checkpoint_age']>=60,'card timing profile')
    wp=c['witness_policy']; require(set(wp)=={'quorum','witnesses'},'witness policy shape')
    from aics_tlog import parse_vkey
    wkeys=[parse_vkey(w['vkey']) for w in wp['witnesses']]
    require(ctx.policy.quorum<=wp['quorum']<=len(wkeys) and len({w.public_key for w in wkeys})==len(wkeys),'witness uniqueness/quorum')
    require(set(ctx.policy.witness_vkeys).issubset({w['vkey'] for w in wp['witnesses']}),'candidate removes pinned witnesses')
    limits=c['limits']; expected=dict(public_body_bytes=32768,ciphertext_bytes=65536,envelope_window_seconds=300,future_skew_seconds=30,session_idle_seconds=900)
    require(set(limits)==set(expected)|{'writes','registrations','preidentity','flood_suspension_seconds'},'limit schema')
    for k,v in expected.items(): require(limits[k]==v,'incorrect '+k)
    for k in ('writes','registrations','preidentity'): require(set(limits[k])=={'count','interval_seconds'} and all(type(x) is int and x>0 for x in limits[k].values()),'unbounded rate limits')
    require(set(c['retention'])=={'dm_seconds','capsule_max_seconds','ciphertext_budget_bytes','eviction'} and c['retention']['eviction']=='oldest-ts-index','retention schema')
    require(all(type(c['retention'][k]) is int and c['retention'][k]>0 for k in ('dm_seconds','capsule_max_seconds','ciphertext_budget_bytes')),'retention bounds')
    patterns=c['secret_patterns']
    require(isinstance(patterns,list) and all(isinstance(x,dict) and set(x)=={'id','pattern_hash'} and isinstance(x['id'],str) and re.fullmatch('[a-z0-9_]{1,32}',x['id']) and isinstance(x['pattern_hash'],str) and re.fullmatch('[0-9a-f]{64}',x['pattern_hash']) for x in patterns) and len({x['id'] for x in patterns})==len(patterns),'secret pattern schema')
    require(set(c['reason_codes'])=={'refusal','tombstone','suspension','freeze','revocation','outcome'},'reason registries')
    # §13.1: the §17.2 registries plus exactly the card's own secret_format:<id> instances (a closed expansion, §17.2)
    active={'secret_format:'+x['id'] for x in patterns}
    for k,vals in c['reason_codes'].items(): require(isinstance(vals,list) and set(vals)==(refusal_codes(profiles)|active if k=='refusal' else ENUMS[k]) and len(vals)==len(set(vals)),'reason registry differs')
    if 'SUP-1' in profiles: verify_sup(c)
    require(set(c['tiers'])=={'verified','third-party-generated','unverified'} and 'x25519-xsalsa20-poly1305' in c['schemes'],'required tier/scheme')
    require(set(a['id'] for a in c['assurances'])=={f'G{i}' for i in range(1,11)}|{f'N{i}' for i in range(1,6)} and len(c['assurances'])==15,'assurance registry')
    for a in c['assurances']:
        require(set(a)=={'id','status','claim','assumptions','evidence'} and a['status'] in ('proven','promised','not-offered'),'assurance shape/status')
        if a['id'].startswith('N'): require(a['status']=='not-offered','non-guarantee overstated')
    require(bool(c['tile_prefixes']) and all(x.startswith('https://') for x in c['tile_prefixes']),'tile transport')
    return c,hist,h
