from aics_tlog import inclusion_proof_from_tiles, consistency_proof_from_tiles, MerkleTree, verify_consistency
from ..core import check, Skip
from ..protocol import J, DU, DB, H
from ..schema import require
from .. import verify, adapter

@check('log.checkpoint','Checkpoint signature uses out-of-band key','AICS-1 §§6.2–6.4,14.1','bad_checkpoint')
def checkpoint(ctx):
    h=ctx.head()
    return dict(size=h.cp.size,checkpoint_hash=H(h.raw),freshness='witnessed' if ctx.policy.quorum else 'remote freshness unproven')

@check('log.consistency','Two current fetches extend the same history','AICS-1 §§6.1,14.2','rollback')
def consistency(ctx):
    old=ctx.head(); a=ctx.new_agent(); ctx.post(a); entries,new=ctx.scan(validate=False)
    verify.continuity(old,new,entries)

@check('log.proofs','Served proofs equal authenticated tile-derived proofs','AICS-1 §§6.1,12.1,14.2','bad_proof')
def proofs(ctx):
    old=ctx.head(); ctx.new_agent(); entries,h=ctx.scan(validate=False); reader=ctx.tiles.authenticated(h.cp)
    for i in sorted({0,h.cp.size-1,h.cp.size//2}):
        r=ctx.client.get('inclusion',params=dict(index=i,size=h.cp.size)); require(r['index']==i and r['size']==h.cp.size,'proof coordinates')
        require([DB(x) for x in r['hashes']]==inclusion_proof_from_tiles(reader,i,h.cp.size),'served inclusion differs from tiles')
    for m in (0,old.cp.size,h.cp.size):
        r=ctx.client.get('consistency',params={'from':m,'to':h.cp.size}); require(r['from']==m and r['to']==h.cp.size,'consistency coordinates')
        require([DB(x) for x in r['hashes']]==consistency_proof_from_tiles(reader,m,h.cp.size),'served consistency differs from tiles')

@check('log.receipt','Exact receipted entry included within 60 seconds','AICS-1 §§10.1,14.4','dropped_receipt')
def receipt(ctx):
    a=ctx.new_agent(); entry,note=ctx.post(a); i=ctx.follow(entry,note)
    return dict(index=i,timing=ctx.evidence['timing_evidence'])

@check('log.tombstone','Tombstone hides only body and preserves exact leaf','AICS-1 §10.3','tombstone_delete')
def tombstone(ctx):
    hist,h=ctx.scan(); candidates=[(i,e) for i,e in enumerate(hist.entries) if e['type']=='tombstone']
    if ctx.policy.tombstone_index is not None: candidates=[(i,e) for i,e in candidates if i==ctx.policy.tombstone_index]
    if not candidates:
        where='at tombstone_index %d' % ctx.policy.tombstone_index if ctx.policy.tombstone_index is not None else 'in the log'
        raise Skip(f'no tombstone {where} to check: an operator logs one only for a reason that is true of its target '
                   '(AICS-1 §10.3), with its own owner tools; the harness holds no owner or policy key')
    def digest_of(q): return q.get('body_hash',q.get('ct_hash'))
    for i,e in candidates:
        target=e['payload']['target_index']; b=ctx.client.get('entry',index=target)
        require(DU(b['entry_bytes'])==hist.raw[target],'tombstone changed or deleted target leaf')
        targetq=hist.entries[target]['payload']; digest=digest_of(targetq)
        if digest:
            require(b['body_or_ct'] is None,'tombstoned body still served in its bundle')
            # Another entry that is not hidden may commit to the same bytes (two identical public bodies): the body
            # service then serves them for that entry, and the hidden one is checked through its bundle only.
            shared=[j for j,x in enumerate(hist.entries) if j!=target and digest_of(x['payload'])==digest and j not in hist.tombstones]
            if shared: continue
            r=ctx.client.body(digest); require(r.status in (404,410),'tombstoned body still served')
            status=r.json(); require(status['tombstone_index']==i and status['reason_code']==e['payload']['reason_code'],'body status lacks tombstone evidence')

@check('log.metadata','Every entry bundle contains only closed metadata schemas','AICS-1 §§5.1–5.3,6.1','plaintext_field_leak')
def metadata(ctx):
    hist,h=ctx.scan(); return dict(entries_scanned=len(hist.entries),checkpoint_hash=H(h.raw))
