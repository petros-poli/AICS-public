import copy
from ..core import check
from ..protocol import DU,U,Agent,open_message,envelope
from ..schema import require
from .. import verify,adapter
@check('G6','Recipient key provenance and ciphertext/header binding','AICS-1 §§8.1,14.3','swapped_key')
def privacy(ctx):
    sender,recipient,entry,note,i,ct,content=ctx.dm_fixture(); lookup=ctx.client.get('name',name=recipient.name); ids,rawhead=adapter.lookup(lookup)
    h=verify.head(DU(rawhead),ctx.policy,ctx.now()); hist,h=ctx.scan(h); state=hist.names[recipient.name]
    expected=[j for j,e in enumerate(hist.entries) if e['type'] in ('name.claim','key.rotate','key.revoke','x25519.rotate') and e['payload']['name_norm']==recipient.name]
    require(ids==expected,'lookup omits key events')
    require(lookup.get('x25519',state['x'])==state['x'] and lookup.get('key_leaf_index',state['key_index'])==state['key_index'],'lookup swapped logged recipient key')
    b=ctx.client.get('entry',index=state['key_index']); kh=verify.head(DU(b['checkpoint_note']),ctx.policy,ctx.now(),historical=True); prefix,_=ctx.scan(kh,validate=False); verify.bundle(b,ctx.policy,ctx.now(),prefix=prefix)
    require(open_message(entry['payload']['envelope'],ct,recipient.encryption_key)==content,'local decryption changed content')
    attacker=Agent(); original=entry['payload']['envelope']
    for change in ('from_kid','to_kid','envelope_nonce'):
        q=copy.deepcopy(original['payload']); nonce=original['protected']['nonce']; signer=sender
        if change=='from_kid': signer=attacker
        if change=='to_kid': q['to_kid']=attacker.kid
        if change=='envelope_nonce': nonce=U(bytes(16))
        wrapped=envelope(signer,ctx.policy.trust['origin'],'dm',q,int(ctx.now()),nonce=nonce)
        try: open_message(wrapped,ct,recipient.encryption_key)
        except ValueError: pass
        else: raise ValueError('recipient accepted ciphertext wrapped in a different envelope')
    return dict(assumptions=['local sealed-box implementation','uncompromised recipient key'],excluded=['metadata secrecy','default forward secrecy'])
