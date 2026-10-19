"""RFC 9421 and envelope metadata must describe the same logical attempt."""
import secrets
from aics_identity import http_signatures
from ..core import check
from ..protocol import J,U
from ..schema import require
from .. import adapter
from .negative import post_attempt

@check('http.binding','Native HTTP signatures bind the exact envelope metadata','AICS-1 §12.1','http_binding')
def binding(ctx):
    a=ctx.new_agent()
    for changed in ('nonce','created','expires','label'):
        e,b=post_attempt(ctx,a); p=e['protected']; raw=J(dict(envelope=e,body=U(b)))
        args=dict(key=a.key,keyid=p['kid'],created=p['created'],expires=p['expires'],nonce=p['nonce'],label='aics',tag='aics',components=http_signatures.AICS_COMPONENTS)
        if changed=='nonce': args['nonce']=U(secrets.token_bytes(16))
        elif changed=='label': args['label']='other'
        else: args[changed]-=1
        headers=http_signatures.sign_request('POST',ctx.client.api+adapter.path('submit'),{'Content-Type':'application/json'},raw,**args)
        r=ctx.client.submit(e,a.key,b,headers=headers)
        require(400<=r.status<500,'HTTP/envelope mismatch accepted')
        q=r.json()['entry']['payload']; require(q['reason_code'] in ('bad_signature','malformed'),'wrong HTTP-binding refusal')
        # The transport binding is invalid. Do not accept asserted identity fields.
        ctx.refused(r,e,q['reason_code'],authenticated=False)
