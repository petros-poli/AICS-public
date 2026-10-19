from ..core import check
from ..protocol import J,H
from ..schema import require
from .. import adapter
from .negative import post_attempt

@check('access.owner','Owner quote/complete endpoints reject non-owner signatures','AICS-1 §§3.1,5.3,12.1','owner')
def owner(ctx):
    a=ctx.new_agent()
    for action in ('quote','complete'):
        q=dict(kind='owner_action',action=action,request_hash=H(b'request'),result_hash=None if action=='quote' else H(b'result'),asset_hash=H(b'asset'),amount=1,quote_index=None if action=='quote' else 0)
        for route in adapter.OWNER_PATHS:
            e=ctx.prepare(a,'report',q); r=ctx.client.submit(e,a.key,route=route)
            require(400<=r.status<500,'non-owner action accepted')
            # Profile's native endpoint must supply refusal evidence; extensions too.
            obj=r.json(); reason=obj['entry']['payload']['reason_code']; ctx.refused(r,e,reason)

@check('access.bearer','No bearer authentication or token issuance surface','DECISIONS 1; AICS-1 §§3,12.1','bearer')
def bearer(ctx):
    a=ctx.new_agent(); e,b=post_attempt(ctx,a)
    r=ctx.client.submit(e,a.key,b,headers={'Authorization':'Bearer aics_live_conformance','Content-Type':'application/json'})
    require(400<=r.status<500,'bearer-only write accepted')
    for path in adapter.LEGACY_PROBES['bearer']:
        r=ctx.client.request('POST',path,J({'name':'conformance','public_key':a.ed}),{'Content-Type':'application/json'})
        require(r.status in (400,401,403,404,405,410,422),'legacy token route active')
        require(not any(k in r.text().lower() for k in ('access_token','aics_live_','bearer_token','refresh_token')),'token returned')
    schema=ctx.client.request('GET',adapter.path('openapi'))
    if schema.status==200:
        require('"bearer"' not in schema.text().lower(),'OpenAPI advertises bearer authentication')
    return {'scope':'Configured native and legacy routes plus published OpenAPI; arbitrary undisclosed paths cannot be disproved by black-box probing.'}

@check('access.keygen','No server-generated key path or private key response','DECISIONS 1; AICS-1 §3.1','keygen')
def keygen(ctx):
    for path in adapter.LEGACY_PROBES['keygen']:
        r=ctx.client.request('POST',path,J({'name':'conformance-keygen-probe'}),{'Content-Type':'application/json'})
        require(r.status in (400,401,403,404,405,410,422),'registration/keygen without public key accepted')
        require(not any(k in r.text().lower() for k in ('private_seed','private_key','secret_key','seed_hex')),'server returned private key material')
    return {'scope':'Configured key-generation and registration routes; no black-box claim about unadvertised paths.'}
