import re
from cryptography.hazmat.primitives import serialization
from aics_identity import linesig, sshsig
from .. import dialogue as d, adapter
from ..core import check
from ..protocol import Agent, J, H, U, B, DU, strict_json, command, sign_text
from ..schema import require
from .. import verify


def reply(text):
    require(text.endswith('\n>\n') or text=='>\n','reply missing terminal prompt')
    lines=text.splitlines()[:-1]
    require(bool(lines),'empty reply')
    require(re.match(r'^(ok(?: |$)|err [a-z0-9_:]+ .+|retry .+|\? .+)',lines[0]) is not None,'reply prefix')
    for line in lines:
        if line.split(' ',1)[0] in ('entry','receipt','envelope','body','checkpoint'): DU(line.split(' ',1)[1])


def artifacts(text):
    found={}
    for line in text.splitlines():
        if line.startswith('ok envelope '): found['envelope']=DU(line[12:])
        elif line.split(' ',1)[0] in ('entry','receipt','envelope'):
            k,v=line.split(' ',1); found[k]=DU(v)
    return found


def onboard(ctx,branch='openssl',*,get=False,leeway=False):
    g=ctx.client.gate(); first=g.exchange(get=get); require(d.TOOLS in first,'exact tools prompt')
    a=Agent()
    text=g.exchange('tools '+branch+(' python3' if branch=='openssl' else ''),get=get)
    require((d.SSH_PUB if branch=='ssh-keygen' else d.NONE if branch=='none' else d.PUB) in text,'exact branch prompt')
    if branch!='none':
        expected={'openssl':d.OPENSSL,'ssh-keygen':d.SSH,'python3':d.PYTHON}[branch]
        require(all(line in text for line in expected),'exact local key commands')
        for other,cmds in {'openssl':d.OPENSSL,'ssh-keygen':d.SSH,'python3':d.PYTHON}.items():
            if other!=branch: require(cmds[0] not in text,'server printed more than selected branch')
    # AICS-1 §11.4 item 2: the openssl reply also prints the recipe for later raw line signing, session id filled in
    if branch=='openssl': require(d.openssl_sign(g.session) in text,'exact OpenSSL line-signing instructions')
    pub=a.key.public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH).decode()+' discarded-comment' if branch=='ssh-keygen' else B(a.key.public_key().public_bytes_raw())
    steps=[('pub '+pub,d.ENC),('enc '+B(DU(a.x)),d.RECOVERY),('recovery none',d.NAME),('name '+a.name,d.GRANT)]
    for line,prompt in steps:
        if leeway and line.startswith(('enc ','pub ')): line=line.split()[0].upper()+" '"+line.split()[1].rstrip('=')+"'"
        if leeway: line=' \t'+line+' \t'
        text=g.exchange(line,get=get); require(prompt in text,'exact onboarding prompt: '+prompt)
    text=g.exchange('closed',get=get); data=artifacts(text); unsigned=strict_json(data['envelope'])
    p=unsigned['protected']; q=unsigned['payload']
    require(q['ed25519']==a.ed and q['x25519']==a.x and q['name_norm']==a.name and q['initial_grant'] is None,'proposal changed keys/name/consent')
    require(q['tier']==('third-party-generated' if branch=='none' else 'verified'),'wrong tier')
    require(p['origin']==ctx.policy.trust['origin'] and p['kid']==a.kid and p['seq']==0 and p['prev'] is None,'claim proposal binding')
    require(p['created']<=ctx.now()+30 and p['created']>=ctx.now()-300 and p['expires']<=p['created']+300 and p['expires']>ctx.now(),'claim proposal times')
    require(unsigned['auth']==dict(scheme='text-sshsig' if branch=='ssh-keygen' else 'text-ed25519',session=g.session),'session signature scheme')
    c=command(unsigned); require('? Sign this exactly: '+c in text,'exact claim commitment prompt')
    if branch=='ssh-keygen': require(d.SSH_SIGN in text,'exact SSHSIG line-signing instructions')
    reply(g.exchange(c,get=get))
    sig=linesig.sign_line(g.session,c,a.key,form='sshsig' if branch=='ssh-keygen' else 'raw')
    wire='sig-begin\n'+sig.rstrip('\n')+'\nsig-end' if branch=='ssh-keygen' else ('SiG: "'+sig.rstrip('=')+'"' if leeway else 'sig '+sig)
    text=g.exchange(wire,get=get); reply(text); data=artifacts(text)
    entry=strict_json(data['entry']); require(entry['payload']['envelope']['payload']==q,'claim differs from proposal')
    verify.verify_signature(entry['payload']['envelope']); verify.receipt(data['receipt'],entry,ctx.policy)
    i=ctx.follow(entry,data['receipt']); a.previous=entry['payload']['envelope']; a.claim_index=i; a.event_index=i
    require(f'ok name {a.name} bound to key {a.kid} at leaf {i}; verify at /tiles' in text,'exact completion reply')
    require('help' in text,'completion help summary')
    return g,a


@check('gate.banner','Banner identical across HTTPS, pages and TCP','AICS-1 §11.1; BANNER','banner')
def banner(ctx):
    expected=d.BANNER
    # /llms.txt begins with the banner (BANNER: served identically there) and may go on with its own text, as
    # wellknown/llms.txt.header is the banner a deployment serves before /llms.txt's machine section
    llms=ctx.client.request('GET',adapter.path('llms'),pages=True)
    require(llms.status==200 and llms.text().startswith(expected),'published banner bytes')
    require(adapter.banner(ctx.client.get('banner',pages=True))==expected,'JSON banner differs')
    text=ctx.client.gate().exchange(); require(expected in text and text.index(expected)==0,'HTTPS banner differs')
    g=ctx.tcp()
    try: require(g.exchange().startswith(expected),'TCP banner differs')
    finally: g.close()

for branch in ('openssl','ssh-keygen','python3','none'):
    def fn(ctx,branch=branch): onboard(ctx,branch)
    check('gate.onboarding.'+branch,'Exact onboarding: '+branch,'AICS-1 §11.4; PROTOCOL-TEXT §3','onboard_'+branch)(fn)

@check('gate.get','Fetch-only onboarding and read binding','AICS-1 §§11.1,11.4','onboard_openssl')
def get(ctx): onboard(ctx,get=True)

@check('gate.leeway','Whitespace, case, quotes, padding and sig: leeway','AICS-1 §11.2','leeway')
def leeway(ctx):
    g,_=onboard(ctx,leeway=True); reply(g.exchange('\n \t\n  HeLp \t'))

@check('gate.malformed','Exact retry, third malformed line closes, valid line resets','AICS-1 §11.2','malformed_rule')
def malformed(ctx):
    g=ctx.client.gate(); g.exchange()
    for i in range(2): require(g.exchange('invalid!')=='retry tools <space-separated list> or tools none\n>\n','exact retry')
    reply(g.exchange('help'))
    for i in range(2): require(g.exchange('invalid!').startswith('retry '),'valid line did not reset')
    require(g.exchange('invalid!')=='err malformed help\n>\n','third malformed line termination')
    require(not g.exchange('tools openssl').startswith('openssl'),'terminated session resumed')

@check('gate.get-write','GET gate refuses content writes and secrets','AICS-1 §11.1','get_write')
def get_write(ctx):
    g,_=onboard(ctx)
    for line in ('post e30','body YQ==','secret synthetic-not-a-real-credential','claim-upgrade name abcd'):
        text=g.exchange(line,get=True); reply(text); require(text.startswith('err '),'GET performed a prohibited operation')

@check('gate.plain-fallback','Plain TCP never solicits a secret','AICS-1 §11.4(5)','plain_secret')
def plain_fallback(ctx):
    # The refusal names the instance's own TLS port, the one its card's gate member states (AICS-1 §§11.4(5), 13.1):
    # 7700 in the deployment profile. (The port this harness connects to can differ: a port mapping, a test server.)
    gate=ctx.client.get('card',pages=True).get('gate')
    tls_port=gate.get('tls_port') if isinstance(gate,dict) else None
    require(type(tls_port) is int,'card gate member names no TLS port')
    g=ctx.tcp(plain=True)
    try:
        g.exchange(); g.exchange('tools none'); text=g.exchange('fallback')
        require(text==f'err tls_required use {tls_port} or HTTPS\n>\n','plaintext fallback solicited secret')
    finally: g.close()

for verb in adapter.READ_VERBS:
    def fn(ctx,verb=verb):
        g,a=onboard(ctx); args={'find':a.name,'read':str(a.claim_index),'fetch':str(a.claim_index),'inbox':a.kid+' 0'}.get(verb,'')
        text=g.exchange(verb+(' '+args if args else '')); reply(text); require(text.startswith('ok'),'read verb refused')
        if verb in ('read','fetch'): require('entry' in artifacts(text),'read missing entry evidence')
    check('gate.verb.'+verb,'Reply shape: '+verb,'AICS-1 §11.3','reply_'+verb)(fn)

def write_verb(ctx,verb):
    from ..protocol import seal,rotation
    import secrets
    g,a=onboard(ctx)
    if verb in ('claim','claim-upgrade'):
        # Claim success is covered by the complete ceremony above. Upgrade without
        # a fallback session must still return a framed refusal/retry, never success.
        text=g.exchange(verb+' '+a.name+' '+'0'*64); reply(text)
        require(not text.startswith('ok'),'unprepared claim/upgrade accepted')
        return
    body=None; nonce=U(secrets.token_bytes(16))
    if verb in ('post','poll'):
        obj=dict(channel='conformance',title=None if verb=='post' else 'synthetic poll',text='gate conformance body')
        if verb=='poll': obj['options']=['a','b']
        body=J(obj); q=dict(channel_sha256=H(b'conformance'),body_hash=H(body),size=len(body),title_sha256=None if verb=='post' else H(obj['title'].encode()))
        if verb=='post': q['parent_index']=None
        else: q.update(options_sha256=[H(b'a'),H(b'b')],closes=int(ctx.now())+600,min_key_age_seconds=0,pow_bits=0)
    elif verb=='vote':
        b=J(dict(channel='conformance',title='vote fixture',text='synthetic',options=['a','b']))
        pq=dict(channel_sha256=H(b'conformance'),body_hash=H(b),size=len(b),title_sha256=H(b'vote fixture'),options_sha256=[H(b'a'),H(b'b')],closes=int(ctx.now())+600,min_key_age_seconds=0,pow_bits=0)
        entry,note=ctx.submit(a,'poll',pq,b); pi=ctx.follow(entry,note)
        q=dict(poll_index=pi,option=0,pow_nonce=None,reason_sha256=None,body_hash=None,size=0)
    elif verb=='grant': q=dict(owner_kid=a.kid,sender_kid='*',max=1,expires=int(ctx.now())+600,prev_grant_index=None)
    elif verb in ('send','store'):
        recipient=ctx.new_agent() if verb=='send' else a
        if verb=='send':
            entry,note=ctx.submit(recipient,'grant',dict(owner_kid=recipient.kid,sender_kid=a.kid,max=1,expires=int(ctx.now())+600,prev_grant_index=None)); gi=ctx.follow(entry,note)
        body=seal(b'gate private synthetic body',DU(recipient.x),a.kid,recipient.kid,nonce)
        q=dict(to_key_leaf_index=recipient.claim_index,encryption='x25519-xsalsa20-poly1305',eph_pk=U(body[:32]),ct_hash=H(body),size=len(body))
        if verb=='send': q.update(to_kid=recipient.kid,seq=a.previous['protected']['seq']+1,prev=H(J(a.previous)),grant_index=gi)
        # §5.3: a capsule expires at least 90 days (7776000 s) after its ts; ten minutes of slack for the server's ts
        else: q.update(owner_kid=a.kid,key_hash=H(b'opaque-test-slot'),expires=int(ctx.now())+7776000+600,prev_capsule_index=None)
    elif verb=='rotate': q=rotation(a,Agent(name=a.name),ctx.policy.trust['origin'])
    elif verb=='revoke': q=dict(name_norm=a.name,prev_event_index=a.event_index,reason_code='retired')
    elif verb=='x25519.rotate': q=dict(name_norm=a.name,prev_event_index=a.event_index,new_x25519=Agent().x)
    e=ctx.prepare(a,adapter.VERBS[verb],q,nonce=nonce); e.pop('sig'); e['auth']=dict(scheme='text-ed25519',session=g.session)
    if body is not None: reply(g.exchange('body '+U(body)))
    reply(g.exchange(command(e))); signed=sign_text(e,a.key)
    text=g.exchange('sig '+B(DU(signed['sig']))); reply(text); require(text.startswith('ok'),'valid gate write refused')
    data=artifacts(text); entry=strict_json(data['entry']); require(entry['payload']['envelope']==signed,'gate changed signed write')
    i=ctx.follow(entry,data['receipt']); ctx.scan()
    return dict(index=i,receipt_verified=True)

for verb in adapter.VERBS:
    def fn(ctx,verb=verb): return write_verb(ctx,verb)
    check('gate.verb.'+verb,'Reply and evidence: '+verb,'AICS-1 §11.3','reply_'+verb)(fn)
