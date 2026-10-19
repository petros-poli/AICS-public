import re
import secrets
from aics_identity import keys
from .. import dialogue as d
from ..adapter import VERBS, READ_VERBS
from ..protocol import U, DU, J, H, strict_json, envelope, Agent, command


def tokens(line):
    # Gate quoting has neither shell expansion nor backslash escapes.
    found=re.findall(r'''"[\x20-\x21\x23-\x7e]*"|'[\x20-\x26\x28-\x7e]*'|[^\s"']+''',line)
    if ''.join(found)!=''.join(line.split()):
        # Compare spacing only outside quotes by reconstructing consumed spans.
        pos=0
        for m in re.finditer(r'''"[\x20-\x21\x23-\x7e]*"|'[\x20-\x26\x28-\x7e]*'|[^\s"']+''',line):
            if line[pos:m.start()].strip(): raise ValueError('quote')
            pos=m.end()
        if line[pos:].strip(): raise ValueError('quote')
    return [x[1:-1] if x[:1] in ('"',"'") else x for x in found]


def exchange(server,method,body,query,*,plain=False):
    if method=='GET': sid=query.get('s',[''])[0]; lines=query.get('l',[''])[0].splitlines()
    else:
        lines=body.decode().splitlines(); sid=''
        if lines and lines[0].startswith('session '): sid=lines.pop(0)[8:]
    new=sid not in server.sessions
    if new:
        sid=U(secrets.token_bytes(16)); server.sessions[sid]=dict(stage='tools',bad=0,branch=None,agent=None,body=None,pending=None,dead=False)
    s=server.sessions[sid]; out=[]
    # Preserve SSHSIG armor as one signature artifact, never reinterpret it as lines.
    if 'sig-begin' in lines:
        start=lines.index('sig-begin'); end=lines.index('sig-end',start)
        from aics_identity.sshsig import parse_sshsig
        blob=parse_sshsig('\n'.join(lines[start+1:end])+'\n').to_blob()
        lines=lines[:start]+['sig '+U(blob)]+lines[end+1:]
    if new:
        out.extend(['session '+sid,d.BANNER.rstrip('\n'),d.TOOLS])
    def emit(text): out.append(text)
    for line in lines:
        if not line.strip(): continue
        try:
            if len(line.encode())>131072 or any(ord(c)<32 and c!='\t' for c in line) or not line.isascii(): raise ValueError('line')
            if 'leeway' in server.faults and (line!=line.strip() or line.split()[0]!=line.split()[0].lower() or '"' in line or "'" in line): raise ValueError('leeway')
            t=tokens(line); verb=t[0].lower(); args=t[1:]
            if verb=='sig:': verb='sig'
            if s['dead']: emit('err malformed help'); continue
            if method=='GET' and 'get_write' not in server.faults and (verb in ('body','secret','draft') or verb in VERBS and verb not in ('claim','claim-upgrade') or verb=='claim-upgrade'):
                emit('err unsupported_scheme use POST'); continue
            if method=='GET' and 'get_write' in server.faults and verb in ('post','body','secret','claim-upgrade'): emit('ok accepted'); continue
            if 'reply_'+verb in server.faults: emit('SUCCESS'); continue
            if verb=='tools':
                if not args or args[0] not in ('openssl','ssh-keygen','python3','none'): raise ValueError('tools')
                s['branch']=args[0]; s['stage']='pub'
                if args[0]=='none': emit(d.NONE)
                else:
                    out.extend({'openssl':d.OPENSSL,'ssh-keygen':d.SSH,'python3':d.PYTHON}[args[0]])
                    if args[0]=='openssl': emit(d.openssl_sign(sid))  # AICS-1 §11.4 item 2: for later signing
                    emit(d.SSH_PUB if args[0]=='ssh-keygen' else d.PUB)
                if 'onboard_'+args[0] in server.faults: out[-1]='? paste your private key'
            elif verb=='pub' and s['stage']=='pub':
                pub=keys.parse_openssh_public_key(' '.join(args)) if args[0]=='ssh-ed25519' and hasattr(keys,'parse_openssh_public_key') else None
                if args[0]=='ssh-ed25519':
                    from aics_identity.sshsig import parse_openssh_public_key
                    pub=parse_openssh_public_key(' '.join(args))
                else: pub=keys.public_key_from_bytes(keys.b64_decode_strict(args[0]))
                s['pub']=pub; s['stage']='enc'; emit(d.ENC)
            elif verb=='enc' and s['stage']=='enc':
                raw=keys.b64_decode_strict(args[0]); assert len(raw)==32
                s['x']=U(raw); s['stage']='recovery'; emit(d.RECOVERY)
            elif verb=='recovery' and s['stage']=='recovery' and args==['none']:
                s['stage']='name'; emit(d.NAME)
            elif verb=='name' and s['stage']=='name':
                name=args[0].removeprefix('@').lower().removesuffix('.wesupport-ai.com')
                if not re.fullmatch('[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?',name): raise ValueError('name')
                s['name']=name; s['stage']='grant'; emit(d.GRANT)
            elif verb in ('closed','open') and s['stage']=='grant':
                a=Agent(name=s['name']); q=a.claim(); q.update(ed25519=U(s['pub'].public_bytes_raw()),x25519=s['x'],tier='third-party-generated' if s['branch']=='none' else 'verified')
                if verb=='open': q['initial_grant']=dict(sender_kid='*',max=int(args[0]),expires=int(args[1]))
                e=envelope(a,server.origin,'name.claim',q,int(server.now)); e.pop('sig'); e['protected']['kid']=keys.did_key(s['pub'])
                e['auth']=dict(scheme='text-sshsig' if s['branch']=='ssh-keygen' else 'text-ed25519',session=sid)
                s['proposal']=e; s['stage']='claim'; emit('ok envelope '+U(J(e)))
                if s['branch']=='ssh-keygen': emit(d.SSH_SIGN)
                emit('? Sign this exactly: '+command(e))
            elif verb in ('claim','claim-upgrade') and s.get('proposal'):
                if ' '.join([verb]+args)!=command(s['proposal']): raise ValueError('claim commitment')
                s['pending']=s['proposal']; emit('? Reply exactly: sig <base64>')
            elif verb=='draft':
                typ=VERBS[args[0]]; q=strict_json(DU(args[1])); a=Agent(); a.previous=server.last.get(s['kid']); e=envelope(a,server.origin,typ,q,int(server.now)); e.pop('sig'); e['protected']['kid']=s['kid']; e['auth']=dict(scheme='text-ed25519',session=sid)
                emit('ok envelope '+U(J(e)))
            elif verb in VERBS:
                e=strict_json(DU(args[0])); s['pending']=e; emit('? Reply exactly: sig <base64>')
            elif verb=='body': s['body']=keys.b64_decode_strict(args[0]); emit('ok body staged')
            elif verb=='sig' and s['pending']:
                e=s['pending']|{'sig':U(keys.b64_decode_strict(args[0]))}; r=server.submit(e,s['body'],{},'https://fake/t',gate=True); s['body']=None; s['pending']=None; obj=r.json()
                if r.status==202:
                    s['kid']=e['protected']['kid']; s['stage']='ready'
                    if e['protected']['type']=='name.claim': emit(f"ok name {s['name']} bound to key {s['kid']} at leaf {len(server.entries)-1}; verify at /tiles")
                    else: emit('ok accepted')
                else: emit('err '+obj['entry']['payload']['reason_code']+' help')
                emit('entry '+U(J(obj['entry']))); emit('receipt '+obj['receipt_note']); emit('ok help '+ ' '.join(READ_VERBS+tuple(VERBS)))
            elif verb=='fallback': emit('err tls_required use 7700 or HTTPS' if plain else d.FALLBACK)
            elif verb in READ_VERBS:
                if args and verb in ('help','who','quit'): raise ValueError('argument')
                if verb in ('find','read','fetch','inbox') and not args: raise ValueError('argument')
                if verb=='quit': s['dead']=True
                emit('ok '+verb)
                if verb in ('read','fetch'):
                    i=int(args[0]); emit('entry '+U(J(server.entries[i])))
                if verb=='help': emit('ok '+ ' '.join(READ_VERBS+tuple(VERBS)))
            else: raise ValueError('syntax')
            s['bad']=0
        except (ValueError,KeyError,IndexError,AssertionError):
            s['bad']+=1
            if s['bad']>=3 and 'malformed_rule' not in server.faults: s['dead']=True; emit('err malformed help')
            else: emit('retry tools <space-separated list> or tools none' if s['stage']=='tools' else 'retry help')
    out.append('>'); return '\n'.join(out)+'\n'
