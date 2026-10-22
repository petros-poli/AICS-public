"""Minimal HTTP, text/TCP and authenticated C2SP tile clients."""
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from aics_identity import http_signatures, linesig, keys
from aics_tlog import HttpTileReader, VerifiedTileReader
from . import adapter, __version__
from .protocol import J, U, DU, strict_json, Agent, seal, open_message

#: The harness names itself on every HTTP request.  urllib's default ``Python-urllib/3.x`` is refused by some CDN
#: edges before the request reaches the instance (Cloudflare's browser integrity check answers 403, error 1010, on
#: proxied hosts such as a pages host or a tile mirror), which would turn an edge setting into protocol failures.
USER_AGENT = f'aics-conformance/{__version__} (+https://github.com/petros-poli/AICS-public)'

@dataclass
class Response:
    status: int
    body: bytes
    headers: dict
    def json(self): return adapter.normalize_wire(strict_json(self.body))
    def text(self): return self.body.decode('utf-8')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class HTTPTransport:
    def __init__(self, timeout=15):
        self.timeout=timeout
        self.opener=urllib.request.build_opener(NoRedirect())
    def request(self,method,url,body=None,headers=None):
        headers=dict(headers or {})
        if not any(k.lower()=='user-agent' for k in headers): headers['User-Agent']=USER_AGENT
        req=urllib.request.Request(url,data=body,headers=headers,method=method)
        try: response=self.opener.open(req,timeout=self.timeout)
        except urllib.error.HTTPError as e: response=e
        with response:
            data=response.read(16*1024*1024+1)
            if len(data)>16*1024*1024: raise ValueError('HTTP response exceeds harness bound')
            return Response(response.status,data,dict(response.headers))

class JSONClient:
    def __init__(self, api, *, pages=None, transport=None):
        self.api=api.rstrip('/'); self.pages=(pages or api).rstrip('/')
        self.transport=transport or HTTPTransport()
        self.transcript=[]
    def request(self, method, path, body=None, headers=None, *, pages=False):
        r=self.transport.request(method,(self.pages if pages else self.api)+path,body,headers)
        # Exact response bytes permit offline diagnosis. No private keys/credential controls.
        self.transcript.append({'method':method,'path':path,'status':r.status,'response':U(r.body)})
        return r
    def get(self, op, *, params=None, pages=False, **values):
        p=adapter.path(op,**values)
        if params: p+='?'+urllib.parse.urlencode(params)
        r=self.request('GET',p,pages=pages)
        if r.status in (404,408,429) or r.status>=500: raise OSError(f'{op}: unavailable, HTTP {r.status}')
        if r.status!=200: raise ValueError(f'{op}: HTTP {r.status}')
        return r.json()
    def submit(self, e, key, body=None, *, headers=None, route=None):
        raw=J({'envelope':e,'body':None if body is None else U(body)})
        path=route or adapter.path('submit'); p=e['protected']
        h=http_signatures.sign_request('POST',self.api+path,{'Content-Type':'application/json'},raw,
              key=key,keyid=p['kid'],created=p['created'],expires=p['expires'],nonce=p['nonce'],
              tag='aics',components=http_signatures.AICS_COMPONENTS,label='aics')
        if headers is not None: h=headers
        return self.request('POST',path,raw,h)
    def body(self, digest): return self.request('GET',adapter.path('body',hash=digest))
    def notice(self, obj): return self.request('POST',adapter.path('notice'),J(obj),{'Content-Type':'application/json'},pages=True)
    def gate(self): return HTTPSGate(self)

class HTTPSGate:
    def __init__(self,client): self.client=client; self.session=None; self.history=[]
    def exchange(self,line='',*,get=False):
        if get:
            p=adapter.path('gate')+'?'+urllib.parse.urlencode({'s':self.session or '', 'l':line})
            r=self.client.request('GET',p)
        else:
            data=(('session '+self.session+'\n') if self.session else '')+line+'\n'
            r=self.client.request('POST',adapter.path('gate'),data.encode(),{'Content-Type':'text/plain; charset=utf-8'})
        if r.status!=200: raise ValueError(f'text gate: HTTP {r.status}')
        text=r.text()
        if text.startswith('session '):
            first,text=text.split('\n',1); self.session=first[8:]
            if len(DU(self.session))!=16: raise ValueError('invalid session identifier')
        self.history.append(text)
        return text
    def close(self): pass

class TCPGate:
    """7700 TLS (certificate/hostname verified), 7701 plaintext; explicit override for tests."""
    def __init__(self, target, *, tls=None, timeout=15, ssl_context=None):
        host, port=target.rsplit(':',1); host=host.strip('[]'); port=int(port)
        self.tls=(port!=7701) if tls is None else tls
        sock=socket.create_connection((host,port),timeout=timeout)
        self.socket=(ssl_context or ssl.create_default_context()).wrap_socket(sock,server_hostname=host) if self.tls else sock
        self.stream=self.socket.makefile('rb'); self.session=None
    def exchange(self,line=None,**unused):
        if line is not None: self.socket.sendall((line+'\n').encode())
        parts=[]; total=0
        while True:
            raw=self.stream.readline(131074)
            if not raw: raise EOFError('gate closed before prompt')
            total+=len(raw)
            if total>2*1024*1024: raise ValueError('oversized gate reply')
            parts.append(raw)
            if raw.rstrip(b'\r\n')==b'>': break
        text=b''.join(parts).decode()
        if text.startswith('session '): self.session,text=text.split('\n',1)[0][8:],text.split('\n',1)[1]
        return text
    def close(self): self.stream.close(); self.socket.close()

class Tiles:
    def __init__(self, url, *, transport=None, timeout=15):
        self.url=url.rstrip('/'); self.transport=transport or HTTPTransport(timeout)
        self.reader=HttpTileReader(url,timeout=timeout)
        # Fake transports expose a TileReader; real runs always use aics-tlog HTTP.
        if hasattr(self.transport,'tile_reader'): self.reader=self.transport.tile_reader(url)
    def checkpoint(self):
        r=self.transport.request('GET',self.url+'/checkpoint')
        if r.status in (404,408,429) or r.status>=500: raise OSError(f'checkpoint: unavailable, HTTP {r.status}')
        if r.status!=200: raise ValueError(f'checkpoint: HTTP {r.status}')
        return r.body
    def authenticated(self, cp): return VerifiedTileReader(self.reader,cp.size,cp.root)

# Explicit local API exports; private keys are never serialized into requests.
generate_agent=Agent
sign_line=linesig.sign_line
