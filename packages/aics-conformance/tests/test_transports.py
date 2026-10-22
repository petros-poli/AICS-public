import datetime
import ssl
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from aics_conformance.client import JSONClient,Tiles,TCPGate
from aics_conformance.core import Context,CHECKS
from aics_conformance.fakes.network import http_server,tcp_server
from aics_conformance.protocol import DU
from aics_conformance import dialogue
from aics_conformance.checks.gate import onboard


def test_real_http_gate_post_and_percent_decoded_get(server):
    with http_server(server) as url:
        client=JSONClient(url); ctx=Context(client,Tiles(url+'/tiles'),server.configuration(),clock=lambda:server.now,sleep=server.sleep)
        onboard(ctx,get=True)
        g=client.gate(); g.exchange()
        assert g.exchange('help%20',get=True).startswith('retry ')
        assert g.exchange('help',get=True).startswith('ok ')


def test_real_http_native_signatures_and_tile_proofs(server):
    with http_server(server) as url:
        client=JSONClient(url); ctx=Context(client,Tiles(url+'/tiles'),server.configuration(),clock=lambda:server.now,sleep=server.sleep)
        a=ctx.new_agent(); entry,note=ctx.post(a); i=ctx.follow(entry,note)
        hist,h=ctx.scan(); assert hist.entries[i]==entry
        c=next(c for c in CHECKS if c.id=='log.proofs'); r=c.run(ctx)
        assert r['verdict']=='pass',r['details'].get('reason')


def test_real_plain_tcp(server):
    with tcp_server(server) as address:
        g=TCPGate(address,tls=False)
        try:
            assert dialogue.TOOLS in g.exchange()
            assert dialogue.NONE in g.exchange('tools none')
            assert g.exchange('fallback')=='err tls_required use 7700 or HTTPS\n>\n'
        finally: g.close()

def test_the_plain_target_is_guessed_only_beside_the_deployment_profile_s_tls_port(monkeypatch):
    """Without gate_plain the plaintext target was the TLS target's host on 7701. For staging (TLS gate on 7800 on
    production's address) that is production's plaintext gate, so 7701 is guessed only beside 7700; otherwise the
    plaintext checks skip until gate_plain names the instance's own port."""
    import types
    import aics_conformance.core as core
    opened=[]
    monkeypatch.setattr(core,'TCPGate',lambda target,tls=None: opened.append((target,tls)) or target)
    client=types.SimpleNamespace(transport=object())
    unnamed=types.SimpleNamespace(gate_plain=None)
    staging=Context(client,None,unnamed,gate='test.wesupport-ai.com:7800')
    with pytest.raises(core.Skip,match='gate_plain'): staging.tcp(plain=True)
    assert staging.tcp()=='test.wesupport-ai.com:7800'
    assert Context(client,None,unnamed,gate='gate.wesupport-ai.com:7700').tcp(plain=True)=='gate.wesupport-ai.com:7701'
    named=Context(client,None,types.SimpleNamespace(gate_plain='test.wesupport-ai.com:7801'),gate='test.wesupport-ai.com:7800')
    assert named.tcp(plain=True)=='test.wesupport-ai.com:7801'
    assert opened==[('test.wesupport-ai.com:7800',None),('gate.wesupport-ai.com:7701',False),('test.wesupport-ai.com:7801',False)]


def test_the_plaintext_refusal_names_the_tls_port_the_card_states(server):
    """gate.plain-fallback expects the TLS port the instance's card names (AICS-1 §13.1), not a fixed 7700 and not the
    port the harness connects to: the fake gate refuses with "use 7700", which passes against the fake's own card and
    fails against a card that names 7800 (a staging instance's)."""
    check=next(c for c in CHECKS if c.id=='gate.plain-fallback')
    ctx=server.context(); card=ctx.client.get('card',pages=True)
    assert card['gate']['tls_port']==7700
    assert check.run(ctx)['verdict']=='pass'
    get=ctx.client.get
    def staging_card(op,**kw):
        found=get(op,**kw)
        return {**found,'gate':{**found['gate'],'tls_port':7800,'plaintext_port':7801}} if op=='card' else found
    ctx.client.get=staging_card
    result=check.run(ctx)
    assert result['verdict']=='fail' and result['details']['reason']=='plaintext fallback solicited secret',result


@pytest.fixture
def tls_contexts(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048); name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    kp=tmp_path/'key.pem'; cp=tmp_path/'cert.pem'
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.load_cert_chain(cp,kp)
    client=ssl.create_default_context(cafile=str(cp))
    return server,client


def test_real_tcp_tls_validates_certificate(server,tls_contexts):
    sc,cc=tls_contexts
    with tcp_server(server,ssl_context=sc) as address:
        g=TCPGate(address,tls=True,ssl_context=cc)
        try:
            assert dialogue.TOOLS in g.exchange()
            assert 'openssl genpkey' in g.exchange('tools openssl')
        finally: g.close()


def test_real_tcp_tls_rejects_untrusted_certificate(server,tls_contexts):
    sc,cc=tls_contexts
    with tcp_server(server,ssl_context=sc) as address:
        with pytest.raises(ssl.SSLCertVerificationError): TCPGate(address,tls=True)


def _recording_http_server():
    """A loopback HTTP server that answers 200 and records each request's User-Agent."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get('User-Agent'))
            self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'{}')
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server,seen


def test_http_requests_name_the_harness_not_python_urllib():
    # Cloudflare's browser integrity check refuses urllib's default User-Agent with 403 (error 1010) on proxied
    # hosts (the wesupport-ai.com pages host and tile mirror, 2026-10-20): every harness request names itself.
    from aics_conformance import __version__
    from aics_conformance.client import HTTPTransport, USER_AGENT
    server,seen=_recording_http_server()
    try:
        url=f'http://127.0.0.1:{server.server_port}'
        client=JSONClient(url,pages=url)
        assert client.request('GET','/llms.txt',pages=True).status==200
        assert Tiles(url+'/tiles',transport=client.transport).checkpoint()==b'{}'
        assert HTTPTransport().request('GET',url+'/x',headers={'user-agent':'operator-choice/1'}).status==200
    finally: server.shutdown(); server.server_close()
    assert USER_AGENT.startswith(f'aics-conformance/{__version__} ')
    assert seen==[USER_AGENT,USER_AGENT,'operator-choice/1']
    assert not any(ua.startswith('Python-urllib') for ua in seen)
