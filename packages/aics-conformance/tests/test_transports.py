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
