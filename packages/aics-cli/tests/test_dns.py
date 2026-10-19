"""The stdlib DNS TXT resolver against a local fake DNS server."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from aics_cli.dnstxt import (
    FLAG_AD,
    FLAG_QR,
    FLAG_TC,
    build_query,
    encode_name,
    lookup_txt,
    lookup_txt_stdlib,
    parse_response,
)
from aics_cli.errors import DnsError


def _txt_rdata(strings: list[bytes]) -> bytes:
    return b"".join(bytes([len(s)]) + s for s in strings)


def make_answer(query: bytes, records: list[list[bytes]], *, rcode: int = 0, tc: bool = False,
                ad: bool = True, cname: bool = False) -> bytes:
    qid = struct.unpack(">H", query[:2])[0]
    # question section = everything after the header up to the end of QTYPE/QCLASS
    off = 12
    while query[off] != 0:
        off += query[off] + 1
    question = query[12:off + 5]
    flags = FLAG_QR | 0x0100 | 0x0080 | rcode | (FLAG_TC if tc else 0) | (FLAG_AD if ad else 0)
    answers = b""
    count = 0
    if cname:  # a CNAME first, then TXT under a compressed owner name
        target = encode_name("target.example")
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target
        count += 1
    for strings in ([] if tc else records):
        rdata = _txt_rdata(strings)
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(rdata)) + rdata  # pointer to the qname
        count += 1
    header = struct.pack(">HHHHHH", qid, flags, 1, count, 0, 0)
    return header + question + answers


class FakeDnsServer:
    def __init__(self, records: list[list[bytes]], *, rcode: int = 0, truncate_udp: bool = False,
                 cname: bool = False) -> None:
        self.records, self.rcode, self.truncate_udp, self.cname = records, rcode, truncate_udp, cname
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(1)
        self.queries: list[bytes] = []
        self.tcp_used = False
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()

    def _serve_udp(self) -> None:
        while True:
            try:
                q, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            self.queries.append(q)
            self.udp.sendto(make_answer(q, self.records, rcode=self.rcode, tc=self.truncate_udp,
                                        cname=self.cname), addr)

    def _serve_tcp(self) -> None:
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            with conn:
                n = struct.unpack(">H", conn.recv(2))[0]
                q = b""
                while len(q) < n:
                    q += conn.recv(n - len(q))
                self.tcp_used = True
                a = make_answer(q, self.records, rcode=self.rcode, cname=self.cname)
                conn.sendall(struct.pack(">H", len(a)) + a)

    def close(self) -> None:
        self.udp.close()
        self.tcp.close()


@pytest.fixture
def server():
    servers: list[FakeDnsServer] = []

    def make(*args, **kw) -> FakeDnsServer:
        s = FakeDnsServer(*args, **kw)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def test_multi_string_records_are_joined(server):
    s = server([[b"v=aics1; log=abc", b"def; quorum=0"], [b"other record"]])
    res = lookup_txt_stdlib("_aics.log.test", nameserver=f"127.0.0.1:{s.port}")
    assert res.records == ["v=aics1; log=abcdef; quorum=0", "other record"]
    assert res.ad is True and res.resolver.startswith("stdlib:127.0.0.1")
    q = s.queries[0]
    assert struct.unpack(">H", q[2:4])[0] & FLAG_AD  # asks for the AD bit
    assert b"\x05_aics\x03log\x04test\x00\x00\x10\x00\x01" in q


def test_truncated_udp_retries_over_tcp(server):
    s = server([[b"v=aics1; " + b"x" * 200, b"y" * 200]], truncate_udp=True)
    res = lookup_txt_stdlib("_aics.log.test", nameserver=f"127.0.0.1:{s.port}")
    assert s.tcp_used
    assert res.records == ["v=aics1; " + "x" * 200 + "y" * 200]


def test_nxdomain_is_an_empty_answer(server):
    s = server([], rcode=3)
    res = lookup_txt_stdlib("_aics.nowhere.test", nameserver=f"127.0.0.1:{s.port}")
    assert res.records == [] and res.nxdomain


def test_servfail_raises(server):
    s = server([], rcode=2)
    with pytest.raises(DnsError):
        lookup_txt_stdlib("_aics.log.test", nameserver=f"127.0.0.1:{s.port}", timeout=1)


def test_cname_answers_are_skipped(server):
    s = server([[b"v=aics1"]], cname=True)
    res = lookup_txt("_aics.log.test", nameserver=f"127.0.0.1:{s.port}", use_dnspython=False)
    assert res.records == ["v=aics1"]


def test_parse_response_rejects_wrong_id_and_loops():
    q = build_query("a.test", 7)
    a = make_answer(q, [[b"x"]])
    with pytest.raises(DnsError, match="ID"):
        parse_response(a, 8)
    loop = struct.pack(">HHHHHH", 7, FLAG_QR, 0, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 10
    with pytest.raises(DnsError):
        parse_response(loop, 7)


def test_bad_names_are_refused():
    with pytest.raises(DnsError):
        encode_name("a" * 64 + ".test")


def test_dnspython_path_when_installed(server):
    pytest.importorskip("dns.resolver")
    s = server([[b"v=aics1; quorum=0"]])
    res = lookup_txt("_aics.log.test", nameserver=f"127.0.0.1:{s.port}", use_dnspython=True)
    assert res.records == ["v=aics1; quorum=0"] and res.resolver == "dnspython"


def test_policy_init_over_the_stdlib_resolver(server, h):
    """End to end: the trust bundle TXT (longer than one 255-byte string) from a real UDP DNS exchange."""
    import json

    from aics_cli.commands import Env
    from aics_cli.dnstxt import lookup_txt as real_lookup

    from conftest import CARD_URL, DOMAIN, Instance, Log

    inst = Instance(Log(3))
    txt = inst.bundle.txt.encode()
    assert len(txt) > 255
    s = server([[txt[i:i + 255] for i in range(0, len(txt), 255)], [b"v=spf1 -all"]])
    h.fetcher.set(CARD_URL, json.dumps(inst.card))
    seen = []

    def resolve(name, *, nameserver=None):
        seen.append((name, nameserver))
        return real_lookup(name, nameserver=nameserver, use_dnspython=False)

    import io

    from aics_cli.cli import run

    env = Env(fetcher=h.fetcher, resolve_txt=resolve, clock=lambda: h.clock[0], home=h.home)
    buf = io.StringIO()
    code = run(["policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", "--nameserver",
                f"127.0.0.1:{s.port}", "--json"], env=env, out=buf)
    out = json.loads(buf.getvalue())
    assert code == 0, out
    assert seen == [(f"_aics.{DOMAIN}", f"127.0.0.1:{s.port}")]
    assert out["policy"]["trust_bundle_sha256"] == inst.bundle.sha256
    assert out["dns"]["dnssec_ad"] is True and not any("DNSSEC" in w for w in out["warnings"])
