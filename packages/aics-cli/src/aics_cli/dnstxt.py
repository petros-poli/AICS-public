"""DNS TXT lookup: dnspython when installed (``pip install 'aics[dns]'``),
otherwise a small stdlib resolver (UDP with EDNS0, TCP on truncation).

Neither path validates DNSSEC itself.  The query sets the AD bit and the
result reports whether the resolver claimed the answer was authenticated
(``ad``); that claim is only as good as the path to the resolver.

The stdlib resolver accepts a response only if it answers the question that
was asked: the same ID, exactly one question with the queried name
(compared case-insensitively), type TXT and class IN, and it takes TXT
records only from the queried name or a CNAME target reached from it in the
answer section.
"""

from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass, field

from .errors import DnsError

TYPE_CNAME = 5
TYPE_TXT = 16
TYPE_OPT = 41
CLASS_IN = 1
FLAG_QR = 0x8000
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_AD = 0x0020
RCODE_NXDOMAIN = 3


@dataclass
class TxtResult:
    name: str
    records: list[str] = field(default_factory=list)  # each record's strings joined
    ad: bool = False  # resolver said "authenticated data" (DNSSEC); not checked by us
    resolver: str = ""  # "dnspython" or "stdlib:<ip>:<port>"
    nxdomain: bool = False


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def lookup_txt(name: str, *, nameserver: str | None = None, timeout: float = 5.0,
               use_dnspython: bool | None = None) -> TxtResult:
    """TXT records at ``name``.  ``nameserver`` is ``ip`` or ``ip:port``
    (``[v6]:port``).  No record or NXDOMAIN returns an empty list; other
    failures raise :class:`DnsError`."""
    name = name.rstrip(".")
    if use_dnspython is None:
        try:
            import dns.resolver

            use_dnspython = True
        except ImportError:
            use_dnspython = False
    if use_dnspython:
        return _lookup_dnspython(name, nameserver, timeout)
    return lookup_txt_stdlib(name, nameserver=nameserver, timeout=timeout)


def _split_ns(nameserver: str) -> tuple[str, int]:
    ns = nameserver.strip()
    if ns.startswith("["):
        host, _, rest = ns[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else 53
        return host, port
    if ns.count(":") == 1:
        host, port = ns.split(":")
        return host, int(port)
    return ns, 53


def _lookup_dnspython(name: str, nameserver: str | None, timeout: float) -> TxtResult:
    import dns.exception
    import dns.flags
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver is not None:
        host, port = _split_ns(nameserver)
        resolver.nameservers = [host]
        resolver.port = port
    resolver.lifetime = timeout
    resolver.flags = dns.flags.RD | dns.flags.AD
    try:
        answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return TxtResult(name=name, resolver="dnspython", nxdomain=True)
    except dns.exception.DNSException as exc:
        raise DnsError(f"TXT lookup for {name} failed: {exc}") from None
    records: list[str] = []
    for rr in answer:
        try:
            records.append(b"".join(rr.strings).decode("utf-8"))
        except UnicodeDecodeError:
            continue
    ad = bool(answer.response.flags & dns.flags.AD) if answer.response is not None else False
    return TxtResult(name=name, records=records, ad=ad, resolver="dnspython")


# ---------------------------------------------------------------------------
# stdlib resolver
# ---------------------------------------------------------------------------


def system_nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    out.append(parts[1])
    except OSError:
        pass
    return out


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise DnsError(f"bad DNS label in {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > 255:
        raise DnsError(f"DNS name too long: {name!r}")
    return bytes(out)


def build_query(name: str, qid: int, *, qtype: int = TYPE_TXT, udp_size: int = 1232) -> bytes:
    header = struct.pack(">HHHHHH", qid, FLAG_RD | FLAG_AD, 1, 0, 0, 1)
    question = encode_name(name) + struct.pack(">HH", qtype, CLASS_IN)
    opt = b"\x00" + struct.pack(">HHIH", TYPE_OPT, udp_size, 0, 0)  # EDNS0, no DO bit
    return header + question + opt


def _read_name(msg: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumps = 0
    end: int | None = None
    while True:
        if off >= len(msg):
            raise DnsError("truncated DNS name")
        length = msg[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DnsError("truncated DNS pointer")
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | msg[off + 1]
            jumps += 1
            if jumps > 32:
                raise DnsError("DNS name compression loop")
            continue
        if length & 0xC0:
            raise DnsError("unsupported DNS label type")
        off += 1
        if length == 0:
            break
        labels.append(msg[off:off + length].decode("ascii", errors="replace"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def _norm(name: str) -> str:
    """A name as it appears on the wire (IDNA labels), lowercased, no final dot."""
    labels = []
    for label in name.rstrip(".").split("."):
        if any(ord(c) > 127 for c in label):
            try:
                label = label.encode("idna").decode("ascii")
            except UnicodeError:
                pass
        labels.append(label.lower())
    return ".".join(labels)


def parse_response(msg: bytes, qid: int, qname: str | None = None,
                   qtype: int = TYPE_TXT) -> tuple[int, int, list[bytes]]:
    """Returns (flags, rcode, [TXT rdata strings joined per record]).

    The response must carry exactly one question; with ``qname`` it must be
    that name (case-insensitive), ``qtype`` and class IN, and only TXT
    records owned by ``qname`` or by a CNAME target in the answer chain
    from it are returned."""
    if len(msg) < 12:
        raise DnsError("short DNS response")
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise DnsError("DNS response ID mismatch")
    if not flags & FLAG_QR:
        raise DnsError("DNS message is not a response")
    rcode = flags & 0x000F
    if qd != 1:
        raise DnsError(f"DNS response carries {qd} questions, not the one that was asked")
    name, off = _read_name(msg, 12)
    if off + 4 > len(msg):
        raise DnsError("truncated DNS question")
    rqtype, rqclass = struct.unpack(">HH", msg[off:off + 4])
    off += 4
    if qname is not None and (_norm(name) != _norm(qname) or rqtype != qtype or rqclass != CLASS_IN):
        raise DnsError(f"DNS response answers another question ({name!r} type {rqtype} class {rqclass})")
    answers: list[tuple[str, int, int, int, bytes]] = []  # owner, type, class, rdata offset, rdata
    for _ in range(an):
        owner, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise DnsError("truncated DNS answer")
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if len(rdata) != rdlen:
            raise DnsError("truncated DNS rdata")
        answers.append((_norm(owner), rtype, rclass, off, rdata))
        off += rdlen
    allowed = {_norm(qname if qname is not None else name)}
    changed = True
    while changed:  # follow CNAMEs from the queried name, in any order
        changed = False
        for owner, rtype, rclass, roff, _rdata in answers:
            if rtype == TYPE_CNAME and rclass == CLASS_IN and owner in allowed:
                target = _norm(_read_name(msg, roff)[0])
                if target not in allowed:
                    allowed.add(target)
                    changed = True
    records: list[bytes] = []
    for owner, rtype, rclass, _roff, rdata in answers:
        if rtype != TYPE_TXT or rclass != CLASS_IN or owner not in allowed:
            continue  # a CNAME on the way, or a record about some other name
        parts: list[bytes] = []
        i = 0
        while i < len(rdata):
            n = rdata[i]
            i += 1
            if i + n > len(rdata):
                raise DnsError("malformed TXT character-string")
            parts.append(rdata[i:i + n])
            i += n
        records.append(b"".join(parts))
    return flags, rcode, records


def _query_udp(query: bytes, addr: tuple, family: int, qid: int, timeout: float) -> bytes:
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.connect(addr)  # only accept datagrams from the server we asked
        s.send(query)
        while True:
            data = s.recv(65535)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                return data


def _query_tcp(query: bytes, addr: tuple, family: int, timeout: float) -> bytes:
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(addr)
        s.sendall(struct.pack(">H", len(query)) + query)
        head = _recv_exact(s, 2)
        (n,) = struct.unpack(">H", head)
        return _recv_exact(s, n)


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DnsError("DNS TCP connection closed early")
        buf += chunk
    return bytes(buf)


def lookup_txt_stdlib(name: str, *, nameserver: str | None = None, timeout: float = 5.0) -> TxtResult:
    servers = [nameserver] if nameserver else system_nameservers()
    if not servers:
        raise DnsError("no nameserver configured (no /etc/resolv.conf); pass --nameserver")
    last: Exception | None = None
    for ns in servers:
        host, port = _split_ns(ns)
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        except socket.gaierror as exc:
            last = exc
            continue
        family, _, _, _, addr = infos[0]
        qid = secrets.randbelow(65536)
        query = build_query(name, qid)
        try:
            data = _query_udp(query, addr, family, qid, timeout)
            flags, rcode, records = parse_response(data, qid, name)
            if flags & FLAG_TC:
                data = _query_tcp(query, addr, family, timeout)
                flags, rcode, records = parse_response(data, qid, name)
        except (OSError, DnsError) as exc:
            last = exc
            continue
        label = f"stdlib:{host}:{port}"
        if rcode == RCODE_NXDOMAIN:
            return TxtResult(name=name, resolver=label, nxdomain=True, ad=bool(flags & FLAG_AD))
        if rcode != 0:
            last = DnsError(f"DNS server {host} answered rcode {rcode}")
            continue
        texts: list[str] = []
        for r in records:
            try:
                texts.append(r.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return TxtResult(name=name, records=texts, ad=bool(flags & FLAG_AD), resolver=label)
    raise DnsError(f"TXT lookup for {name} failed: {last}")
