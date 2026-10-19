"""Async transports. Local mode calls the repository fake in this process."""

import asyncio
import ssl
import time
from urllib.parse import urlsplit

import httpx
from aics_conformance.client import Response
from aics_conformance.protocol import DU


class HTTP:
    def __init__(self, concurrency=16, timeout=10):
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        )

    async def request(self, method, url, body=None, headers=None):
        # Bound downloaded bytes, including error pages; never follow redirects.
        async with self.client.stream(method, url, content=body, headers=headers) as r:
            chunks, size = [], 0
            async for chunk in r.aiter_bytes():
                size += len(chunk)
                if size > 16 * 1024 * 1024:
                    raise ValueError("response exceeds 16 MiB")
                chunks.append(chunk)
            return Response(r.status_code, b"".join(chunks), dict(r.headers))

    async def close(self):
        await self.client.aclose()


class Local:
    def __init__(self, fake, latency=0.0):
        self.fake, self.latency = fake, latency
        self.lock = asyncio.Lock()

    async def request(self, method, url, body=None, headers=None):
        await asyncio.sleep(self.latency)
        async with self.lock:
            self.fake.now = int(time.time())
            return self.fake.request(method, url, body, headers)

    async def close(self):
        pass


class HTTPGate:
    def __init__(self, transport, url):
        self.transport, self.url, self.session = transport, url, None

    async def exchange(self, line=None):
        raw = (f"session {self.session}\n" if self.session else "") + (line or "") + "\n"
        response = await self.transport.request(
            "POST", self.url, raw.encode(), {"Content-Type": "text/plain; charset=utf-8"}
        )
        if response.status == 200:
            text = response.text()
            if text.startswith("session "):
                first, text = text.split("\n", 1)
                self.session = first[8:]
                if len(DU(self.session)) != 16:
                    raise ValueError("invalid gate session")
            response = Response(response.status, text.encode(), response.headers)
        return response

    async def close(self):
        pass


class LocalTCPGate:
    def __init__(self, transport):
        self.transport = transport
        self.gate = transport.fake.tcp_gate(plain=True)

    @property
    def session(self):
        return self.gate.session

    async def exchange(self, line=None):
        await asyncio.sleep(self.transport.latency)
        async with self.transport.lock:
            self.transport.fake.now = int(time.time())
            return Response(200, self.gate.exchange(line).encode(), {})

    async def close(self):
        self.gate.close()


class TCPGate:
    def __init__(self, url):
        self.url, self.session = urlsplit(url), None
        self.reader, self.writer = None, None

    async def exchange(self, line=None):
        if self.writer is None:
            secure = self.url.scheme == "tls"
            self.reader, self.writer = await asyncio.open_connection(
                self.url.hostname,
                self.url.port or (7700 if secure else 7701),
                ssl=ssl.create_default_context() if secure else None,
                server_hostname=self.url.hostname if secure else None,
                limit=131074,
            )
        if line is not None:
            self.writer.write((line + "\n").encode())
            await self.writer.drain()
        chunks, size = [], 0
        while True:
            raw = await self.reader.readline()
            if not raw:
                raise EOFError("gate closed before prompt")
            size += len(raw)
            if size > 2 * 1024 * 1024:
                raise ValueError("gate reply exceeds bound")
            chunks.append(raw)
            if raw.rstrip(b"\r\n") == b">":
                break
        text = b"".join(chunks).decode()
        if text.startswith("session "):
            first, text = text.split("\n", 1)
            self.session = first[8:]
            if len(DU(self.session)) != 16:
                raise ValueError("invalid gate session")
        return Response(200, text.encode(), {})

    async def close(self):
        if self.writer:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 1)
            except (OSError, TimeoutError):
                pass
