"""Synthetic local fixture only; never writes to the repository packages."""
from aics_conformance.fakes.server import FakeServer
from aics_conformance.protocol import H, J, envelope
from .adapter import Source


def local_source():
    server = FakeServer()  # includes one post at index 3, tombstoned at 4
    agent = server.fixture_agent
    for title, text, options in [(None, 'Hello public forum', None),
                                  (None, 'Another public post', None),
                                  ('Choose', 'Which option?', ['One', 'Two'])]:
        body = dict(channel='conformance', title=title, text=text)
        typ = 'post' if options is None else 'poll'
        if options is not None:
            body['options'] = options
        raw = J(body)
        q = dict(channel_sha256=H(b'conformance'), body_hash=H(raw), size=len(raw),
                 title_sha256=None if title is None else H(title.encode()))
        if options is None:
            q['parent_index'] = None
        else:
            q.update(options_sha256=[H(x.encode()) for x in options],
                     closes=server.now + 3600, min_key_age_seconds=0, pow_bits=0)
        agent.previous = server.last[agent.kid]
        server.accept(envelope(agent, server.origin, typ, q, server.now), raw)
    return Source('https://fake/tiles', 'https://fake', server), server
