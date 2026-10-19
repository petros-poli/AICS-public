"""AICS-1 §4.3 as amended (DECISIONS row 26): a (kid, nonce) is used once per log, also after its record expires.

History refuses a prefix in which an accepted envelope carries a (kid, nonce) that an earlier leaf carries,
as an envelope or as a refusal's attempt tuple, however long ago it expired; the fake refuses such a write with
code replay, as aics-server does.
"""
import pytest
from aics_conformance import verify
from aics_conformance.checks.negative import post_attempt
from aics_conformance.fakes import FakeServer
from aics_conformance.protocol import Agent, J, H, U, envelope


def post_q(text='x'):
    body = J(dict(channel='conformance', title=None, text=text))
    return dict(channel_sha256=H(b'conformance'), parent_index=None, body_hash=H(body), size=len(body),
                title_sha256=None), body


def history(server):
    return verify.History([J(e) for e in server.entries], server.configuration())


def accept(server, agent, typ, q, body=None, **kw):
    e = server.accept(envelope(agent, server.origin, typ, q, server.now, **kw), body)
    agent.previous = e['payload']['envelope']
    return len(server.entries) - 1


def claimed(server):
    a = Agent(); accept(server, a, 'name.claim', a.claim()); return a


def test_a_fresh_nonce_after_expiry_is_accepted():
    s = FakeServer(); a = claimed(s)
    accept(s, a, 'post', *post_q())
    s.sleep(3600)
    accept(s, a, 'post', *post_q('y'))
    history(s)


def test_a_nonce_reused_after_its_record_expired_is_a_replay():
    s = FakeServer(); a = claimed(s)
    first = accept(s, a, 'post', *post_q())
    nonce = s.entries[first]['payload']['envelope']['protected']['nonce']
    s.sleep(3600)  # the first record expired long ago
    accept(s, a, 'post', *post_q('y'), nonce=nonce)
    with pytest.raises(ValueError, match='reused nonce'):
        history(s)


def test_a_refused_attempt_uses_its_nonce_for_good():
    s = FakeServer(); a = claimed(s)
    q, body = post_q()
    attempt = envelope(a, s.origin, 'post', q, s.now)
    s.refuse(attempt, 'malformed')
    s.sleep(3600)
    accept(s, a, 'post', q, body, nonce=attempt['protected']['nonce'])
    with pytest.raises(ValueError, match='reused nonce'):
        history(s)


def test_the_fake_refuses_a_reuse_after_expiry_with_code_replay():
    s = FakeServer(); ctx = s.context()
    a = ctx.new_agent(); e, b = post_attempt(ctx, a)
    entry, note = ctx.accepted(ctx.client.submit(e, a.key, b), a, e); i = ctx.follow(entry, note)
    s.sleep(3600)
    again, b2 = post_attempt(ctx, a, text='the same nonce an hour later', nonce=e['protected']['nonce'])
    assert again['protected']['created'] > e['protected']['expires']
    refusal = ctx.refused(ctx.client.submit(again, a.key, b2), again, 'replay')
    assert refusal['payload']['conflict_index'] == i
