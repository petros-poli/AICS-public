"""AICS-1 0.2-draft wire forms the harness reads and writes: trust bundle (§6.4), request binding (§12.1), card
(§13.1), verification package (§14.3) and the refusal registry (§17.2)."""
import copy
import json
import pytest
from aics_identity import http_signatures, keys
from aics_tlog import Checkpoint, parse_vkey, sign_checkpoint
from aics_conformance import checks, guarantees, verify  # noqa: F401 (checks and guarantees register CHECKS)
from aics_conformance.card import SPEC_VERSIONS, VERSION, verify_card
from aics_conformance.core import CHECKS
from aics_conformance.fakes import FakeServer
from aics_conformance.policy import Policy
from aics_conformance.protocol import Agent, J, U, envelope
from aics_conformance.schema import ENUMS, REFUSAL, validate_entry


def check(id): return next(c for c in CHECKS if c.id == id)


# --- §6.4 trust bundle -----------------------------------------------------------------------------------------

def bad_bundles(trust):
    other = Agent().kid
    return {
        'missing-v': {k: v for k, v in trust.items() if k != 'v'},
        'unknown-member': {**trust, 'note': 'x'},
        'v-2': {**trust, 'v': 2},
        'v-true': {**trust, 'v': True},
        'policy-is-owner': {**trust, 'owner_kid': trust['policy_kid']},
        'uppercase-card-hash': {**trust, 'bootstrap_card_hash': 'AB' * 32},
        'origin-with-scheme': {**trust, 'origin': 'https://' + trust['origin']},
        'origin-trailing-slash': {**trust, 'origin': trust['origin'] + '/'},
        'policy-not-a-did-key': {**trust, 'policy_kid': 'z' + other[9:]},
        'log-key-is-policy-key': {**trust, 'policy_kid': keys.did_key(keys.public_key_from_bytes(
            parse_vkey(trust['log_vkey']).public_key))},
    }


def test_policy_accepts_the_aics1_trust_bundle(server):
    Policy(dict(server.trust))


@pytest.mark.parametrize('case', ['missing-v', 'unknown-member', 'v-2', 'v-true', 'policy-is-owner',
                                  'uppercase-card-hash', 'origin-with-scheme', 'origin-trailing-slash',
                                  'policy-not-a-did-key', 'log-key-is-policy-key'])
def test_policy_refuses_what_section_6_4_refuses(server, case):
    with pytest.raises(ValueError):
        Policy(bad_bundles(server.trust)[case])


# --- §12.1 Content-Digest over the bytes as received --------------------------------------------------------------

def signed_request(server, raw, *, signed=None):
    a = Agent(); e = envelope(a, server.origin, 'name.claim', a.claim(), server.now); p = e['protected']
    headers = http_signatures.sign_request('POST', 'https://fake/v2/entries', {'Content-Type': 'application/json'},
                                           (signed or raw)(e), key=a.key, keyid=p['kid'], created=p['created'],
                                           expires=p['expires'], nonce=p['nonce'], tag='aics', label='aics',
                                           components=http_signatures.AICS_COMPONENTS)
    return e, raw(e), headers


def outcome(r):
    return 'accepted' if r.status == 202 else json.loads(r.body)['entry']['payload']['reason_code']


def test_content_digest_is_over_the_request_bytes(server):
    pretty = lambda e: json.dumps({'envelope': e, 'body': None}, indent=1).encode()
    jcs = lambda e: J({'envelope': e, 'body': None})
    e, body, headers = signed_request(server, pretty)  # a valid request whose JSON is not JCS
    assert outcome(server.request('POST', 'https://fake/v2/entries', body, headers)) == 'accepted'
    e, body, headers = signed_request(server, lambda e: jcs(e) + b' ', signed=jcs)  # bytes changed after signing
    assert outcome(server.request('POST', 'https://fake/v2/entries', body, headers)) == 'bad_signature'
    with pytest.raises(TypeError, match='content='):
        server.submit(e, None, headers, 'https://fake/v2/entries')


# --- §13.1 card -----------------------------------------------------------------------------------------------

def resigned(server, **changes):
    c = {k: v for k, v in copy.deepcopy(server.card).items() if k != 'signatures'} | changes
    protected = U(J(dict(alg='EdDSA', kid=server.policy_actor.kid, typ='JOSE')))
    c['signatures'] = [dict(protected=protected, signature=U(server.policy_actor.key.sign((protected + '.' + U(J(c))).encode())))]
    return c


def test_the_card_is_the_0_2_draft_card(ctx, server):
    assert (server.card['version'], server.card['spec_versions']) == ('0.2-draft', SPEC_VERSIONS) and VERSION == '0.2-draft'
    assert set(SPEC_VERSIONS.values()) == {'1.0.0', '1.1.0'} and SPEC_VERSIONS['tlog-witness'] == '1.1.0'
    verify_card(ctx)


@pytest.mark.parametrize('changes,message', [
    (dict(version='0.1-draft', spec_versions={k: '1.0.0' for k in SPEC_VERSIONS}), "card version must be '0.2-draft'"),
    (dict(spec_versions={**SPEC_VERSIONS, 'tlog-checkpoint': '1.0.0'}), 'spec versions'),
])
def test_other_card_versions_are_refused(server, changes, message):
    ctx = server.context()
    with pytest.raises(ValueError, match=message):
        verify_card(ctx, resigned(server, **changes))


def card_server(change):
    """A fake whose logged bootstrap card is its usual card changed by ``change`` (and signed again)."""
    class Server(FakeServer):
        def make_card(self):
            c = {k: v for k, v in super().make_card().items() if k != 'signatures'}; change(c)
            protected = U(J(dict(alg='EdDSA', kid=self.policy_actor.kid, typ='JOSE')))
            c['signatures'] = [dict(protected=protected, signature=U(self.policy_actor.key.sign((protected + '.' + U(J(c))).encode())))]
            return c
    return Server()


REFUSAL_CHANGES = {
    'adds-invalid_signature': lambda codes: codes + ['invalid_signature'],
    'drops-malformed': lambda codes: [c for c in codes if c != 'malformed'],
    'unknown-secret-pattern': lambda codes: codes + ['secret_format:no_such_pattern'],
    'drops-secret-pattern': lambda codes: [c for c in codes if c != 'secret_format:github_pat'],
    'adds-swarm-code': lambda codes: codes + ['swarm_stale'],
    'duplicate': lambda codes: codes + ['rate'],
}


@pytest.mark.parametrize('change', sorted(REFUSAL_CHANGES))
def test_card_reason_registries_are_section_17_2(change):
    """§13.1: the §17.2 registries plus exactly the card's own secret_format:<id> instances (closed expansion)."""
    server = card_server(lambda c: c['reason_codes'].update(refusal=REFUSAL_CHANGES[change](c['reason_codes']['refusal'])))
    with pytest.raises(ValueError, match='reason registry differs'):
        verify_card(server.context())


def test_card_reason_registries_are_sets():
    verify_card(card_server(lambda c: c['reason_codes'].update(refusal=list(reversed(c['reason_codes']['refusal'])))).context())


@pytest.mark.parametrize('patterns', [[{'id': 'GitHub', 'pattern_hash': '0' * 64}], [{'id': 'github_pat'}],
                                      [{'id': 'github_pat', 'pattern_hash': '0' * 64}] * 2])
def test_card_secret_patterns_are_checked(patterns):
    with pytest.raises(ValueError, match='secret pattern schema'):
        verify_card(card_server(lambda c: c.update(secret_patterns=patterns)).context())


# --- §14.3 verification package -------------------------------------------------------------------------------

def test_the_package_has_exactly_the_section_14_3_members(ctx):
    result = check('G8').run(ctx); assert result['verdict'] == 'pass', result['details']
    package = result['details']['package']
    assert tuple(package) == verify.PACKAGE_MEMBERS
    verify.offline_package(package, ctx.policy, ctx.now())
    for changed in ({**package, 'trust_policy': dict(witness_vkeys=[], quorum=0, max_checkpoint_age=300)},
                    {k: v for k, v in package.items() if k != 'checkpoint_notes'}):
        with pytest.raises(ValueError, match='exactly'):
            verify.offline_package(changed, ctx.policy, ctx.now())


def test_package_checkpoint_notes_must_agree_with_the_prefix(ctx, server):
    package = check('G8').run(ctx)['details']['package']
    size = len(package['entry_prefix'])  # a log-signed note of the prefix's size with another root
    forked = sign_checkpoint(Checkpoint(server.origin, size, bytes(32)), server.log, server.origin).to_bytes()
    with pytest.raises(ValueError, match='split-proven'):
        verify.offline_package({**package, 'checkpoint_notes': [U(forked)]}, ctx.policy, ctx.now())


# --- §17.2 refusal registry -----------------------------------------------------------------------------------

CHARTER = ('secret_format', 'rate', 'seq', 'fork', 'sig', 'no_grant', 'size', 'format', 'name', 'key_state', 'poll_rule')


def test_the_refusal_registry_is_section_17_2(server):
    assert len(REFUSAL) == len(set(REFUSAL)) == 41 and ENUMS['refusal'] == set(REFUSAL)
    assert set(CHARTER) <= ENUMS['refusal'] and 'invalid_signature' not in ENUMS['refusal']
    assert server.card['reason_codes']['refusal'] == sorted(REFUSAL) + ['secret_format:github_pat']


@pytest.mark.parametrize('code', CHARTER + ('rate_limit', 'secret_format:github_pat'))
def test_refusal_leaves_carry_registered_codes(server, code):
    a = Agent(); e = envelope(a, server.origin, 'post', dict(channel_sha256='0' * 64, parent_index=None,
                                                             body_hash='0' * 64, size=1, title_sha256=None), server.now)
    server.refuse(e, code); validate_entry(server.entries[-1], server.origin)


@pytest.mark.parametrize('code', ['invalid_signature', 'whatever', 'secret_format:'])
def test_refusal_leaves_refuse_unregistered_codes(server, code):
    a = Agent(); e = envelope(a, server.origin, 'post', dict(channel_sha256='0' * 64, parent_index=None,
                                                             body_hash='0' * 64, size=1, title_sha256=None), server.now)
    server.refuse(e, code)
    with pytest.raises(ValueError, match='refusal'):
        validate_entry(server.entries[-1], server.origin)
