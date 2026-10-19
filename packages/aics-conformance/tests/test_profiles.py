"""The contributions and owner-service profile (AICS-1+SUP-1, §20): the card of §20.9 and the §20.3 entries.

A real instance (WeSupport-AI) advertises AICS-1+SUP-1, so the harness verifies that profile when the operator pins
it (``Policy.profiles``) and refuses it otherwise, as a base-only client must (§20: report an unsupported profile).
"""
import pytest
from aics_conformance import verify
from aics_conformance.card import verify_card, card_spec
from aics_conformance.fakes import FakeServer
from aics_conformance.policy import Policy
from aics_conformance.protocol import Agent, J, H, U, envelope
from aics_conformance.schema import REFUSAL, SUP_REFUSAL, validate_entry


def sup_member(origin, **changes):
    s = dict(asset_hash=verify.sup_asset_hash(origin), contributions=[], intent_seconds=86400, claim_seconds=604800,
             record_seconds=31536000, storage=None)
    return s | changes


class SupServer(FakeServer):
    """The fake with an AICS-1+SUP-1 bootstrap card (``card_change`` applied before signing)."""
    def __init__(self, *faults, card_change=None):
        self.card_change = card_change
        super().__init__(*faults)
    def make_card(self):
        c = {k: v for k, v in super().make_card().items() if k != 'signatures'}
        c['spec'] = card_spec(('SUP-1',)); c['sup'] = sup_member(self.origin)
        c['reason_codes']['refusal'] = sorted(set(c['reason_codes']['refusal']) | set(SUP_REFUSAL))
        if self.card_change: self.card_change(c)
        protected = U(J(dict(alg='EdDSA', kid=self.policy_actor.kid, typ='JOSE')))
        c['signatures'] = [dict(protected=protected, signature=U(self.policy_actor.key.sign((protected + '.' + U(J(c))).encode())))]
        return c


def sup_context(server, profiles=('SUP-1',)):
    ctx = server.context(); ctx.policy.profiles = list(profiles); return ctx


def test_policy_profiles_are_known():
    trust = FakeServer().trust
    assert Policy(dict(trust), profiles=['SUP-1']).profiles == ['SUP-1']
    with pytest.raises(ValueError, match='unsupported profile'):
        Policy(dict(trust), profiles=['SWARMS-1'])


def test_a_sup_card_verifies_when_the_profile_is_pinned():
    c, hist, h = verify_card(sup_context(SupServer()))
    assert c['spec'] == 'AICS-1+SUP-1' and set(c['reason_codes']['refusal']) >= set(SUP_REFUSAL)


def test_a_base_only_harness_reports_the_unsupported_profile():
    with pytest.raises(ValueError, match='unsupported profile'):
        verify_card(sup_context(SupServer(), profiles=()))
    with pytest.raises(ValueError, match='not the pinned'):  # and a base card when SUP-1 is pinned
        verify_card(sup_context(FakeServer()))


SUP_CHANGES = {
    'asset': (lambda c: c['sup'].update(asset_hash='0' * 64), 'sup asset_hash'),
    'members': (lambda c: c['sup'].pop('storage'), 'sup member schema'),
    'windows': (lambda c: c['sup'].update(intent_seconds=700000), 'sup windows'),
    'record': (lambda c: c['sup'].update(record_seconds=31536001), 'sup windows'),
    'quota': (lambda c: c['sup'].update(storage=dict(free_quota_bytes=1024, unit_bytes=None, unit_amount=None)), 'free capsule quota'),
    'units': (lambda c: c['sup'].update(storage=dict(free_quota_bytes=65536, unit_bytes=1024, unit_amount=None)), 'storage units'),
    'network': (lambda c: c['sup'].update(contributions=[dict(network='Base USDC', asset='USDC', decimals=6, address='0xa', units_per_sup=10000)]), 'network id'),
    'twice': (lambda c: c['sup'].update(contributions=[dict(network='base-usdc', asset='USDC', decimals=6, address='0xa', units_per_sup=10000)] * 2), 'once'),
    'registry': (lambda c: c['reason_codes'].update(refusal=[x for x in c['reason_codes']['refusal'] if x != 'stale_quote']), 'reason registry differs'),
}


@pytest.mark.parametrize('change', sorted(SUP_CHANGES))
def test_the_sup_member_and_registry_are_section_20_9(change):
    fn, message = SUP_CHANGES[change]
    with pytest.raises(ValueError, match=message):
        verify_card(sup_context(SupServer(card_change=fn)))


# --- §20.3 entries replayed in index order --------------------------------------------------------------------

def sup_log(steps):
    """The fake's log (charter, card, a claim, a post, a tombstone) plus an account and ``steps(server, alice)``."""
    s = FakeServer(); alice = Agent()
    s.accept(envelope(alice, s.origin, 'name.claim', alice.claim(), s.now)); alice.previous = s.entries[-1]['payload']['envelope']
    for typ, signer, q, *body in steps(s, alice):
        e = s.accept(envelope(signer, s.origin, typ, q, s.now), *body)
        signer.previous = e['payload']['envelope']
    return s, alice


def owner_steps(server, alice, *, award=30, spend=20, account=None, asset=None):
    asset = asset or verify.sup_asset_hash(server.origin)
    body = J(dict(title='Write a verifier', text='In another language.'))
    task = dict(body_hash=H(body), size=len(body), asset_hash=asset, reward=30, max_awards=1, closes=server.now + 3600)
    work = J(dict(channel='tasks', title=None, text='done'))
    post = dict(channel_sha256=H(b'tasks'), parent_index=None, body_hash=H(work), size=len(work), title_sha256=None)
    n = len(server.entries)  # the task's index
    return [('sup.task', server.owner, task, body), ('post', alice, post, work),
            ('sup.credit', server.owner, dict(source='task', account_kid=account or alice.kid, task_index=n,
                                              submission_index=n + 1, asset_hash=asset, amount=award)),
            ('sup.spend', alice, dict(purpose='hosting', ref_index=None, asset_hash=asset, amount=spend, bytes=0))]


def history(server, profiles=('SUP-1',)):
    policy = server.configuration(); policy.profiles = list(profiles)
    return verify.History([J(e) for e in server.entries], policy)


def test_sup_entries_replay_with_the_profile():
    s, alice = sup_log(owner_steps)
    hist = history(s)
    assert hist.balances == {alice.name: 10} and len(hist.tasks) == 1


def test_sup_entries_are_refused_without_the_profile():
    s, _ = sup_log(owner_steps)
    with pytest.raises(ValueError, match='profile that is not active'):
        history(s, profiles=())


@pytest.mark.parametrize('kw,message', [
    (dict(spend=31), 'insufficient_balance'), (dict(award=29), 'award amount'),
    (dict(account=Agent().kid), 'names no account'), (dict(asset='0' * 64), 'asset_hash'),
])
def test_sup_rules_are_replayed(kw, message):
    s, _ = sup_log(lambda server, alice: owner_steps(server, alice, **kw))
    with pytest.raises(ValueError, match=message):
        history(s)


def append(server, signer, typ, q, body=None):
    e = server.accept(envelope(signer, server.origin, typ, q, server.now), body); signer.previous = e['payload']['envelope']
    return len(server.entries) - 1


def test_the_owner_action_market_is_replayed():
    """§20.4: a request post, the owner's quote and completion (report/owner_action), the requester's payment."""
    from aics_tlog import leaf_hash
    s, alice = sup_log(lambda server, alice: owner_steps(server, alice, spend=1))  # an award of 30, hosting 1
    asset = verify.sup_asset_hash(s.origin)
    req = J(dict(channel='owner', title=None, text='please'))
    r = append(s, alice, 'post', dict(channel_sha256=H(b'owner'), parent_index=None, body_hash=H(req), size=len(req),
                                      title_sha256=None), req)
    quote = dict(kind='owner_action', action='quote', request_hash=leaf_hash(J(s.entries[r])).hex(), result_hash=None,
                 asset_hash=asset, amount=5, quote_index=None)
    qi = append(s, s.owner, 'report', quote)
    done = J(dict(text='done'))
    ci = append(s, s.owner, 'report', dict(quote, action='complete', result_hash=H(done), quote_index=qi), done)
    pay = dict(purpose='owner_action', ref_index=ci, asset_hash=asset, amount=5, bytes=0)
    append(s, alice, 'sup.spend', pay)
    hist = history(s)
    assert hist.balances == {alice.name: 30 - 1 - 5} and hist.paid == {ci}
    append(s, alice, 'sup.spend', pay)  # the same completion paid again
    with pytest.raises(ValueError, match='paid twice'):
        history(s)


def test_a_completion_must_name_the_latest_quote():
    from aics_tlog import leaf_hash
    s, alice = sup_log(lambda server, alice: owner_steps(server, alice, spend=1))
    asset = verify.sup_asset_hash(s.origin)
    req = J(dict(channel='owner', title=None, text='please'))
    r = append(s, alice, 'post', dict(channel_sha256=H(b'owner'), parent_index=None, body_hash=H(req), size=len(req),
                                      title_sha256=None), req)
    quote = dict(kind='owner_action', action='quote', request_hash=leaf_hash(J(s.entries[r])).hex(), result_hash=None,
                 asset_hash=asset, amount=5, quote_index=None)
    first = append(s, s.owner, 'report', quote)
    append(s, s.owner, 'report', dict(quote, amount=6))  # a later quote replaces the price
    done = J(dict(text='done'))
    append(s, s.owner, 'report', dict(quote, action='complete', result_hash=H(done), quote_index=first), done)
    with pytest.raises(ValueError, match='stale_quote'):
        history(s)


def test_profile_refusal_codes_validate_only_with_the_profile():
    s = FakeServer(); a = Agent()
    e = envelope(a, s.origin, 'post', dict(channel_sha256='0' * 64, parent_index=None, body_hash='0' * 64, size=1,
                                           title_sha256=None), s.now)
    s.refuse(e, 'insufficient_balance')
    validate_entry(s.entries[-1], s.origin, ('SUP-1',))
    with pytest.raises(ValueError, match='refusal'):
        validate_entry(s.entries[-1], s.origin)
    assert not set(SUP_REFUSAL) & set(REFUSAL)
