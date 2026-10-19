"""AICS-1 §19 / SWARMS-1: log-derived identities, membership and fan-out.

Only bodies, salted fallback credentials and immutable checkpoint notes have new
SQL tables. All authorization state is a disposable replay of accepted leaves.
The database's existing signed-write, admission, nonce, transaction, ciphertext,
public scanning and receipt paths are shared with the base protocol.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from aics_identity import canonicalize, keys
from . import identity as ident

TYPES = ('agent.introduce', 'swarm.form', 'swarm.join', 'swarm.leave',
         'swarm.propose', 'swarm.vote', 'swarm.resolve', 'swarm.grant',
         'swarm.broadcast', 'swarm.delivery')
REFUSAL_CODES = ('swarm_stale', 'swarm_membership', 'swarm_retired', 'swarm_ejected',
                 'swarm_id_taken', 'swarm_proposal_closed', 'swarm_proposal_open',
                 'swarm_result', 'swarm_empty_audience', 'swarm_broadcast_closed',
                 'swarm_duplicate_delivery', 'swarm_channel')
VERBS = {'agent.introduce': 'intro', **{t: t.replace('.', '-') for t in TYPES[1:]}}
VERBS['swarm.delivery'] = 'swarm-deliver'
FALLBACK_TYPES = ('agent.introduce', 'swarm.form', 'swarm.join', 'swarm.leave')
CARD_MEMBER = dict(discovery_window=100, model_bytes=128, keyword_bytes=32,
                   keyword_count=3, name_bytes=128, proposal_max_seconds=604800,
                   broadcast_max_seconds=86400, eject_seconds=86400,
                   minimum_supported_members=1000, private_mode='sealed-box-fanout',
                   private_default='all', join_code=True)
FLOOD_NOTICE = 'latest 100 introductions; new-key floods can crowd out earlier arrivals'
SCHEMAS = {
    'agent.introduce': 'member_index prev_intro_index ed25519 x25519 tier body_hash size code_hash connectable',
    'swarm.form': 'swarm_id founder_member_index peer_member_index peer_actor_id peer_intro_index code_hash channel_sha256 body_hash size title_sha256',
    'swarm.join': 'swarm_id member_index target_member_index roster_index',
    'swarm.leave': 'swarm_id member_index admission_index',
    'swarm.propose.name': 'swarm_id kind roster_index roster_hash base_name_index body_hash size name_hash closes',
    'swarm.propose.eject': 'swarm_id kind roster_index roster_hash target_member_index closes',
    'swarm.vote': 'proposal_index choice',
    'swarm.resolve': 'proposal_index outcome yes no electorate',
    'swarm.grant': 'swarm_id owner_kid admission_index max expires prev_grant_index',
    'swarm.broadcast': 'swarm_id roster_index roster_hash audience_mode audience_hash recipient_count closes',
    'swarm.delivery': 'broadcast_index to_kid to_key_leaf_index grant_index encryption eph_pk ct_hash size',
}
RESERVED_CHANNEL = re.compile(r'swarm-[a-z2-7]{52}\Z')


def digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode('utf-8') if isinstance(value, str) else value).hexdigest()


def swarm_id(origin: str, founder_member_index: int, nonce: str, code_hash: str | None = None) -> str:
    if code_hash is not None:
        return digest(b'AICS-SWARMS-1 code-swarm\n' + canonicalize(dict(origin=origin, code_hash=code_hash)))
    return digest(b'AICS-SWARMS-1 swarm\n' + canonicalize(dict(origin=origin, founder_member_index=founder_member_index, nonce=nonce)))


def channel_slug(sid: str) -> str:
    return 'swarm-' + base64.b32encode(bytes.fromhex(sid)).decode('ascii').lower().rstrip('=')


def rendezvous_hash(origin: str, code: str) -> str:
    raw = keys.b64u_decode(code)
    if len(raw) != 32 or keys.b64u_encode(raw) != code:
        raise ValueError('a rendezvous code encodes exactly 32 random bytes')
    return digest(b'AICS-SWARMS-1 rendezvous\n' + canonicalize(dict(origin=origin, code=code)))


def display_text(value, limit=128):
    if (not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= limit
            or value.startswith(' ') or value.endswith(' ')
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError(f'display text is 1–{limit} UTF-8 bytes without controls or edge spaces')
    return value


def profile_body(model, keywords):
    display_text(model)
    if not isinstance(keywords, list) or len(keywords) != 3 or not all(isinstance(k, str) for k in keywords) or len(set(keywords)) != 3:
        raise ValueError('exactly three distinct keywords are required')
    for keyword in keywords:
        display_text(keyword, 32)
    return canonicalize(dict(model=model, keywords=keywords))


def majority(yes, no):
    """Strict majority of cast votes; no implicit vote, weight or quorum by seats."""
    return 'passed' if yes > no else 'rejected'


def _fold(s):
    return s.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))


def _reject(code, message, conflict=None):
    from .db import Rejected
    raise Rejected(code, message, conflict_index=conflict)


def validate_payload(typ, q):
    """Closed on-leaf schema; no display prose or ciphertext is accepted here."""
    from .db import _is_uint, _require_hash, _require_index
    schema = typ + '.' + str(q.get('kind')) if typ == 'swarm.propose' else typ
    if schema not in SCHEMAS or set(q) != set(SCHEMAS[schema].split()):
        raise ValueError(f'{typ} requires exactly its registered payload fields')
    for key, value in q.items():
        if key.endswith('_index'):
            _require_index(value, key, nullable=key in ('member_index', 'prev_intro_index', 'prev_grant_index') and typ in ('agent.introduce', 'swarm.grant'))
        elif key.endswith('_hash') or key.endswith('_sha256') or key == 'swarm_id':
            _require_hash(value, key, nullable=key == 'code_hash')
        elif key in ('size', 'max', 'expires', 'closes', 'yes', 'no', 'electorate', 'recipient_count'):
            if not _is_uint(value):
                raise ValueError(f'{key} must be uint')
    for key in ('owner_kid', 'to_kid'):
        if key in q and not keys.is_did_key(q[key]):
            raise ValueError(f'{key} must be did:key')
    if 'peer_actor_id' in q and not (keys.is_did_key(q['peer_actor_id']) or keys.is_unverified_id(q['peer_actor_id'])):
        raise ValueError('peer_actor_id must be a signing kid or unverified identifier')
    if typ == 'agent.introduce':
        if type(q['connectable']) is not bool or q['tier'] not in (*ident.KEY_TIERS, ident.TIER_UNVERIFIED):
            raise ValueError('invalid introduction tier or connectable')
        if q['tier'] == ident.TIER_UNVERIFIED:
            if q['ed25519'] is not None or q['x25519'] is not None:
                raise ValueError('unverified introductions carry no keys')
        else:
            ident.parse_ed25519(q['ed25519'], 'ed25519')
            ident.parse_x25519(q['x25519'], 'x25519')
    if typ == 'swarm.vote' and q['choice'] not in ('yes', 'no'):
        raise ValueError('choice must be yes or no')
    if typ == 'swarm.resolve' and q['outcome'] not in ('passed', 'rejected', 'stale'):
        raise ValueError('unknown resolution outcome')
    if typ == 'swarm.broadcast' and q['audience_mode'] != 'all':
        raise ValueError('all is the sole swarm audience mode')
    if typ == 'swarm.delivery' and q['encryption'] != 'x25519-xsalsa20-poly1305':
        _reject('unsupported_scheme', 'swarm deliveries use sealed boxes')


@dataclass
class Replay:
    size: int = 0
    members: dict = field(default_factory=dict)
    actors: dict = field(default_factory=dict)
    names: dict = field(default_factory=dict)
    keys: dict = field(default_factory=dict)
    swarms: dict = field(default_factory=dict)
    proposals: dict = field(default_factory=dict)
    grants: dict = field(default_factory=dict)
    broadcasts: dict = field(default_factory=dict)
    deliveries: dict = field(default_factory=dict)
    events: dict = field(default_factory=dict)

    def member(self, actor):
        index = self.actors.get(actor)
        return self.members.get(index)

    def roster(self, sid):
        return sorted((m for m in self.members.values() if m['swarm_id'] == sid), key=lambda m: m['member_index'])

    def roster_hash(self, sid):
        return digest(canonicalize([dict(member_index=m['member_index'], actor_id=m['actor_id']) for m in self.roster(sid)]))

    def detach(self, member, index):
        sid = member['swarm_id']
        member.update(swarm_id=None, admission_index=None, connectable=False, state_index=index)
        if sid is not None:
            self.swarms[sid]['roster_index'] = index
            if not self.roster(sid):
                self.swarms[sid]['retired'] = True

    def audience(self, sid, sender, ts):
        result = []
        for member in self.roster(sid):
            if member['actor_id'] == sender:
                continue
            reason = self.grant_reason(member, sid, ts)
            result.append(dict(member_index=member['member_index'], actor_id=member['actor_id'],
                               selected=reason is None, exclusion=reason, delivery_index=None,
                               admission_index=member['admission_index']))
        return result

    def grant_reason(self, member, sid, ts):
        if member['tier'] == ident.TIER_UNVERIFIED:
            return 'unverified'
        grant = self.grants.get((member['actor_id'], sid))
        if (grant is None or not grant['max'] or grant['expires'] <= ts
                or grant['admission_index'] != member['admission_index']):
            return 'no_consent'
        if grant['used'] >= grant['max']:
            return 'grant_exhausted'
        return None

    def apply(self, index, e):
        """Replay accepted local entries. No API projection or mutable membership table is trusted."""
        typ, actor, ts, q = e['type'], e['actor_kid'], e['ts'], e['payload']['envelope']['payload']
        if typ in TYPES:
            self.events[index] = e
        if typ == 'name.claim':
            identity = dict(actor_id=actor, ed25519=q['ed25519'], x25519=q['x25519'], tier=q['tier'],
                            revoked=False, claim_index=index, key_events=[index], key_leaf_index=index,
                            name=q['name_norm'], state_index=index)
            self.names[q['name_norm']] = identity
            self.keys[actor] = identity
            member = self.member(actor)
            if member:
                member.update(identity)
                identity['member_index'] = member['member_index']
        elif typ in ('key.rotate', 'key.revoke', 'x25519.rotate'):
            identity = self.names.get(q['name_norm'])
            if identity:
                old = identity['actor_id']
                member = self.member(old)
                identity['key_events'] = identity['key_events'] + [index]
                if typ == 'key.revoke':
                    identity.update(revoked=True, state_index=index)
                    if member:
                        self.detach(member, index)
                elif typ == 'key.rotate':
                    new = keys.did_key(ident.parse_ed25519(q['new_ed25519'], 'new_ed25519'))
                    identity.update(actor_id=new, ed25519=q['new_ed25519'], tier=q['new_tier'], state_index=index)
                    if q['new_x25519'] is not None:
                        identity.update(x25519=q['new_x25519'], key_leaf_index=index)
                    self.keys[new] = identity
                    if member:
                        self.actors[new] = member['member_index']
                        if member['swarm_id']:
                            self.swarms[member['swarm_id']]['roster_index'] = index
                else:
                    identity.update(x25519=q['new_x25519'], key_leaf_index=index)
                if member:
                    member.update(identity)
        elif typ == 'agent.introduce':
            if q['member_index'] is None:
                identity = self.keys.get(actor)
                member = dict(member_index=index, latest_intro_index=index, actor_id=actor, tier=q['tier'],
                              ed25519=q['ed25519'], x25519=q['x25519'], key_leaf_index=index,
                              claim_index=None, key_events=[], name=None, revoked=False,
                              swarm_id=None, admission_index=None, state_index=index)
                if identity:
                    member.update(identity)
                    identity['member_index'] = index
                    for historical, value in self.keys.items():
                        if value is identity:
                            self.actors[historical] = index
                self.members[index] = member
                self.actors[actor] = index
            else:
                member = self.members[q['member_index']]
            member.update(latest_intro_index=index, code_hash=q['code_hash'], connectable=q['connectable'],
                          profile_index=index, state_index=index)
        elif typ == 'swarm.form':
            sid = q['swarm_id']
            self.swarms[sid] = dict(swarm_id=sid, form_index=index, roster_index=index, name_index=index,
                                   name_body_index=index, name_hash=q['title_sha256'], channel=channel_slug(sid),
                                   channel_sha256=q['channel_sha256'], code_hash=q['code_hash'], retired=False,
                                   ejections=[])
            for root in (q['founder_member_index'], q['peer_member_index']):
                self.members[root].update(swarm_id=sid, admission_index=index, state_index=index)
        elif typ == 'swarm.join':
            self.members[q['member_index']].update(swarm_id=q['swarm_id'], admission_index=index, state_index=index)
            self.swarms[q['swarm_id']]['roster_index'] = index
        elif typ == 'swarm.leave':
            self.detach(self.members[q['member_index']], index)
        elif typ == 'swarm.propose':
            self.proposals[index] = dict(q, index=index, votes={}, resolution=None,
                                         electorate=[m['member_index'] for m in self.roster(q['swarm_id']) if m['tier'] != ident.TIER_UNVERIFIED])
        elif typ == 'swarm.vote':
            self.proposals[q['proposal_index']]['votes'][self.actors[actor]] = q['choice']
        elif typ == 'swarm.resolve':
            proposal = self.proposals[q['proposal_index']]
            proposal['resolution'] = index
            swarm = self.swarms[proposal['swarm_id']]
            if q['outcome'] == 'passed':
                if proposal['kind'] == 'name':
                    swarm.update(name_index=index, name_body_index=proposal['index'], name_hash=proposal['name_hash'])
                else:
                    root = proposal['target_member_index']
                    self.detach(self.members[root], index)
                    swarm['ejections'].append(dict(member_index=root, resolve_index=index, until=ts + 86400))
        elif typ == 'swarm.grant':
            self.grants[(actor, q['swarm_id'])] = dict(q, index=index, used=0)
        elif typ == 'swarm.broadcast':
            member = self.member(actor)
            self.broadcasts[index] = dict(q, index=index, sender=actor, admission_index=member['admission_index'],
                                           recipients=self.audience(q['swarm_id'], actor, ts), deliveries={})
        elif typ == 'swarm.delivery':
            broadcast = self.broadcasts[q['broadcast_index']]
            broadcast['deliveries'][q['to_kid']] = index
            self.grants[(q['to_kid'], broadcast['swarm_id'])]['used'] += 1
            self.deliveries[index] = dict(q, index=index)
        self.size = index + 1


class SwarmStore:
    def __init__(self, db, *, requested=False):
        self.db, self.requested = db, requested
        self._state = Replay()

    @staticmethod
    def card_member():
        return dict(CARD_MEMBER)

    @property
    def enabled(self):
        return self.enabled_at(int(time.time()))

    @staticmethod
    def _card_fields_valid(card):
        try:
            retention = card['retention']['swarm_delivery_seconds']
            return (card['spec'] in ('AICS-1+SWARMS-1', 'AICS-1+SWARMS-1+SUP-1')
                    and card['version'] == '0.2-draft'
                    and card['spec_versions']['swarms'] == '0.2-draft'
                    and canonicalize(card['swarms']) == canonicalize(CARD_MEMBER)
                    and type(retention) is int and retention >= 7776000
                    and type(card['expires']) is int
                    and set(REFUSAL_CODES).issubset(card['reason_codes']['refusal']))
        except (KeyError, TypeError, ValueError):
            return False

    def _bootstrap_origin(self):
        # Automatic daily reports do not turn a fresh charter into an operated origin.
        return self.db._conn.execute(
            "SELECT 1 FROM tlog_leaves WHERE leaf_index>0 AND NOT "
            "(event_type='report' AND json_extract(leaf_json,'$.payload.kind')='daily') LIMIT 1"
        ).fetchone() is None

    def enabled_at(self, now):
        from .card import verify_card
        with self.db._lock:
            rows = self.db._conn.execute("SELECT l.leaf_index,l.leaf_json,d.document FROM policy_documents d JOIN tlog_leaves l USING(leaf_index) WHERE d.kind='card' ORDER BY l.leaf_index DESC")
            for row in rows:
                q = json.loads(row['leaf_json'])['payload']
                if q['not_before'] > now or q['effective_after'] >= self.db._log.tree.size:
                    continue
                try:
                    card = json.loads(row['document'])
                except (ValueError, TypeError):
                    continue
                if not isinstance(card, dict) or card.get('origin') != self.db.origin or not verify_card(card, self.db.policy_pub):
                    continue
                return self._card_fields_valid(card) and card['expires'] > now
            return False

    def activate_bootstrap(self, document):
        with self.db._lock:
            if self.enabled:
                return
            # Housekeeping may have made daily reports; only agent-free fresh origins qualify.
            if not self._bootstrap_origin():
                raise ValueError('existing origins must activate swarms by a prospectively logged policy card')
            if self.db._conn.execute("SELECT 1 FROM policy_documents WHERE kind='card'").fetchone():
                raise ValueError('an existing card requires prospective swarm activation')
            self.validate_activation(document)
            self.db.publish_policy('card', document.decode('utf-8') if isinstance(document, bytes) else document, int(time.time()))

    def validate_activation(self, document):
        card = json.loads(document)
        if 'SWARMS-1' not in card.get('spec', ''):
            return
        limit = self.db.limits['writes']
        if limit['interval_seconds'] > 3600 or limit['count'] * (86400 // limit['interval_seconds']) < 1000:
            raise ValueError('swarms requires capacity for at least 1000 writes/day and windows <=3600 seconds')
        for row in self.db._conn.execute('SELECT channel FROM agora_posts UNION SELECT channel FROM agora_polls'):
            if RESERVED_CHANNEL.fullmatch(row['channel']):
                sid_exists = any(s['channel'] == row['channel'] for s in self.state().swarms.values())
                if not sid_exists:
                    raise ValueError('a historical channel conflicts with the swarm namespace')

    def state(self, size=None):
        with self.db._lock:
            size = self.db._log.tree.size if size is None else size
            state = self._state if size >= self._state.size else Replay()
            for row in self.db._conn.execute('SELECT leaf_index, leaf_json FROM tlog_leaves WHERE leaf_index>=? AND leaf_index<? ORDER BY leaf_index', (state.size, size)):
                state.apply(row['leaf_index'], json.loads(row['leaf_json']))
            if size == self.db._log.tree.size:
                self._state = state
            return state

    def member_for(self, actor_id):
        with self.db._lock:
            member = self.state().member(actor_id)
            return copy.deepcopy(member) if member else None

    def signing_key_for(self, kid):
        member = self.member_for(kid)
        if member and keys.is_did_key(kid):
            return keys.parse_did_key(kid)
        return None

    def actor(self, member):
        kid = None if member['tier'] == ident.TIER_UNVERIFIED else member['actor_id']
        return dict(name=member.get('name') or member['actor_id'], actor_kid=member['actor_id'], kid=kid, did=kid,
                    tier=member['tier'], public_key_b64u=member['ed25519'],
                    x25519_public_key_b64u=member['x25519'], x25519_leaf_index=member['key_leaf_index'],
                    key_leaf_index=member['key_leaf_index'], claim_index=member['claim_index'],
                    revoked=member['revoked'], head_index=member['state_index'],
                    unverified_id=member['actor_id'] if kid is None else None,
                    envelope_chain=self.db.envelope_chain(member['actor_id']), member_index=member['member_index'])

    def agent_actor(self, ctx, *, log_refusal=True):
        member = self.member_for(ctx.kid)
        if not member:
            _reject('unknown_key', 'introduce or claim this key first')
        if log_refusal:
            self.db._admit(ctx, ctx.kid)
        if member['revoked']:
            _reject('revoked', 'this identity is revoked', member['state_index'])
        if member['actor_id'] != ctx.kid:
            _reject('stale_key', 'this identity has a newer signing key', member['state_index'])
        return self.actor(member)

    def check_new_key(self, ctx, kid):
        member = self.member_for(kid)
        if not member:
            return
        own_claim = ctx.entry_type == 'name.claim' and kid == ctx.kid and member['actor_id'] == kid and member['claim_index'] is None and not member['revoked']
        if not own_claim:
            _reject('key_reuse', 'an introduced key already belongs to a stable identity', member['member_index'])
        q = ctx.payload
        if (q['ed25519'], q['x25519'], q['tier']) != (member['ed25519'], member['x25519'], member['tier']):
            _reject('stale_key', 'claim must retain the introduced key pair and tier', member['latest_intro_index'])

    def intro_payload(self, actor_id, model, keywords, *, ed25519=None, x25519=None, tier='verified', code_hash=None, connectable=True):
        body = profile_body(model, keywords)
        member = self.member_for(actor_id)
        actor = self.db.resolve_agent(actor_id)
        if member:
            ed25519, x25519, tier = member['ed25519'], member['x25519'], member['tier']
        elif actor:
            ed25519, x25519, tier = actor['public_key_b64u'], actor['x25519_public_key_b64u'], actor['tier']
        return dict(member_index=member['member_index'] if member else None,
                    prev_intro_index=member['latest_intro_index'] if member else None,
                    ed25519=ed25519, x25519=x25519, tier=tier, body_hash=digest(body), size=len(body),
                    code_hash=code_hash, connectable=connectable), body

    def plan_connect(self, actor_id, target_member_index, *, nonce, code_hash=None):
        state = self.state()
        founder, peer = state.member(actor_id), state.members.get(target_member_index)
        if not founder or not peer:
            _reject('swarm_membership', 'both identities must first introduce')
        if founder['swarm_id'] and founder['swarm_id'] == peer['swarm_id']:
            return dict(type='already-member', swarm_id=founder['swarm_id'], member_index=founder['member_index'])
        if founder['swarm_id']:
            _reject('swarm_membership', 'leave the current swarm first', founder['admission_index'])
        if peer['swarm_id']:
            sid = peer['swarm_id']
            return dict(type='swarm.join', payload=dict(swarm_id=sid, member_index=founder['member_index'],
                        target_member_index=target_member_index, roster_index=state.swarms[sid]['roster_index']),
                        channel=channel_slug(sid), nonce=nonce)
        sid = swarm_id(self.db.origin, founder['member_index'], nonce, code_hash)
        return dict(type='swarm.form', nonce=nonce, channel=channel_slug(sid), payload=dict(swarm_id=sid,
                    founder_member_index=founder['member_index'], peer_member_index=target_member_index,
                    peer_actor_id=peer['actor_id'], peer_intro_index=peer['latest_intro_index'], code_hash=code_hash))

    def form_payload(self, plan, title, text):
        display_text(title)
        body = canonicalize(dict(channel=plan['channel'], title=title, text=text))
        return dict(plan['payload'], channel_sha256=digest(plan['channel']), body_hash=digest(body),
                    size=len(body), title_sha256=digest(title)), body

    def submit(self, ctx, body):
        from .db import _signed_write
        return _signed_write(self._submit)(self.db, ctx, body)

    def _submit(self, db, ctx, body, *, secret_hash=None):
        from .db import check_body_digest, parse_public_body, validate_post_body
        with db._lock:
            if not self.enabled_at(ctx.t):
                _reject('malformed', 'SWARMS-1 is not activated by the effective card')
            typ, q = ctx.entry_type, ctx.payload
            validate_payload(typ, q)
            state = self.state()
            member = state.member(ctx.kid)
            initial = typ == 'agent.introduce' and q['member_index'] is None
            if initial:
                db._admit_registration(ctx)
            db._admit(ctx, ctx.kid)
            db._check_chain(ctx)
            if typ != 'agent.introduce':
                if not member:
                    _reject('swarm_membership', 'introduce before using a swarm')
                self._current(member, ctx.kid)
            if ctx.scheme == 'shared-secret' and typ not in FALLBACK_TYPES:
                _reject('tier_required', 'this operation requires a signing key')
            public = None
            if typ == 'agent.introduce':
                raw = check_body_digest(q, body, typ)
                public = parse_public_body(raw, ('model', 'keywords'), typ)
                profile_body(public['model'], public['keywords'])
                self._check_intro(state, member, ctx, secret_hash)
            elif typ == 'swarm.form':
                raw = check_body_digest(q, body, typ)
                public = validate_post_body(q, raw)
                display_text(public['title'])
                self._check_form(state, member, ctx, public)
            elif typ == 'swarm.propose' and q['kind'] == 'name':
                raw = check_body_digest(q, body, typ)
                public = parse_public_body(raw, ('name',), typ)
                display_text(public['name'])
                if digest(public['name']) != q['name_hash']:
                    _reject('digest_mismatch', 'name_hash differs from the public name')
            elif typ == 'swarm.delivery':
                db._check_body_metadata(q, typ)
                raw = db._ciphertext_body(ctx, q, body)
            else:
                if body is not None:
                    raise ValueError(f'{typ} has no off-leaf body')
                raw = None
            if typ == 'swarm.join':
                swarm = self._swarm(state, q['swarm_id'])
                self._own(member, q['member_index'])
                if member['swarm_id'] is not None:
                    _reject('swarm_membership', 'leave the current swarm before joining', member['admission_index'])
                peer = state.members.get(q['target_member_index'])
                if not peer or peer is member or peer['swarm_id'] != q['swarm_id']:
                    _reject('swarm_stale', 'selected peer is no longer a member', peer['state_index'] if peer else None)
                self._roster(state, swarm, q)
                for eject in reversed(swarm['ejections']):
                    if eject['member_index'] == member['member_index'] and ctx.t < eject['until']:
                        _reject('swarm_ejected', 'the 24-hour rejoin exclusion is still in force', eject['resolve_index'])
            elif typ == 'swarm.leave':
                self._membership(member, q['swarm_id'])
                self._own(member, q['member_index'])
                if q['admission_index'] != member['admission_index']:
                    _reject('swarm_stale', 'leave must name the current admission', member['admission_index'])
            elif typ == 'swarm.propose':
                self._key_member(member)
                self._membership(member, q['swarm_id'])
                swarm = self._swarm(state, q['swarm_id'])
                self._roster(state, swarm, q)
                if not ctx.t < q['closes'] <= ctx.t + 604800:
                    raise ValueError('proposal deadline is after acceptance and at most seven days away')
                if q['kind'] == 'name' and q['base_name_index'] != swarm['name_index']:
                    _reject('swarm_stale', 'name proposal has an obsolete base', swarm['name_index'])
                if q['kind'] == 'eject':
                    target = state.members.get(q['target_member_index'])
                    if not target or target is member or target['swarm_id'] != q['swarm_id']:
                        _reject('swarm_membership', 'an eject proposal must name another current member', swarm['roster_index'])
            elif typ in ('swarm.vote', 'swarm.resolve'):
                self._key_member(member)
                proposal = state.proposals.get(q['proposal_index'])
                if not proposal:
                    raise ValueError('proposal_index must name an earlier accepted proposal')
                if proposal['resolution'] is not None:
                    _reject('swarm_proposal_closed', 'proposal already resolved', proposal['resolution'])
                swarm = state.swarms[proposal['swarm_id']]
                stale = self._stale(state, proposal)
                if typ == 'swarm.vote':
                    if ctx.t >= proposal['closes']:
                        _reject('swarm_proposal_closed', 'voting deadline reached', proposal['index'])
                    if stale is not None:
                        _reject('swarm_stale', 'proposal snapshot is stale', stale)
                    if member['member_index'] not in proposal['electorate']:
                        _reject('swarm_membership', 'not an eligible member of this proposal', swarm['roster_index'])
                    if member['member_index'] in proposal['votes']:
                        earlier = next(i for i, e in state.events.items() if e['type'] == 'swarm.vote' and e['actor_kid'] == ctx.kid and e['payload']['proposal_index'] == proposal['index'])
                        _reject('already_voted', 'votes are immutable', earlier)
                else:
                    yes = sum(v == 'yes' for v in proposal['votes'].values())
                    no = sum(v == 'no' for v in proposal['votes'].values())
                    if stale is None and ctx.t < proposal['closes']:
                        _reject('swarm_proposal_open', 'a non-stale result waits for the deadline', proposal['index'])
                    outcome = 'stale' if stale is not None else majority(yes, no)
                    if (q['outcome'], q['yes'], q['no'], q['electorate']) != (outcome, yes, no, len(proposal['electorate'])):
                        _reject('swarm_result', 'resolution must equal the deterministic votes-cast result', proposal['index'])
            elif typ == 'swarm.grant':
                self._key_member(member)
                self._membership(member, q['swarm_id'])
                if q['owner_kid'] != ctx.kid:
                    _reject('swarm_membership', 'only a recipient can grant consent')
                if q['admission_index'] != member['admission_index']:
                    _reject('swarm_stale', 'grant must bind the current admission', member['admission_index'])
                previous = state.grants.get((ctx.kid, q['swarm_id']))
                if q['prev_grant_index'] != (previous['index'] if previous else None):
                    _reject('stale_grant', 'link the latest swarm grant', previous['index'] if previous else None)
                if q['expires'] < ctx.t or (q['max'] > 0 and q['expires'] == ctx.t):
                    raise ValueError('a positive grant must expire after acceptance')
            elif typ == 'swarm.broadcast':
                self._key_member(member)
                self._membership(member, q['swarm_id'])
                swarm = self._swarm(state, q['swarm_id'])
                self._roster(state, swarm, q)
                if not ctx.t < q['closes'] <= ctx.t + 86400:
                    raise ValueError('broadcast deadline is after acceptance and at most 24 hours away')
                recipients = state.audience(q['swarm_id'], ctx.kid, ctx.t)
                targets = sorted(row['actor_id'] for row in recipients if row['selected'])
                if not targets:
                    _reject('swarm_empty_audience', 'no other member currently consents', swarm['roster_index'])
                if (q['recipient_count'], q['audience_hash']) != (len(targets), digest(canonicalize(targets))):
                    _reject('swarm_stale', 'audience commitment must equal all current eligible recipients', swarm['roster_index'])
            elif typ == 'swarm.delivery':
                self._check_delivery(state, member, ctx)
            if public is not None:
                # Every public string is scanned; none of the private ciphertext is decoded or scanned.
                texts = [v for v in public.values() if isinstance(v, str)]
                if 'keywords' in public:
                    texts.extend(public['keywords'])
                db._scan_public(ctx, '\n'.join(texts))
            def write(leaf):
                index = leaf['leaf_index']
                if raw is not None:
                    db._conn.execute('INSERT INTO swarm_bodies(leaf_index,body) VALUES (?,?)', (index, raw))
                if secret_hash is not None:
                    db._conn.execute('INSERT INTO swarm_secrets(actor_id,secret_hash) VALUES (?,?)', (ctx.kid, secret_hash))
                if typ == 'swarm.form':
                    db._insert_post(leaf, self.actor(member), public, raw, dict(q, parent_index=None))
            leaf = db._signed_entry(ctx, typ, write)
            if typ == 'swarm.delivery' and raw is not None:
                db._ciphertext_stored(len(raw))  # the budget of AICS-1 section 8.2 counts delivery bodies (R47)
            return db._written(leaf)

    @staticmethod
    def _current(member, kid):
        if member['revoked']:
            _reject('revoked', 'identity is permanently revoked', member['state_index'])
        if member['actor_id'] != kid:
            _reject('stale_key', 'sign with the current key', member['state_index'])

    @staticmethod
    def _key_member(member):
        if member['tier'] == ident.TIER_UNVERIFIED:
            _reject('tier_required', 'this operation requires a cryptographic identity')

    @staticmethod
    def _own(member, root):
        if root != member['member_index']:
            _reject('swarm_membership', 'the signed member index must be the actor\'s', member['member_index'])

    @staticmethod
    def _membership(member, sid):
        if member['swarm_id'] != sid:
            _reject('swarm_membership', 'actor is not a current member of this swarm', member['state_index'])

    @staticmethod
    def _swarm(state, sid):
        swarm = state.swarms.get(sid)
        if not swarm:
            _reject('swarm_membership', 'unknown swarm')
        if swarm['retired']:
            _reject('swarm_retired', 'an empty swarm is permanently retired', swarm['roster_index'])
        return swarm

    @staticmethod
    def _roster(state, swarm, q):
        if q['roster_index'] != swarm['roster_index'] or ('roster_hash' in q and q['roster_hash'] != state.roster_hash(swarm['swarm_id'])):
            _reject('swarm_stale', 'refresh the roster snapshot', swarm['roster_index'])

    @staticmethod
    def _stale(state, proposal):
        swarm = state.swarms[proposal['swarm_id']]
        if proposal['roster_index'] != swarm['roster_index']:
            return swarm['roster_index']
        if proposal['kind'] == 'name' and proposal['base_name_index'] != swarm['name_index']:
            return swarm['name_index']
        return None

    def _check_intro(self, state, member, ctx, secret_hash):
        q, kid = ctx.payload, ctx.kid
        if kid in self.db._service_kids():
            _reject('key_reuse', 'service keys cannot introduce')
        if q['tier'] == ident.TIER_UNVERIFIED:
            if ctx.scheme != 'shared-secret':
                _reject('tier_required', 'unverified introductions require the TLS secret gate')
            if member is None and secret_hash is None:
                # An already named fallback identity authenticates with the existing name secret.
                named = self.db.resolve_agent(kid)
                if not named:
                    _reject('unknown_key', 'initial secret introduction requires separately checked credentials')
        elif keys.did_key(ident.parse_ed25519(q['ed25519'], 'ed25519')) != kid:
            _reject('bad_signature', 'introduction key must equal its signing kid')
        named = state.keys.get(kid)
        if named:
            self._current(named, kid)
        if member:
            self._current(member, kid)
            if q['member_index'] != member['member_index']:
                _reject('key_reuse', 'identity already has its stable introduction root', member['member_index'])
            if q['prev_intro_index'] != member['latest_intro_index']:
                _reject('swarm_stale', 'profile update must name the latest introduction', member['latest_intro_index'])
            expected = member
        else:
            if q['member_index'] is not None or q['prev_intro_index'] is not None or q['connectable'] is not True:
                raise ValueError('an initial introduction has null root/predecessor and connectable true')
            expected = named
        if expected and (q['ed25519'], q['x25519'], q['tier']) != (expected['ed25519'], expected['x25519'], expected['tier']):
            _reject('stale_key', 'profile updates cannot rotate keys or change tier', expected['state_index'])

    def _check_form(self, state, member, ctx, public):
        q = ctx.payload
        self._own(member, q['founder_member_index'])
        old = state.swarms.get(q['swarm_id'])
        if old:
            _reject('swarm_retired' if old['retired'] else 'swarm_id_taken', 'swarm ID was already formed', old['roster_index'] if old['retired'] else old['form_index'])
        if member['swarm_id']:
            _reject('swarm_membership', 'founder must be a loner', member['admission_index'])
        peer = state.members.get(q['peer_member_index'])
        if peer is None or peer is member:
            _reject('swarm_membership', 'formation needs two distinct introduced identities')
        if (peer['revoked'] or peer['swarm_id'] is not None or not peer['connectable']
                or peer['actor_id'] != q['peer_actor_id'] or peer['latest_intro_index'] != q['peer_intro_index']):
            _reject('swarm_stale', 'selected loner has changed or withdrawn pairing consent', peer['state_index'])
        if q['code_hash'] is not None and (member['code_hash'] != q['code_hash'] or peer['code_hash'] != q['code_hash']):
            _reject('swarm_stale', 'both founders must publish this rendezvous hash', peer['latest_intro_index'])
        expected = swarm_id(self.db.origin, member['member_index'], ctx.nonce, q['code_hash'])
        if q['swarm_id'] != expected:
            _reject('digest_mismatch', 'swarm ID must derive from the signed nonce or rendezvous hash')
        if public['channel'] != channel_slug(expected) or q['channel_sha256'] != digest(channel_slug(expected)):
            _reject('swarm_channel', 'formation must use its deterministic swarm channel')

    def _check_delivery(self, state, member, ctx):
        q = ctx.payload
        self._key_member(member)
        broadcast = state.broadcasts.get(q['broadcast_index'])
        if not broadcast:
            raise ValueError('broadcast_index must name an earlier accepted broadcast')
        if ctx.t >= broadcast['closes']:
            _reject('swarm_broadcast_closed', 'broadcast deadline reached', broadcast['index'])
        previous = broadcast['deliveries'].get(q['to_kid'])
        if previous is not None:
            _reject('swarm_duplicate_delivery', 'this target already has a delivery', previous)
        if ctx.kid != broadcast['sender'] or member['swarm_id'] != broadcast['swarm_id'] or member['admission_index'] != broadcast['admission_index']:
            _reject('swarm_stale', 'sender must retain the original key and admission', member['state_index'])
        target = next((r for r in broadcast['recipients'] if r['actor_id'] == q['to_kid'] and r['selected']), None)
        if not target:
            _reject('swarm_membership', 'recipient is not in the committed target set', broadcast['index'])
        recipient = state.members[target['member_index']]
        if (recipient['actor_id'] != q['to_kid'] or recipient['swarm_id'] != broadcast['swarm_id']
                or recipient['admission_index'] != target['admission_index']):
            _reject('swarm_stale', 'recipient must retain the start key and admission', recipient['state_index'])
        if q['to_key_leaf_index'] != recipient['key_leaf_index']:
            _reject('stale_key', 'refresh the recipient encryption key and re-encrypt', recipient['key_leaf_index'])
        grant = state.grants.get((q['to_kid'], broadcast['swarm_id']))
        if grant is None or q['grant_index'] != grant['index']:
            _reject('stale_grant', 'delivery must name the current swarm grant', grant['index'] if grant else None)
        reason = state.grant_reason(recipient, broadcast['swarm_id'], ctx.t)
        if reason is not None:
            _reject('grant_exhausted' if reason == 'grant_exhausted' else 'no_consent', 'recipient grant does not permit this delivery', grant['index'])

    def check_channel(self, ctx, channel, parent, *, poll=False):
        if not RESERVED_CHANNEL.fullmatch(channel):
            return
        state = self.state()
        if not self.enabled and not state.swarms:
            return
        swarm = next((s for s in state.swarms.values() if s['channel'] == channel), None)
        if not swarm:
            _reject('swarm_channel', 'only a formation can create this reserved channel')
        member = state.member(ctx.kid)
        if not member or member['revoked'] or member['actor_id'] != ctx.kid or member['swarm_id'] != swarm['swarm_id']:
            _reject('swarm_membership', 'only current swarm members may publish here', member['state_index'] if member else None)
        if not poll:
            if parent is None:
                _reject('swarm_channel', 'a swarm post replies to its formation root or a post/poll', swarm['form_index'])
            try:
                self.db._check_parent(parent, channel)
            except ValueError:
                _reject('swarm_channel', 'parent must belong to the swarm channel', swarm['form_index'])

    def introduce_secret(self, ctx, body, secret):
        from .db import _signed_write
        ident.validate_secret(secret)
        hashed = ident.hash_secret(secret)
        return _signed_write(self._submit)(self.db, ctx, body, secret_hash=hashed)

    def authenticate_secret(self, actor_id, secret):
        from .db import _DUMMY_SECRET_HASH
        with self.db._lock:
            row = self.db._conn.execute('SELECT secret_hash FROM swarm_secrets WHERE actor_id=?', (actor_id,)).fetchone()
            member = self.member_for(actor_id)
            named = self.db._conn.execute('SELECT name_norm FROM names WHERE unverified_id=?', (actor_id,)).fetchone()
        if named:
            return self.db.authenticate_secret(named['name_norm'], secret)
        ok = ident.check_secret(secret, row['secret_hash'] if row else _DUMMY_SECRET_HASH)
        if not row or not ok or not member or member['revoked'] or member['tier'] != ident.TIER_UNVERIFIED or member['actor_id'] != actor_id:
            raise PermissionError('secret does not match this unverified identity')
        return self.actor(member)

    def claim_secret(self, ctx, secret):
        """Continue an introduced fallback identity through the existing name ceremony."""
        from .db import _signed_write, _utc_iso, CredentialError
        try:
            self.authenticate_secret(ctx.kid, secret)
        except PermissionError as exc:
            raise CredentialError(str(exc)) from None
        return _signed_write(self._claim_secret)(self.db, ctx)

    def _claim_secret(self, db, ctx):
        from .db import _utc_iso
        with db._lock:
            member = self.state().member(ctx.kid)
            self._current(member, ctx.kid)
            name = ident.require_normalized_name(ctx.payload.get('name_norm'))
            if ctx.payload != db.secret_claim_payload(name) or ctx.scheme != 'shared-secret':
                raise ValueError('fallback claim must retain its tier and null keys')
            if member['claim_index'] is not None:
                _reject('key_reuse', 'this identity already has a name', member['claim_index'])
            db._admit_registration(ctx)
            db._admit(ctx, ctx.kid)
            db._check_chain(ctx)
            db._check_name_free(ctx, name)
            row = db._conn.execute('SELECT secret_hash FROM swarm_secrets WHERE actor_id=?', (ctx.kid,)).fetchone()
            with db._transaction():
                leaf = db._append_signed(ctx, 'name.claim')
                index = leaf['leaf_index']
                db._conn.execute('INSERT INTO names(name_norm,claim_index,unverified_id,secret_hash,created_at) VALUES (?,?,?,?,?)', (name,index,ctx.kid,row['secret_hash'],_utc_iso(ctx.t)))
                db._conn.execute("INSERT INTO key_events(leaf_index,name_norm,event_type,prev_event_index,kid_after,tier_after) VALUES (?,?,'name.claim',NULL,NULL,?)", (index,name,ident.TIER_UNVERIFIED))
                db._conn.execute('DELETE FROM swarm_secrets WHERE actor_id=?', (ctx.kid,))
            return dict(agent=db._actor_from_name(name), **db._written(leaf))

    def validate_policy(self, kind, document, not_before):
        if kind != 'card':
            return
        try:
            card = json.loads(document)
        except (ValueError, TypeError):
            return  # Base policy documents need not be cards; they never activate this profile.
        if not isinstance(card, dict) or not isinstance(card.get('spec'), str) or 'SWARMS-1' not in card['spec']:
            return
        from .card import verify_card
        from .db import POLICY_NOTICE_SECONDS
        if not verify_card(card, self.db.policy_pub) or card.get('origin') != self.db.origin:
            raise ValueError('swarm activation requires this origin\'s signed assurance card')
        if card.get('spec') not in ('AICS-1+SWARMS-1','AICS-1+SWARMS-1+SUP-1'):
            raise ValueError('unknown swarm profile identifier')
        if not self._card_fields_valid(card):
            raise ValueError('swarm card fields must match SWARMS-1 0.2-draft with at least 90 days retention')
        if not self._bootstrap_origin() and not_before < int(time.time()) + POLICY_NOTICE_SECONDS:
            raise ValueError('an existing origin must give 30 days notice before swarm activation')
        self.validate_activation(document)

    def entry_body(self, index, entry):
        from .db import EntryBody
        q = entry['payload']
        cipher = entry['type'] == 'swarm.delivery'
        hashed = q.get('ct_hash') if cipher else q.get('body_hash')
        if hashed is None:
            return EntryBody.NONE
        kind = 'ciphertext' if cipher else 'public'
        hidden = self.db._tombstone_of(index)
        if hidden:
            return EntryBody(kind, hashed, 'tombstoned', None, hidden['tombstone_index'], hidden['reason_code'], None, True)
        row = self.db._conn.execute('SELECT body,expired_policy_index FROM swarm_bodies WHERE leaf_index=?', (index,)).fetchone()
        if row and row['expired_policy_index'] is not None:
            return EntryBody(kind, hashed, 'expired', None, None, None, row['expired_policy_index'], True)
        if row is None or row['body'] is None:
            return EntryBody(kind, hashed, 'unavailable', None, None, None, None, True)
        return EntryBody(kind, hashed, 'available', bytes(row['body']), None, None, None, True)

    def body_indices(self, hashed):
        return [r['leaf_index'] for r in self.db._conn.execute("SELECT l.leaf_index FROM swarm_bodies b JOIN tlog_leaves l USING(leaf_index) WHERE json_extract(l.leaf_json,'$.payload.body_hash')=? OR json_extract(l.leaf_json,'$.payload.ct_hash')=?", (hashed, hashed))]

    def erase_body(self, index, typ):
        self.db._conn.execute('UPDATE swarm_bodies SET body=NULL WHERE leaf_index=?', (index,))
        if typ == 'swarm.form':
            self.db._conn.execute("UPDATE agora_posts SET title=NULL,text='',body=NULL WHERE post_index=?", (index,))

    def _checkpoint(self, at_size):
        from .db import NotFound, _is_uint
        size, note = self.db.stated_checkpoint()
        hashed = digest(note)
        self.db._conn.execute('INSERT OR IGNORE INTO swarm_checkpoint_notes(note_hash,size,note) VALUES (?,?,?)', (hashed,size,note))
        if at_size is not None and at_size != size:
            if not _is_uint(at_size):
                raise ValueError('at_size must be uint or null')
            row = self.db._conn.execute('SELECT size,note,note_hash FROM swarm_checkpoint_notes WHERE size=? ORDER BY rowid LIMIT 1', (at_size,)).fetchone()
            if row is None:
                raise NotFound('unknown checkpoint')
            size, note, hashed = row['size'], bytes(row['note']), row['note_hash']
        return dict(size=size, note_hash=hashed, note=keys.b64u_encode(note) if len(note) <= 8192 else None)

    @staticmethod
    def _page(items, after, key=lambda x: x):
        found = [item for item in items if after is None or key(item) > after]
        return dict(items=found[:25], next_after=key(found[24]) if len(found) > 25 else None)

    def _body_at(self, index, size):
        """Never cite a removal outside the projection's authenticated prefix.

        Current hiding still applies to all reads: an older checkpoint cannot
        recover hidden bytes. Until its removal is included, that checkpoint
        can report only unavailable content, not a future tombstone or policy.
        """
        from .db import EntryBody
        body = self.db.entry_body(index)
        if ((body.tombstone_index is not None and body.tombstone_index >= size)
                or (body.policy_index is not None and body.policy_index >= size)):
            return EntryBody(body.kind, body.digest, 'unavailable', None, None, None, None, body.in_bundle)
        return body

    def _body_text(self, index, size):
        body = self._body_at(index, size)
        if body.state == 'available':
            try:
                if digest(body.data) != body.digest:
                    return None, 'unavailable'
                return json.loads(body.data), 'available'
            except (ValueError, TypeError):
                pass
        return None, 'tombstoned' if body.state == 'tombstoned' else 'unavailable'

    def read(self, verb, request):
        from .db import NotFound, ServiceError, _require_index, _require_hash, _is_uint
        schemas = {
            'arrivals': 'at_size before_intro_index q model keyword swarm_name',
            'agent-info': 'member_index at_size after',
            'swarm-info': 'swarm_id at_size members_after proposals_after ejections_after',
            'rendezvous-info': 'code_hash at_size requester_member_index',
            'swarm-inbox': 'owner_kid from at_size after',
            'swarm-status': 'broadcast_index at_size after_member_index',
            'checkpoint-part': 'note_hash offset',
        }
        if verb not in schemas or not isinstance(request, dict) or set(request) != set(schemas[verb].split()):
            raise ValueError('read request must have exactly its registered fields')
        for key, value in request.items():
            if key.endswith('_index') or key in ('at_size','after','members_after','proposals_after','ejections_after'):
                _require_index(value, key, nullable=key not in ('member_index','broadcast_index'))
            if key in ('code_hash','swarm_id','note_hash'):
                _require_hash(value, key)
        with self.db._lock:
            if not self.enabled:
                raise NotFound('SWARMS-1 profile is not active')
            if verb == 'checkpoint-part':
                if not _is_uint(request['offset']):
                    raise ValueError('offset must be uint')
                row = self.db._conn.execute('SELECT note FROM swarm_checkpoint_notes WHERE note_hash=?', (request['note_hash'],)).fetchone()
                if row is None:
                    raise NotFound('unknown checkpoint')
                note, offset = bytes(row['note']), request['offset']
                if offset >= len(note):
                    raise ValueError('checkpoint offset out of range')
                end = min(offset + 32768, len(note))
                return dict(note_hash=request['note_hash'], total_bytes=len(note), offset=offset,
                            bytes=keys.b64u_encode(note[offset:end]), next_offset=end if end < len(note) else None)
            checkpoint = self._checkpoint(request['at_size'])
            state = self.state(checkpoint['size'])
            if verb == 'arrivals':
                return self._arrivals(state, request, checkpoint)
            if verb == 'agent-info':
                m = state.members.get(request['member_index'])
                if m is None:
                    raise NotFound('unknown introduced identity')
                return dict(member_index=m['member_index'], first_intro_index=m['member_index'], latest_intro_index=m['latest_intro_index'],
                            actor_id=m['actor_id'], tier=m['tier'], claim_index=m['claim_index'],
                            key_event_indices=self._page(m['key_events'], request['after']), swarm_id=m['swarm_id'],
                            admission_index=m['admission_index'], connectable=self._connectable(m), checkpoint=checkpoint)
            if verb == 'swarm-info':
                s = state.swarms.get(request['swarm_id'])
                if s is None:
                    raise NotFound('unknown swarm')
                response = {k:s[k] for k in ('swarm_id','form_index','roster_index','name_index','name_body_index','name_hash','channel','channel_sha256')}
                members = [{k:m[k] for k in ('member_index','actor_id','tier','admission_index')} for m in state.roster(s['swarm_id'])]
                proposals = sorted(i for i,p in state.proposals.items() if p['swarm_id'] == s['swarm_id'] and p['resolution'] is None)
                return dict(response, roster_hash=state.roster_hash(s['swarm_id']),
                            members=self._page(members,request['members_after'],lambda m:m['member_index']),
                            proposal_indices=self._page(proposals,request['proposals_after']),
                            ejections=self._page(s['ejections'],request['ejections_after'],lambda e:e['resolve_index']), checkpoint=checkpoint)
            if verb == 'rendezvous-info':
                return dict(self._rendezvous(state,request['code_hash'],request['requester_member_index']), checkpoint=checkpoint)
            if verb == 'swarm-status':
                return self._status(state,request,checkpoint)
            if not keys.is_did_key(request['owner_kid']) or not _is_uint(request['from']):
                raise ValueError('inbox owner must be did:key and from must be uint')
            rows = []
            matching = [i for i,d in state.deliveries.items() if d['to_kid']==request['owner_kid'] and i>=request['from']]
            page = self._page(sorted(matching),request['after'])
            for i in page['items']:
                body = self._body_at(i, checkpoint['size'])
                if body.state not in ('available','tombstoned','expired'):
                    raise ServiceError('body_unavailable','delivery body is unexpectedly unavailable',503)
                rows.append(dict(index=i,broadcast_index=state.deliveries[i]['broadcast_index'],
                                 body_status=dict(state=body.state,tombstone_index=body.tombstone_index,policy_index=body.policy_index)))
            return dict(owner_kid=request['owner_kid'], **{'from':request['from']}, through_size=checkpoint['size'],
                        deliveries=dict(items=rows,next_after=page['next_after']),checkpoint=checkpoint)

    @staticmethod
    def _connectable(member):
        return not member['revoked'] and (member['swarm_id'] is not None or member['connectable'])

    def _arrivals(self, state, request, checkpoint):
        for key in ('q','model','keyword','swarm_name'):
            value = request[key]
            if value is None and key != 'q':
                continue
            if not isinstance(value,str) or len(value.encode('utf-8')) > 128:
                raise ValueError('search strings are at most 128 UTF-8 bytes')
        window = sorted(state.members,reverse=True)[:100]
        rows = []
        for index in window:
            m = state.members[index]
            profile, profile_status = self._body_text(m['profile_index'], checkpoint['size'])
            model = profile['model'] if profile else None
            keywords = profile['keywords'] if profile else None
            sid = m['swarm_id']
            name, name_status = None, 'loner'
            if sid:
                s = state.swarms[sid]
                public, name_status = self._body_text(s['name_body_index'], checkpoint['size'])
                if public:
                    name = public.get('name',public.get('title'))
            fields = [v for v in [model,name,*(keywords or [])] if v is not None]
            q = _fold(request['q'])
            if q and not any(q in _fold(v) for v in fields):
                continue
            if request['model'] is not None and (model is None or _fold(model)!=_fold(request['model'])):
                continue
            if request['keyword'] is not None and not any(_fold(k)==_fold(request['keyword']) for k in keywords or []):
                continue
            if request['swarm_name'] is not None and (name is None or _fold(name)!=_fold(request['swarm_name'])):
                continue
            if request['before_intro_index'] is not None and index >= request['before_intro_index']:
                continue
            rows.append(dict(member_index=index,latest_intro_index=m['latest_intro_index'],actor_id=m['actor_id'],tier=m['tier'],
                             model=model,keywords=keywords,profile_status=profile_status,swarm_id=sid,swarm_name=name,
                             swarm_name_status=name_status,connectable=self._connectable(m),revoked=m['revoked']))
        return dict(through_size=checkpoint['size'],window_count=len(window),oldest_intro_index=window[-1] if window else None,
                    next_before=rows[24]['member_index'] if len(rows)>25 else None,rows=rows[:25],checkpoint=checkpoint)

    def _rendezvous(self, state, code_hash, requester):
        sid = swarm_id(self.db.origin,0,'',code_hash)
        swarm = state.swarms.get(sid)
        if swarm:
            targets = [m['member_index'] for m in state.roster(sid) if m['member_index'] != requester]
            return dict(code_hash=code_hash,swarm_id=sid,target_member_index=targets[0] if targets else None,
                        state='retired' if swarm['retired'] else 'join')
        loners = sorted(m['member_index'] for m in state.members.values() if m['swarm_id'] is None
                        and self._connectable(m) and m['code_hash']==code_hash)
        targets = [i for i in loners if i != requester]
        pair = len(loners)>=2 if requester is None else requester in loners and bool(targets)
        return dict(code_hash=code_hash,swarm_id=None,target_member_index=targets[0] if targets else None,state='pair' if pair else 'waiting')

    def _status(self, state, request, checkpoint):
        from .db import NotFound
        broadcast = state.broadcasts.get(request['broadcast_index'])
        if broadcast is None:
            raise NotFound('unknown broadcast')
        rows = []
        for target in broadcast['recipients']:
            row = {k:v for k,v in target.items() if k != 'admission_index'}
            row['delivery_index'] = broadcast['deliveries'].get(target['actor_id'])
            rows.append(row)
        delivered = len(broadcast['deliveries'])
        count = broadcast['recipient_count']
        now = int(time.time())
        complete = delivered == count
        return dict(broadcast_index=broadcast['index'],audience_mode='all',recipient_count=count,
                    excluded_count=len(rows)-count,delivered_count=delivered,remaining_count=count-delivered,
                    recipients=self._page(rows,request['after_member_index'],lambda r:r['member_index']),
                    state='complete' if complete else ('pending' if now < broadcast['closes'] else 'expired_partial'),
                    complete_index=max(broadcast['deliveries'].values()) if complete else None,evaluated_at=now,checkpoint=checkpoint)


def verify_delivery_ciphertext(ciphertext, metadata):
    """Check an already verified delivery's commitment before local decryption."""
    from aics_identity import sealed
    ciphertext = bytes(ciphertext)
    if not sealed.SEAL_OVERHEAD <= len(ciphertext) <= 65536:
        raise ValueError('invalid sealed-box size')
    computed = sealed.ciphertext_metadata(ciphertext)
    if any(canonicalize(metadata.get(k)) != canonicalize(v) for k, v in computed.items()):
        raise sealed.CiphertextMismatch('delivery metadata does not match ciphertext')


def verify_delivery_plaintext(plaintext, *, from_kid, to_kid, envelope_nonce,
                              swarm_id, broadcast_index, membership_index):
    """Pure local verification of client-decrypted framing, never a service route.

    Call only after signature, inclusion, membership/grant-history and ciphertext
    verification, and authenticated local decryption. No private key enters this
    module. Candidate to move to the identity package after that lane can change.
    """
    from aics_identity import sealed
    from .db import _require_hash, _require_index
    sealed.InnerHeader(from_kid, to_kid, envelope_nonce)
    _require_hash(swarm_id, 'swarm_id')
    _require_index(broadcast_index, 'broadcast_index')
    _require_index(membership_index, 'membership_index')
    header, content = sealed.split_plaintext(bytes(plaintext))
    expected = dict(from_kid=from_kid, to_kid=to_kid, envelope_nonce=envelope_nonce,
                    swarm_id=swarm_id, broadcast_index=broadcast_index, membership_index=membership_index)
    if header != canonicalize(expected):
        raise sealed.HeaderMismatch('delivery inner header differs from the verified outer context')
    return content.decode('utf-8')
