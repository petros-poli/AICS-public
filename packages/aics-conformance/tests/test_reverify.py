"""verify-report: a saved instance report re-verified offline, as a reader of published evidence does once the
instance it describes is gone (the pre-launch report of 2026-10-20 names a log that genesis v2 discards)."""
import copy
import json
from pathlib import Path
import pytest
from aics_identity import keys
from aics_tlog import Checkpoint, MerkleTree, sign_checkpoint
from aics_conformance import checks, guarantees  # noqa: F401 (register CHECKS)
from aics_conformance.cli import main, report
from aics_conformance.core import CHECKS
from aics_conformance.fakes import FakeServer
from aics_conformance.protocol import H, U, J
from aics_conformance.reverify import verify_report

IDS = ('log.checkpoint', 'G2', 'G4', 'G8')


def instance_report(server):
    """The bytes ``aics-conformance run`` writes, for a few checks against the fake."""
    ctx = server.context()
    obj = report([c.run(ctx) for c in CHECKS if c.id in IDS], mode='instance', started=0.0)
    obj['checkpoint_archive'] = [{'note': U(h.raw), 'observed_at': h.observed_at} for h in ctx.heads.values()]
    return (json.dumps(obj, ensure_ascii=False, indent=2) + '\n').encode(), ctx.policy


def rewrite(raw, change):
    obj = json.loads(raw); change(obj)
    return (json.dumps(obj, ensure_ascii=False, indent=2) + '\n').encode()


def test_a_report_verifies_offline():
    server = FakeServer(); raw, policy = instance_report(server)
    summary = verify_report(raw, policy, server.now)
    assert summary['report_sha256'] == H(raw) and summary['counts'] == {'pass': len(IDS), 'fail': 0, 'skip': 0}
    assert summary['g8_package'] == 'verified offline' and summary['verdicts']['G8'] == 'pass'
    notes = summary['archived_notes']
    assert notes['verified'] >= 2 and notes['covered_by_g8_prefix'] >= 1


@pytest.mark.parametrize('change, message', [
    (lambda r: r['checks'][0].update(verdict='skip'), 'counts differ'),
    (lambda r: r.update(mode='fake'), 'instance report'),
    (lambda r: r.update(extra=1), 'exactly'),
    (lambda r: r['checks'].append(copy.deepcopy(r['checks'][0])), 'appears twice'),
    (lambda r: next(c for c in r['checks'] if c['id'] == 'G8')['details']['package']['trust_bundle'].update(origin='x.example/tiles'),
     'independent pins'),
    (lambda r: next(c for c in r['checks'] if c['id'] == 'G8')['details']['package']['entry_prefix'].pop(), 'prefix'),
])
def test_a_tampered_report_does_not_verify(change, message):
    server = FakeServer(); raw, policy = instance_report(server)
    with pytest.raises(ValueError, match=message):
        verify_report(rewrite(raw, change), policy, server.now)


def test_a_report_under_another_log_key_does_not_verify():
    server = FakeServer(); raw, policy = instance_report(server)
    other = FakeServer().configuration()
    with pytest.raises(ValueError):
        verify_report(raw, other, server.now)


def test_two_archived_notes_of_one_size_that_differ_are_a_split():
    server = FakeServer(); raw, policy = instance_report(server)
    size = len(server.entries)
    forged = sign_checkpoint(Checkpoint(server.origin, size, bytes(32)), server.log, server.origin).to_bytes()
    tampered = rewrite(raw, lambda r: r['checkpoint_archive'].append({'note': U(forged), 'observed_at': 0}))
    with pytest.raises(ValueError, match='split-proven'):
        verify_report(tampered, policy, server.now)
    # A note the G8 prefix covers, at a smaller size, with another root: also a split.
    prefix_root = MerkleTree([J(e) for e in server.entries[:2]]).root()
    smaller = sign_checkpoint(Checkpoint(server.origin, 2, bytes(31) + b'\x01'), server.log, server.origin).to_bytes()
    assert bytes(31) + b'\x01' != prefix_root
    with pytest.raises(ValueError, match='split-proven'):
        verify_report(rewrite(raw, lambda r: r['checkpoint_archive'].append({'note': U(smaller), 'observed_at': 0})), policy, server.now)


def test_the_cli_verifies_a_saved_report_with_the_readers_own_pins(tmp_path, capsys):
    server = FakeServer(); raw, policy = instance_report(server)
    (tmp_path / 'report.json').write_bytes(raw)
    (tmp_path / 'trust-bundle.json').write_text(json.dumps(policy.trust))
    (tmp_path / 'policy.toml').write_text('trust_file = "trust-bundle.json"\n')
    assert main(['verify-report', '--report', str(tmp_path / 'report.json'), '--policy', str(tmp_path / 'policy.toml')]) == 0
    assert json.loads(capsys.readouterr().out)['report_sha256'] == H(raw)
    (tmp_path / 'report.json').write_bytes(rewrite(raw, lambda r: r['checks'][0].update(verdict='fail')))
    assert main(['verify-report', '--report', str(tmp_path / 'report.json'), '--policy', str(tmp_path / 'policy.toml')]) == 1
    assert 'does not verify' in capsys.readouterr().err


def with_run(server, **change):
    """``instance_report`` with the ``run`` member ``aics-conformance run`` writes (then ``change`` applied to it)."""
    from aics_conformance.provenance import run_record
    raw, policy = instance_report(server)
    def add(r):
        r['run'] = run_record(policy, policy_file=None, api='https://api.example', gate='gate.example:7700',
                              tiles='https://api.example/tiles', checks=[c['id'] for c in r['checks']])
        for key, value in change.items():
            r['run'][key] = value(r['run'][key]) if callable(value) else value
    return rewrite(raw, add), policy


def test_a_report_with_its_run_states_the_run():
    server = FakeServer(); raw, policy = with_run(server)
    run = verify_report(raw, policy, server.now)['run']
    assert run['recorded'] and run['quorum'] == 0 and run['checks_selected'] == len(IDS) and run['deployed_image'] is None
    assert run['trust_bundle_sha256'] == H(J(policy.trust)) and run['harness']['name'] == 'aics-conformance'
    old, _ = instance_report(server)  # a report written before run existed (the pre-launch report) still verifies
    assert verify_report(old, policy, server.now)['run']['recorded'] is False


@pytest.mark.parametrize('change, message', [
    (dict(pins=lambda p: {**p, 'trust_bundle': {**p['trust_bundle'], 'bootstrap_card_hash': 'f' * 64}}), 'another trust bundle'),
    (dict(selection=lambda s: {**s, 'checks': s['checks'][:-1]}), 'selection'),
    (dict(deployed_image={'id': 'sha256:' + 'a' * 64}), 'deployed_image'),
])
def test_a_run_member_that_does_not_match_the_report_or_your_pins_does_not_verify(change, message):
    server = FakeServer(); raw, policy = with_run(server, **change)
    with pytest.raises(ValueError, match=message):
        verify_report(raw, policy, server.now)
    extra = rewrite(with_run(server)[0], lambda r: r['run'].update(note='x'))
    with pytest.raises(ValueError, match='run has exactly'):
        verify_report(extra, policy, server.now)


def test_the_audit_document_names_the_report_and_stays_far_below_an_audit_leafs_limit():
    from aics_conformance.reverify import MAX_AUDIT_DOCUMENT_BYTES, audit_document
    server = FakeServer(); raw, policy = with_run(server)
    url = 'https://pages.example/docs/evidence/report.json'
    doc = json.loads(audit_document(raw, policy, server.now, url))
    assert doc['format'] == 'aics-conformance-audit/v1' and doc['report'] == dict(
        url=url, sha256=H(raw), bytes=len(raw), format='aics-conformance/v1', mode='instance',
        started_at=0.0, finished_at=json.loads(raw)['finished_at'])
    assert doc['counts'] == {'pass': len(IDS), 'fail': 0, 'skip': 0} and doc['run']['recorded']
    assert len(audit_document(raw, policy, server.now, url).encode()) < MAX_AUDIT_DOCUMENT_BYTES // 10
    # A report above the limit (the full pre-launch report is 447 KB) still gives a small document.
    big = rewrite(raw, lambda r: r['checks'][0]['details'].update(padding='x' * (MAX_AUDIT_DOCUMENT_BYTES + 1)))
    assert len(big) > MAX_AUDIT_DOCUMENT_BYTES and len(audit_document(big, policy, server.now, url)) < 20000
    for bad in ('http://pages.example/r.json', 'https://pages.example/a b.json'):
        with pytest.raises(ValueError, match='https URL'):
            audit_document(raw, policy, server.now, bad)
    with pytest.raises(ValueError, match='counts differ'):  # it is verify-report first
        audit_document(rewrite(raw, lambda r: r['checks'][0].update(verdict='skip')), policy, server.now, url)


def test_the_cli_prints_the_audit_document(tmp_path, capsys):
    server = FakeServer(); raw, policy = with_run(server)
    (tmp_path / 'report.json').write_bytes(raw)
    (tmp_path / 'trust-bundle.json').write_text(json.dumps(policy.trust))
    (tmp_path / 'policy.toml').write_text('trust_file = "trust-bundle.json"\n')
    args = ['audit-document', '--report', str(tmp_path / 'report.json'), '--policy', str(tmp_path / 'policy.toml'),
            '--url', 'https://pages.example/docs/evidence/report.json']
    assert main(args) == 0 and json.loads(capsys.readouterr().out)['report']['sha256'] == H(raw)
    (tmp_path / 'report.json').write_bytes(rewrite(raw, lambda r: r['checks'][0].update(verdict='fail')))
    assert main(args) == 1 and 'no audit document' in capsys.readouterr().err


EVIDENCE = Path(__file__).resolve().parents[3] / 'docs' / 'evidence'


def test_the_published_pre_launch_report_still_verifies_offline():
    # docs/evidence is add-only and a card may name its files by hash: verify-report must keep reading them as
    # published, with the policy published beside the report.
    from aics_conformance.policy import Policy
    if not EVIDENCE.is_dir():
        pytest.skip('docs/evidence is not in this checkout (the public repository does not carry it)')
    report = EVIDENCE / 'conformance-2026-10-20-prelaunch.json'
    raw = report.read_bytes()
    summary = verify_report(raw, Policy.load(EVIDENCE / 'conformance-2026-10-20-prelaunch.policy.toml'), 1792540000)
    assert summary['report_sha256'] == '8a8c5920bde1594d746e5b369298871a846f03b494f47e08695a21f9a7b8eede' == H(raw)
    assert summary['counts'] == {'pass': 61, 'fail': 0, 'skip': 1} and summary['verdicts']['log.tombstone'] == 'skip'
    assert summary['g8_package'] == 'verified offline' and summary['run']['recorded'] is False
