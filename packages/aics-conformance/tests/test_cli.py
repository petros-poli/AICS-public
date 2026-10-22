import json
from aics_conformance.cli import main
from aics_conformance.core import CHECKS

def test_list(capsys):
    assert main(['list','--json'])==0
    rows=json.loads(capsys.readouterr().out)
    assert len(rows)==len(CHECKS)

def test_the_example_policy_loads_and_its_secret_sample_is_one_the_instance_refuses(tmp_path):
    import re
    from pathlib import Path
    from aics_conformance.fakes import FakeServer
    from aics_conformance.policy import Policy
    root=Path(__file__).resolve().parents[1]
    example=(root/'policy.example.toml').read_text()
    (tmp_path/'trust-bundle.json').write_text(json.dumps(FakeServer().trust))
    # The optional restart settings that need no further file, uncommented as an operator would: they must load.
    (tmp_path/'policy.toml').write_text(re.sub(r'^# (restart_command|restart_ready_seconds) = ',r'\1 = ',example,flags=re.M))
    policy=Policy.load(tmp_path/'policy.toml')
    assert policy.restart_command and policy.restart_ready_seconds>0
    # negative.secret-format submits secret_sample and expects the refusal secret_format:<secret_pattern_id>: the
    # instance scans with the pattern definitions it publishes (docs/legal/secret-patterns.json, which its card
    # hashes), so the sample must be one that the named definition matches.
    patterns=root.parents[1]/'docs/legal/secret-patterns.json'
    if not patterns.exists():
        import pytest
        pytest.skip('docs/legal/secret-patterns.json is not in this checkout')
    published=json.loads(patterns.read_text())['patterns']
    definition=next(d for d in published if d['id']==policy.secret_pattern_id)
    assert re.fullmatch(definition['regex'],policy.secret_sample)

def test_run_selection_by_only_and_exclude():
    import pytest
    from aics_conformance.cli import select
    ids=[c.id for c in CHECKS]
    assert [c.id for c in select()]==ids
    # The quorum-1 run against an instance whose card in force has quorum 0: everything but the card checks.
    left=[c.id for c in select(exclude=['G7','G10','rates.published'])]
    assert left==[i for i in ids if i not in ('G7','G10','rates.published')] and len(left)==len(ids)-3
    assert [c.id for c in select(only=['G8','G1'])]==['G1','G8']  # registration order, not argument order
    assert [c.id for c in select(only=['G8','G1'],exclude=['G1'])]==['G8']
    for bad in (dict(only=['G11']),dict(exclude=['g1'])):
        with pytest.raises(ValueError,match='unknown check IDs'): select(**bad)

def test_selftest(tmp_path):
    path=tmp_path/'selftest.json'
    assert main(['selftest','--mutations','--report',str(path)])==0
    report=json.loads(path.read_text())
    assert report['counts']=={'pass':len(CHECKS),'fail':0,'skip':0}
    assert all(m['detected'] for m in report['mutations'])


def test_the_tombstone_fixture_is_a_unique_body_that_log_tombstone_then_checks_through_the_body_service():
    from aics_conformance.fakes import FakeServer
    from aics_conformance.fixture import tombstone_fixture
    server=FakeServer(); ctx=server.context()
    made=tombstone_fixture(ctx); i=made['target_index']
    assert server.entries[i]['type']=='post' and server.entries[i]['payload']['body_hash']==made['body_hash']
    assert [e for e in server.entries if e['type']=='post' and e['payload']['body_hash']==made['body_hash']]==[server.entries[i]]
    # The fixture logs no decision of its own: the log holds no tombstone over it until the operator logs one.
    assert not [e for e in server.entries if e['type']=='tombstone' and e['payload']['target_index']==i]
    ctx.policy.tombstone_index=len(server.entries)  # no tombstone there yet: the check skips, it does not pass
    assert next(c for c in CHECKS if c.id=='log.tombstone').run(ctx)['verdict']=='skip'
    # The operator's tombstone (the fake's policy actor stands in for the owner tool).
    server.admin('tombstone',dict(target_index=i,reason_code='erasure',evidence_hash=None,receipt_hash=None))
    server.hidden[i]=len(server.entries)-1; server.bodies.pop(made['body_hash'],None)
    ctx.policy.tombstone_index=len(server.entries)-1
    result=next(c for c in CHECKS if c.id=='log.tombstone').run(ctx)
    assert result['verdict']=='pass',result['details']
    assert any(t['path']=='/v2/bodies/'+made['body_hash'] for t in ctx.client.transcript)  # not the shared-body shortcut


def test_the_tombstone_fixture_carries_the_operators_text_and_stays_unique():
    import pytest
    from aics_conformance.fakes import FakeServer
    from aics_conformance.fixture import tombstone_fixture
    server=FakeServer(); ctx=server.context()
    one=tombstone_fixture(ctx,'  Jane Operator, jane@example.test  '); two=tombstone_fixture(ctx,'Jane Operator, jane@example.test')
    assert one['text'].startswith('Jane Operator, jane@example.test ') and one['body_hash']!=two['body_hash']
    for bad in ('',' \n'):
        with pytest.raises(ValueError,match='non-empty'): tombstone_fixture(ctx,bad)


def _fake_run(tmp_path,server,*extra):
    """``aics-conformance run`` against the fake over loopback HTTP: two checks that only read."""
    from aics_conformance.fakes.network import http_server
    (tmp_path/'trust.json').write_text(json.dumps(server.trust))
    (tmp_path/'policy.toml').write_text('trust_file = "trust.json"\n')
    report=tmp_path/'out.json'
    with http_server(server) as url:
        code=main(['run','--api',url,'--gate','127.0.0.1:9','--tiles',url+'/tiles','--policy',str(tmp_path/'policy.toml'),
                   '--report',str(report),'--only','log.checkpoint','--only','log.metadata',*extra])
    return code,report


def test_a_run_records_its_harness_pins_selection_and_the_stated_image(tmp_path):
    from aics_conformance.fakes import FakeServer
    from aics_conformance.protocol import H,J
    from aics_conformance.provenance import source_sha256
    from aics_conformance.reverify import verify_report
    from aics_conformance.policy import Policy
    server=FakeServer(); image='sha256:'+'ab'*32
    code,report=_fake_run(tmp_path,server,'--deployed-image',image)
    assert code==0 and report.exists() and not (tmp_path/'out.json.partial').exists()
    obj=json.loads(report.read_text()); run=obj['run']
    assert [c['id'] for c in obj['checks']]==run['selection']['checks']==['log.checkpoint','log.metadata']
    assert run['selection']['only']==['log.checkpoint','log.metadata'] and run['selection']['exclude']==[]
    assert run['pins']['trust_bundle']==server.trust and run['pins']['trust_bundle_sha256']==H(J(server.trust))
    assert run['pins']['quorum']==0 and run['pins']['witness_vkeys']==[]
    assert run['policy_file_sha256']==H((tmp_path/'policy.toml').read_bytes())
    assert run['harness']['name']=='aics-conformance' and run['harness']['source_sha256']==source_sha256()
    assert run['deployed_image']=={'id':image,'stated_by':'operator','observed_by_harness':False}
    summary=verify_report(report.read_bytes(),Policy.load(tmp_path/'policy.toml'),server.now)
    assert summary['run']['recorded'] and summary['run']['deployed_image']==image and summary['run']['quorum']==0


def test_an_interrupted_run_leaves_only_a_partial_report(tmp_path,monkeypatch):
    # The report is saved after each check, but to <report>.partial: an interrupted run never leaves a file that reads
    # as a complete report (and ops/sync-docs.sh refuses a .partial name in docs/evidence).
    from aics_conformance import cli
    from aics_conformance.fakes import FakeServer
    first=next(c for c in CHECKS if c.id=='log.checkpoint')
    class Broken:
        id='log.metadata'
        def run(self,ctx): raise OSError('connection reset')
    monkeypatch.setattr(cli,'select',lambda only,exclude: [first,Broken()])
    code,report=_fake_run(tmp_path,FakeServer())
    partial=tmp_path/'out.json.partial'
    assert code==2 and not report.exists() and partial.exists()
    kept=json.loads(partial.read_text())
    assert [c['id'] for c in kept['checks']]==['log.checkpoint'] and kept['run']['selection']['checks']==['log.checkpoint','log.metadata']


def test_a_malformed_deployed_image_stops_the_run_before_any_check(tmp_path):
    from aics_conformance.fakes import FakeServer
    server=FakeServer(); before=len(server.entries)
    code,report=_fake_run(tmp_path,server,'--deployed-image','e3ab80670f4d')
    assert code==2 and not report.exists() and not (tmp_path/'out.json.partial').exists() and len(server.entries)==before


def test_version_prints_what_a_report_records(capsys):
    from aics_conformance.provenance import harness
    assert main(['version'])==0 and json.loads(capsys.readouterr().out)==harness()
