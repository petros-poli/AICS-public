"""aics-conformance run/list/selftest/tombstone-fixture/verify-report/audit-document/version."""
import argparse
import json
import sys
import time
from pathlib import Path
from . import checks, guarantees
from .core import CHECKS, Context
from .client import JSONClient, Tiles
from .policy import Policy


def report(results, *, mode, started, run=None):
    """The report object; ``run`` (:func:`aics_conformance.provenance.run_record`) is part of an instance report."""
    counts={v:sum(r['verdict']==v for r in results) for v in ('pass','fail','skip')}
    obj=dict(format='aics-conformance/v1',spec='AICS-1 0.2-draft',mode=mode)
    if run is not None: obj['run']=run
    obj.update(started_at=started,finished_at=time.time(),counts=counts,checks=results)
    return obj


def select(only=(),exclude=()):
    """The checks a run executes, in registration order: every check, or exactly the ``only`` IDs, minus the
    ``exclude`` IDs.  An unknown ID is a configuration error, raised before anything runs.  A run of a subset can
    pass; it never establishes full conformance."""
    unknown=(set(only)|set(exclude))-{c.id for c in CHECKS}
    if unknown: raise ValueError('unknown check IDs: '+', '.join(sorted(unknown)))
    return [c for c in CHECKS if (not only or c.id in only) and c.id not in exclude]


def save(path,obj):
    path=Path(path); tmp=path.with_name(path.name+'.tmp'); tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n'); tmp.replace(path)


def partial_path(path):
    """Where a run keeps its report while checks are still running: ``<report>.partial``.  Only a run that went through
    every selected check writes ``<report>`` itself, so an interrupted run never leaves a report that reads as
    complete (ops/sync-docs.sh refuses a ``.partial`` file in docs/evidence)."""
    path=Path(path); return path.with_name(path.name+'.partial')


def main(argv=None):
    p=argparse.ArgumentParser(description='Operator-run AICS-1 checks; run writes synthetic entries to the configured instance.')
    sub=p.add_subparsers(dest='command',required=True)
    listing=sub.add_parser('list'); listing.add_argument('--json',action='store_true')
    run=sub.add_parser('run')
    for arg in ('api','gate','tiles','policy','report'): run.add_argument('--'+arg,required=True)
    run.add_argument('--only',action='append',default=[],help='Exact check ID; repeatable (default all)')
    run.add_argument('--exclude',action='append',default=[],help='Exact check ID left out; repeatable (a pin stricter than the card in force fails G7, G10 and rates.published)')
    run.add_argument('--deployed-image',metavar='IMAGE_ID',help='The image ID the instance runs, as docker inspect prints it '
                     '(sha256:<64 hex>); recorded in the report as stated by the operator, never observed by the harness')
    test=sub.add_parser('selftest'); test.add_argument('--report'); test.add_argument('--mutations',action='store_true',help='Also verify each check detects its paired fault')
    fixture=sub.add_parser('tombstone-fixture',help='Write one unique public post (a disposable agent) that the operator may tombstone '
                           'for a reason that is true of it (AICS-1 §10.3); it names no reason code')
    for arg in ('api','gate','tiles','policy'): fixture.add_argument('--'+arg,required=True)
    fixture.add_argument('--text',help='The body text before its random token (default: a synthetic text, of which no '
                         'tombstone reason is true), e.g. your own personal data whose erasure you then request')
    again=sub.add_parser('verify-report',help='Re-verify a saved instance report offline (no network): archived notes, the G8 package, one history')
    again.add_argument('--report',required=True); again.add_argument('--policy',required=True,help='Your own pins (trust bundle, witness policy); never the report\'s')
    audit=sub.add_parser('audit-document',help='verify-report, then print the short JSON document an operator publishes as an '
                         'audit leaf naming the report (the full report is too large for one)')
    audit.add_argument('--report',required=True); audit.add_argument('--policy',required=True,help='Your own pins, as for verify-report')
    audit.add_argument('--url',required=True,help='The https URL where the report is published byte for byte')
    sub.add_parser('version',help='The harness name, version and source digest a report records in run.harness')
    args=p.parse_args(argv)
    if args.command=='version':
        from .provenance import harness
        print(json.dumps(harness(),indent=2)); return 0
    if args.command=='audit-document':
        from .reverify import audit_document
        try:
            document=audit_document(Path(args.report).read_bytes(),Policy.load(args.policy),time.time(),args.url)
        except (OSError,ValueError,KeyError,TypeError) as exc:
            print(f'no audit document: {exc}',file=sys.stderr); return 1
        sys.stdout.write(document); return 0
    if args.command=='verify-report':
        from .reverify import verify_report
        try:
            summary=verify_report(Path(args.report).read_bytes(),Policy.load(args.policy),time.time())
        except (OSError,ValueError,KeyError,TypeError) as exc:
            print(f'report does not verify: {exc}',file=sys.stderr); return 1
        print(json.dumps(summary,indent=2)); return 0
    if args.command=='tombstone-fixture':
        from .fixture import tombstone_fixture
        try:
            policy=Policy.load(args.policy)
            ctx=Context(JSONClient(args.api,pages=policy.pages),Tiles(args.tiles),policy,gate=args.gate)
            print(json.dumps(tombstone_fixture(ctx,args.text),indent=2)); return 0
        except (OSError,ValueError,KeyError) as exc:
            print(f'configuration/transport error: {exc}',file=sys.stderr); return 2
    if args.command=='list':
        rows=[dict(id=c.id,title=c.title,spec_ref=c.spec_ref) for c in CHECKS]
        if args.json: print(json.dumps(rows,indent=2))
        else:
            for row in rows: print(f"{row['id']:28} {row['title']} ({row['spec_ref']})")
        return 0
    started=time.time()
    try:
        if args.command=='selftest':
            from .fakes import FakeServer
            results=[c.run(FakeServer().context()) for c in CHECKS]
            obj=report(results,mode='fake',started=started)
            if args.mutations:
                obj['mutations']=[{'id':c.id,'fault':c.fault,'detected':c.run(FakeServer(c.fault).context())['verdict']=='fail'} for c in CHECKS]
            if args.report: save(args.report,obj)
        else:
            from .provenance import deployed_image, run_record
            from .protocol import U
            policy=Policy.load(args.policy); client=JSONClient(args.api,pages=policy.pages)
            ctx=Context(client,Tiles(args.tiles),policy,gate=args.gate)
            selected=select(args.only,args.exclude)
            run=run_record(policy,policy_file=args.policy,api=args.api,gate=args.gate,tiles=args.tiles,only=args.only,
                           exclude=args.exclude,checks=[c.id for c in selected],image=deployed_image(args.deployed_image))
            results=[]; partial=partial_path(args.report)
            for c in selected:
                print(c.id,file=sys.stderr,flush=True); results.append(c.run(ctx))
                save(partial,report(results,mode='instance',started=started,run=run))
            obj=report(results,mode='instance',started=started,run=run)
            # Saved current heads are operator-observed evidence for later runs.
            obj['checkpoint_archive']=[{'note':U(h.raw),'observed_at':h.observed_at} for h in ctx.heads.values()]
            save(args.report,obj); partial.unlink(missing_ok=True)
        print(f"{len(results)} checks: {obj['counts']['pass']} pass, {obj['counts']['fail']} fail, {obj['counts']['skip']} skip")
        if obj['counts']['fail'] or any(not m['detected'] for m in obj.get('mutations',[])): return 1
        return 2 if obj['counts']['skip'] else 0
    except (OSError,ValueError,KeyError) as exc:
        print(f'configuration/transport error: {exc}',file=sys.stderr); return 2

if __name__=='__main__': raise SystemExit(main())
