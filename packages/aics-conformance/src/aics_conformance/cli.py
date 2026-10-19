"""aics-conformance run/list/selftest."""
import argparse
import json
import sys
import time
from pathlib import Path
from . import checks, guarantees
from .core import CHECKS, Context
from .client import JSONClient, Tiles
from .policy import Policy


def report(results, *, mode, started):
    counts={v:sum(r['verdict']==v for r in results) for v in ('pass','fail','skip')}
    return dict(format='aics-conformance/v1',spec='AICS-1 0.2-draft',mode=mode,started_at=started,
                finished_at=time.time(),counts=counts,checks=results)


def save(path,obj):
    path=Path(path); tmp=path.with_name(path.name+'.tmp'); tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n'); tmp.replace(path)


def main(argv=None):
    p=argparse.ArgumentParser(description='Operator-run AICS-1 checks; run writes synthetic entries to the configured instance.')
    sub=p.add_subparsers(dest='command',required=True)
    listing=sub.add_parser('list'); listing.add_argument('--json',action='store_true')
    run=sub.add_parser('run')
    for arg in ('api','gate','tiles','policy','report'): run.add_argument('--'+arg,required=True)
    run.add_argument('--only',action='append',default=[],help='Exact check ID; repeatable (default all)')
    test=sub.add_parser('selftest'); test.add_argument('--report'); test.add_argument('--mutations',action='store_true',help='Also verify each check detects its paired fault')
    args=p.parse_args(argv)
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
            policy=Policy.load(args.policy); client=JSONClient(args.api,pages=policy.pages)
            ctx=Context(client,Tiles(args.tiles),policy,gate=args.gate)
            selected=[c for c in CHECKS if not args.only or c.id in args.only]
            unknown=set(args.only)-{c.id for c in CHECKS}
            if unknown: raise ValueError('unknown check IDs: '+', '.join(sorted(unknown)))
            results=[]
            for c in selected:
                print(c.id,file=sys.stderr,flush=True); results.append(c.run(ctx))
                save(args.report,report(results,mode='instance',started=started))
            obj=report(results,mode='instance',started=started)
            # Saved current heads are operator-observed evidence for later runs.
            obj['checkpoint_archive']=[{'note':__import__('aics_conformance.protocol',fromlist=['U']).U(h.raw),'observed_at':h.observed_at} for h in ctx.heads.values()]
            save(args.report,obj)
        print(f"{len(results)} checks: {obj['counts']['pass']} pass, {obj['counts']['fail']} fail, {obj['counts']['skip']} skip")
        if obj['counts']['fail'] or any(not m['detected'] for m in obj.get('mutations',[])): return 1
        return 2 if obj['counts']['skip'] else 0
    except (OSError,ValueError,KeyError) as exc:
        print(f'configuration/transport error: {exc}',file=sys.stderr); return 2

if __name__=='__main__': raise SystemExit(main())
