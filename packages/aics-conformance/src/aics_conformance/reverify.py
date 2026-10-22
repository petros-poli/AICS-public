"""Offline re-verification of a saved instance report: what a reader of published evidence can check with no
network, after the instance itself may be gone (``aics-conformance verify-report``).

It checks the report's own form and counts, that every archived checkpoint note is signed by the pinned log key
(historical: freshness ignored, the pinned witness policy stated per note), that G8's §14.3 verification package
verifies offline under the pinned trust, and that the archived notes and that package's complete entry prefix
describe one history (equal sizes, equal roots; every note the prefix covers has the prefix's root).  It does not
re-run any other check: their verdicts remain the harness's observations of the instance at the time.

A report written since 2026-10-20 also carries ``run`` (aics_conformance.provenance): the harness, the pins, the
selection and the operator's statement of the deployed image.  Its trust bundle must be the reader's, its selection
must be the checks the report holds, and the summary repeats it.  A report without ``run`` (the pre-launch report of
2026-10-20) is still read; the summary then says that its run is not recorded.
"""
import json
from aics_tlog import MerkleTree
from . import verify
from .protocol import DU, H, J, strict_json
from .provenance import RUN_MEMBERS
from .schema import require

#: The members ``aics-conformance run`` writes (cli.report plus the checkpoint archive); ``run`` is optional
#: (:data:`OPTIONAL_MEMBERS`), absent from reports written before it existed.
REPORT_MEMBERS = {'format', 'spec', 'mode', 'started_at', 'finished_at', 'counts', 'checks', 'checkpoint_archive'}
OPTIONAL_MEMBERS = {'run'}
RESULT_MEMBERS = {'id', 'title', 'spec_ref', 'verdict', 'details'}
#: The largest audit document an aics-server owner login accepts (AuditRequest.document; db.MAX_POLICY_DOCUMENT_BYTES).
MAX_AUDIT_DOCUMENT_BYTES = 262144


def verify_report(raw, policy, now):
    """``raw``: the report's exact bytes; ``policy``: the reader's own pins (never taken from the report).

    Returns a summary; raises ``ValueError`` at the first offline check that fails."""
    r = strict_json(raw)
    require(isinstance(r, dict) and REPORT_MEMBERS <= set(r) <= REPORT_MEMBERS | OPTIONAL_MEMBERS,
            'an instance report has exactly ' + ', '.join(sorted(REPORT_MEMBERS)) + ' and optionally run')
    require(r['format'] == 'aics-conformance/v1' and r['spec'] == 'AICS-1 0.2-draft' and r['mode'] == 'instance',
            'not an aics-conformance/v1 instance report of AICS-1 0.2-draft')
    checks = r['checks']
    require(isinstance(checks, list) and bool(checks), 'the report has no check results')
    for c in checks:
        require(isinstance(c, dict) and set(c) == RESULT_MEMBERS and c['verdict'] in ('pass', 'fail', 'skip'), 'check result shape')
    ids = [c['id'] for c in checks]
    require(len(set(ids)) == len(ids), 'a check appears twice')
    run = run_summary(r.get('run'), ids, policy)
    counts = {v: sum(c['verdict'] == v for c in checks) for v in ('pass', 'fail', 'skip')}
    require(r['counts'] == counts, 'the counts differ from the check verdicts')
    archive = r['checkpoint_archive']
    require(isinstance(archive, list) and all(isinstance(a, dict) and set(a) == {'note', 'observed_at'} for a in archive),
            'checkpoint archive shape')
    heads = [verify.head(DU(a['note']), policy, now, historical=True) for a in archive]
    package = None
    g8 = next((c for c in checks if c['id'] == 'G8'), None)
    if g8 is not None and g8['verdict'] == 'pass':
        package = g8['details']['package']
        verify.offline_package(package, policy, now)
    roots = {}
    for h in heads:
        require(roots.setdefault(h.cp.size, h.cp.root) == h.cp.root, 'split-proven: two archived notes of one size differ')
    covered = 0
    if package is not None:
        prefix = [DU(x) for x in package['entry_prefix']]
        tree = MerkleTree(prefix)
        for h in heads:
            if h.cp.size <= len(prefix):
                require(tree.root(h.cp.size) == h.cp.root, 'split-proven: an archived note conflicts with the G8 entry prefix')
                covered += 1
    return dict(
        report_sha256=H(raw), origin=policy.trust['origin'], log_vkey=policy.trust['log_vkey'], counts=counts,
        verdicts={c['id']: c['verdict'] for c in checks},
        archived_notes=dict(verified=len(heads), distinct_sizes=len(roots),
                            smallest=min(roots, default=None), largest=max(roots, default=None),
                            witness_policy_met=sum(h.witness_policy_met for h in heads), covered_by_g8_prefix=covered),
        g8_package='verified offline' if package is not None else 'absent (G8 did not pass or did not run)',
        run=run,
        scope='form and counts, archived notes under the pinned log key, the G8 package offline, one history; '
              'the other verdicts are the harness\'s observations at run time and are not re-derived')


def run_summary(run, ids, policy):
    """What the report's ``run`` member states, checked against the report and the reader's pins; ``None`` → a
    summary saying the run is not recorded (reports written before ``run`` existed)."""
    if run is None:
        return dict(recorded=False, note='this report predates the run member: its harness, pins and selection are '
                                         'stated only beside it (its policy file and description)')
    require(isinstance(run, dict) and set(run) == set(RUN_MEMBERS), 'run has exactly ' + ', '.join(RUN_MEMBERS))
    pins, selection, harness = run['pins'], run['selection'], run['harness']
    require(isinstance(pins, dict) and isinstance(selection, dict) and isinstance(harness, dict), 'run shape')
    require(pins.get('trust_bundle') == policy.trust and pins.get('trust_bundle_sha256') == H(J(policy.trust)),
            'the report ran with another trust bundle than the one you pin (run.pins)')
    require(selection.get('checks') == ids, 'run.selection.checks is not the list of checks the report holds')
    image = run['deployed_image']
    require(image is None or (isinstance(image, dict) and image.get('stated_by') == 'operator'), 'run.deployed_image shape')
    return dict(recorded=True, harness=harness, quorum=pins.get('quorum'), witness_vkeys=pins.get('witness_vkeys'),
                trust_bundle_sha256=pins['trust_bundle_sha256'], only=selection.get('only'),
                exclude=selection.get('exclude'), checks_selected=len(ids),
                deployed_image=image['id'] if image else None, policy_file_sha256=run['policy_file_sha256'])


def audit_document(raw, policy, now, url):
    """The short document an operator publishes as an audit leaf naming a report (``aics-conformance audit-document``).

    It re-verifies the report as :func:`verify_report` does and states its SHA-256, its size and where it is
    published byte for byte, the counts and verdicts, what ``run`` records and what the offline re-check covered.  The
    whole report is too large for an audit leaf (an aics-server owner login takes at most 262144 bytes, the
    pre-launch report alone is 447 KB); this document stays far below that, and is refused above it."""
    if not isinstance(url, str) or not url.startswith('https://') or any(c.isspace() for c in url):
        raise ValueError('--url must be the https URL the report is published at')
    summary = verify_report(raw, policy, now)
    r = strict_json(raw)
    document = dict(
        format='aics-conformance-audit/v1', spec='AICS-1 0.2-draft',
        report=dict(url=url, sha256=summary['report_sha256'], bytes=len(raw), format=r['format'], mode=r['mode'],
                    started_at=r['started_at'], finished_at=r['finished_at']),
        origin=summary['origin'], log_vkey=summary['log_vkey'], counts=summary['counts'], verdicts=summary['verdicts'],
        run=summary['run'], offline_recheck=dict(archived_notes=summary['archived_notes'], g8_package=summary['g8_package'],
                                                  scope=summary['scope']))
    text = json.dumps(document, ensure_ascii=False, indent=1) + '\n'
    require(len(text.encode('utf-8')) <= MAX_AUDIT_DOCUMENT_BYTES,
            f'the audit document is over {MAX_AUDIT_DOCUMENT_BYTES} bytes')
    return text
