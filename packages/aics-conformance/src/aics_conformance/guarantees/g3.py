import subprocess
from ..core import check,Skip
from ..protocol import U
from .. import verify
from ..schema import require


def wait_ready(ctx):
    """After an executed restart, wait at most ``restart_ready_seconds`` until the instance serves a checkpoint again.

    Only unavailability is waited out: ``OSError`` from the tile client, which is a refused or reset connection and
    HTTP 404, 408, 429 or 5xx (``client.Tiles.checkpoint``).  Whatever note is then served is verified by the scan
    that follows, exactly as without a wait; with the default bound 0 nothing is waited for.  Returns the seconds
    waited."""
    started=ctx.now(); pauses=ctx.pauses(ctx.policy.restart_ready_seconds)
    while True:
        try:
            ctx.tiles.checkpoint(); return ctx.now()-started
        except OSError as exc:
            if not next(pauses,False):
                raise OSError(f'instance not ready {ctx.now()-started:.0f} s after the restart (restart_ready_seconds '
                              f'{ctx.policy.restart_ready_seconds:g}): {exc}') from exc


@check('G3','History survives restart and extends saved checkpoints','AICS-1 §§6.1,14.2','restart_rollback')
def permanence(ctx):
    a=ctx.new_agent(); entry,note=ctx.post(a); ctx.follow(entry,note); before=ctx.head()
    executed=bool(ctx.restart or ctx.policy.restart_command)
    if ctx.restart: ctx.restart()
    elif ctx.policy.restart_command: subprocess.run(ctx.policy.restart_command,check=True,timeout=60,shell=False,capture_output=True)
    elif ctx.policy.saved_checkpoint is None: raise Skip('restart_command or pre-restart saved_checkpoint required')
    waited=wait_ready(ctx) if executed else None
    raw,after=ctx.scan(validate=False); verify.continuity(before,after,raw)
    if ctx.policy.saved_checkpoint:
        saved=verify.head(ctx.policy.saved_checkpoint,ctx.policy,ctx.now(),historical=True)
        ctx.evidence.setdefault('checkpoint_notes',[]).append(U(saved.raw)); verify.continuity(saved,after,raw)
        require(saved.witness_policy_met,saved.witness_error)
    result=dict(restart='executed' if executed else 'operator-attested between saved head and run')
    if executed: result['ready_after_seconds']=round(waited,3)
    return result
