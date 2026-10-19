import subprocess
from ..core import check,Skip
from ..protocol import U
from .. import verify
from ..schema import require
@check('G3','History survives restart and extends saved checkpoints','AICS-1 §§6.1,14.2','restart_rollback')
def permanence(ctx):
    a=ctx.new_agent(); entry,note=ctx.post(a); ctx.follow(entry,note); before=ctx.head()
    if ctx.restart: ctx.restart()
    elif ctx.policy.restart_command: subprocess.run(ctx.policy.restart_command,check=True,timeout=60,shell=False,capture_output=True)
    elif ctx.policy.saved_checkpoint is None: raise Skip('restart_command or pre-restart saved_checkpoint required')
    raw,after=ctx.scan(validate=False); verify.continuity(before,after,raw)
    if ctx.policy.saved_checkpoint:
        saved=verify.head(ctx.policy.saved_checkpoint,ctx.policy,ctx.now(),historical=True)
        ctx.evidence.setdefault('checkpoint_notes',[]).append(U(saved.raw)); verify.continuity(saved,after,raw)
        require(saved.witness_policy_met,saved.witness_error)
    return dict(restart='executed' if ctx.restart or ctx.policy.restart_command else 'operator-attested between saved head and run')
