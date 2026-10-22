"""What a report states about its own run (the ``run`` member of an instance report).

A report is evidence only together with what produced it: the harness code, the pins it verified against, the checks
it selected and the instance it addressed.  ``run`` records them inside the hashed bytes, so that a card naming the
report's SHA-256 also fixes them: a reader sees, for instance, that a quorum-1 run left G7, G10 and
``rates.published`` out, which witness it pinned, and which trust bundle (by its AICS-1 §6.4 digest, ``hexH(J(...))``,
the one DNS and README publish).  ``deployed_image`` is what the operator stated with ``--deployed-image``
(``docker inspect``); the harness cannot observe which build answered it, so the member says who stated it.
"""
import re
from pathlib import Path
from . import __version__
from .protocol import H, J

#: The members of ``run`` (:func:`run_record`); verify-report checks exactly these.
RUN_MEMBERS = ('harness', 'target', 'selection', 'pins', 'restart', 'policy_file_sha256', 'deployed_image')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')


def source_sha256(root=None):
    """The digest of the harness's own source: ``hexH(J({relative path: hexH(bytes)}))`` over every ``.py`` file of
    the installed ``aics_conformance`` package (``__pycache__`` excluded).  ``aics-conformance version`` prints it,
    so a reader compares it with a checkout of the commit a report names."""
    root = Path(root or Path(__file__).resolve().parent)
    files = {p.relative_to(root).as_posix(): H(p.read_bytes()) for p in sorted(root.rglob('*.py'))
             if '__pycache__' not in p.parts}
    return H(J(files))


def harness():
    return dict(name='aics-conformance', version=__version__, source_sha256=source_sha256())


def deployed_image(value):
    """``--deployed-image``: an image ID ``sha256:<64 hex>`` as ``docker inspect --format '{{.Image}}'`` prints it."""
    if value is None:
        return None
    if not isinstance(value, str) or IMAGE_ID.fullmatch(value) is None:
        raise ValueError('--deployed-image must be an image ID, sha256: and 64 lowercase hex characters')
    return dict(id=value, stated_by='operator', observed_by_harness=False)


def run_record(policy, *, policy_file, api, gate, tiles, only=(), exclude=(), checks=(), image=None):
    """The ``run`` member: harness, target, selection, pins, restart, the policy file's digest, and ``image``, the
    operator's statement of the deployed image (:func:`deployed_image`) or None."""
    p = policy
    return dict(
        harness=harness(),
        target=dict(api=api, gate=gate, gate_plain=p.gate_plain, tiles=tiles, mirrors=list(p.mirrors), pages=p.pages),
        selection=dict(only=list(only), exclude=list(exclude), checks=list(checks)),
        pins=dict(trust_bundle=p.trust, trust_bundle_sha256=H(J(p.trust)), quorum=p.quorum,
                  witness_vkeys=list(p.witness_vkeys), max_checkpoint_age=p.max_checkpoint_age,
                  witness_wait_seconds=p.witness_wait_seconds, profiles=list(p.profiles),
                  saved_checkpoint_sha256=H(p.saved_checkpoint) if p.saved_checkpoint else None,
                  saved_card_sha256=H(J(p.saved_card)) if p.saved_card else None,
                  tombstone_index=p.tombstone_index, secret_pattern_id=p.secret_pattern_id),
        restart=dict(command=list(p.restart_command) if p.restart_command else None,
                     ready_seconds=p.restart_ready_seconds),
        policy_file_sha256=H(Path(policy_file).read_bytes()) if policy_file is not None else None,
        deployed_image=image,
    )
