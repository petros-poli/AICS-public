"""aics - verify an AICS log, its assurance card and your own keys yourself.

A thin CLI over ``aics-tlog`` and ``aics-identity``; keys are pinned out of
band (docs/spec/AICS-1.md §6.4), never taken from the server being checked.
Entry point: ``aics`` (:func:`aics_cli.cli.main`).
"""

__version__ = "0.1.1"
