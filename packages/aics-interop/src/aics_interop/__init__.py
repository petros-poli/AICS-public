"""aics-interop: AICS-1 artifacts produced by one package of this repository and verified by another.

Modules:

* :mod:`aics_interop.spec` - the suite's own reference encodings and verifiers, written from
  docs/spec/AICS-1.md alone (no sibling package is imported);
* :mod:`aics_interop.appendix_a` - AICS-1 Appendix A, read from the specification text;
* :mod:`aics_interop.aicslog`, :mod:`aics_interop.witnesses`, :mod:`aics_interop.world` - deterministic
  logs (aics-tlog), in-process witnesses (aics-witness) and the shared scenarios;
* :mod:`aics_interop.transport`, :mod:`aics_interop.drivers` - one fake web for aics and
  aics-conformance, and the drivers for both;
* :mod:`aics_interop.findings` - the open findings against the packages, as data;
* :mod:`aics_interop.generate` - the fixtures generator (``aics-interop-fixtures``).
"""

__version__ = "0.1.0"
