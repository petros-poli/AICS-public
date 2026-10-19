"""aics_witness - a C2SP tlog-witness for AICS transparency logs.

The witness keeps, per configured log, the latest checkpoint it cosigned
and cosigns a new one only after verifying the log's signature with the
configured log vkey and an RFC 6962 consistency proof from its last-seen
size (c2sp.org/tlog-witness, tlog-checkpoint, tlog-cosignature,
signed-note).  Cosignatures are Ed25519 cosignature/v1 lines.

* :mod:`aics_witness.service` - the HTTP witness (standard library only)
* :mod:`aics_witness.store` - SQLite state and the witness key
* :mod:`aics_witness.feeder` - the client a log uses to collect cosignatures
* :mod:`aics_witness.config` - the JSON configuration file
* :mod:`aics_witness.cli` - ``aics-witness init | serve | add-log | status |
  evidence | clear-timestamp``
"""

from ._version import __version__
from .config import ConfigError, LogConfig, WitnessConfig, load_config
from .feeder import (
    BadWitnessResponse,
    FeederError,
    WitnessAhead,
    WitnessClient,
    WitnessConflict,
    WitnessRejected,
    WitnessRolledBack,
    WitnessUnavailable,
    merge_cosignatures,
    submit_checkpoint,
)
from .service import Witness, WitnessError, WitnessHTTPServer, make_server
from .store import (
    SEED_ENV,
    KeyFileError,
    LogState,
    StoreError,
    WitnessStore,
    database_status,
    load_or_create_key,
)

__all__ = [
    "SEED_ENV",
    "BadWitnessResponse",
    "ConfigError",
    "FeederError",
    "KeyFileError",
    "LogConfig",
    "LogState",
    "StoreError",
    "Witness",
    "WitnessAhead",
    "WitnessClient",
    "WitnessConfig",
    "WitnessConflict",
    "WitnessError",
    "WitnessHTTPServer",
    "WitnessRejected",
    "WitnessRolledBack",
    "WitnessStore",
    "WitnessUnavailable",
    "__version__",
    "database_status",
    "load_config",
    "load_or_create_key",
    "make_server",
    "merge_cosignatures",
    "submit_checkpoint",
]
