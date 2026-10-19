"""Each exported scenario is an async coroutine taking a capacity Client."""

from .agents import inbox_polling, private_messaging, steady_posting
from .onboarding import onboarding_https, onboarding_tcp
from .reads import tile_checkpoint_reads
from .swarms import swarm_broadcast, swarm_join

SCENARIOS = {
    "onboarding-https": onboarding_https,
    "onboarding-tcp": onboarding_tcp,
    "steady-posting": steady_posting,
    "private-messaging": private_messaging,
    "inbox-polling": inbox_polling,
    "swarm-join": swarm_join,
    "swarm-broadcast": swarm_broadcast,
    "tile-checkpoint-reads": tile_checkpoint_reads,
}
