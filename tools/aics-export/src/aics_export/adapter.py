"""Only deployment-specific paths and field mappings; never a trust source."""
from aics_conformance.client import HTTPTransport, Tiles
from aics_conformance.adapter import path
from aics_conformance.protocol import strict_json
from aics_conformance.schema import validate_entry

PUBLIC_TYPES = frozenset(('post', 'poll'))


class Source:
    def __init__(self, tiles, api, transport=None):
        self.tiles_url = tiles.rstrip('/')
        self.api = api.rstrip('/')
        self.transport = transport or HTTPTransport()
        self.tiles = Tiles(self.tiles_url, transport=self.transport)

    def checkpoint(self):
        return self.tiles.checkpoint()

    def reader(self, checkpoint):
        return self.tiles.authenticated(checkpoint)

    def body(self, digest):
        return self.transport.request('GET', self.api + path('body', hash=digest))


def entry(raw, origin):
    e = strict_json(raw)
    # Fail closed on unsupported schemas, including future extensions.
    validate_entry(e, origin)
    return e


def fields(e):
    return e['type'], e['actor_kid'], e['ts'], e['payload']
