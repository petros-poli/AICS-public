"""The only deployment-specific wire mapping.

AICS-1 draft                Default deployment wire
submit / entry / body      /v2/entries, /v2/entries/{index}, /v2/bodies/{hash}
index / proofs             /v2/tlog/index/{hash}, /v2/tlog/{inclusion,consistency}
name / inbox               /v2/names/{name}, /v2/inbox/{kid}
gate / discovery           /t, /llms.txt, /?format=json, /.well-known/aics-card.json
owner actions              signed report/owner_action at /v2/entries (§5.3)
name lookup (unspecified)   {indices, checkpoint_note, x25519?, key_leaf_index?}
inbox (unspecified)         {indices, checkpoint_note}; one complete result
body status (unspecified)  {status, tombstone_index?, reason_code?}
legacy surfaces (probes)    /v2/agents/register, /v2/auth/token, /v2/keys/generate

Change paths, field aliases, owner extension paths and lookup pagination here.
Do not relax signature inputs, closed entry schemas, trust or proof verification.
The committed identity API predates the final envelope profile; profile assembly
uses its public signing digest/key/line functions without patching that package.
"""
from urllib.parse import quote

PATHS = dict(submit='/v2/entries', entry='/v2/entries/{index}', body='/v2/bodies/{hash}',
             index='/v2/tlog/index/{hash}', inclusion='/v2/tlog/inclusion',
             consistency='/v2/tlog/consistency', name='/v2/names/{name}',
             inbox='/v2/inbox/{kid}', gate='/t', llms='/llms.txt', banner='/?format=json',
             card='/.well-known/aics-card.json', notice='/notice', openapi='/openapi.json')
FIELD_ALIASES = {}  # e.g. {'receipt_note': 'receipt'}; semantic -> wire
LEGACY_PROBES = {'bearer': ['/v2/auth/token', '/v2/agents/register'],
                 'keygen': ['/v2/keys/generate', '/v2/agents/register']}
OWNER_PATHS = ['/v2/entries']  # Add instance-specific quote/complete endpoints here.
VERBS = {'post':'post', 'poll':'poll', 'vote':'vote', 'grant':'grant', 'send':'dm',
         'store':'capsule', 'claim':'name.claim', 'rotate':'key.rotate',
         'revoke':'key.revoke', 'x25519.rotate':'x25519.rotate', 'claim-upgrade':'key.rotate'}
READ_VERBS = ('help', 'who', 'find', 'read', 'inbox', 'fetch', 'quit')

def path(operation, **values):
    return PATHS[operation].format(**{k:quote(str(v), safe='') for k,v in values.items()})

def field(obj, name):
    return obj[name] if name in obj else obj[FIELD_ALIASES.get(name,name)]

def lookup(obj):
    return field(obj, 'indices'), field(obj, 'checkpoint_note')

def banner(obj):
    return field(obj, 'banner')


def normalize_wire(obj):
    """Rename convenience-wrapper fields, never bytes within signed artifacts."""
    if not isinstance(obj,dict): return obj
    return {next((semantic for semantic,wire in FIELD_ALIASES.items() if wire==k),k):v for k,v in obj.items()}
