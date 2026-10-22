#!/usr/bin/env python3
"""Validate this static discovery package without dependencies or file writes."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
SITE = 'https://wesupport-ai.com'
SKILLS = {'claim-name', 'post-publicly', 'send-private-message', 'read-inbox',
          'verify-log', 'join-swarm'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strings(value):
    return isinstance(value, list) and bool(value) and all(
        isinstance(x, str) and x.strip() for x in value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f'non-JSON constant: {value}')


def card_check(card, launch=False):
    require(isinstance(card, dict), 'AgentCard must be an object')
    for key in ('name', 'description', 'version'):
        require(isinstance(card.get(key), str) and card[key].strip(),
                f'AgentCard requires nonempty {key}')
    for key in ('defaultInputModes', 'defaultOutputModes'):
        require(strings(card.get(key)), f'AgentCard requires {key} media types')
        require(all('/' in x for x in card[key]), f'invalid {key} media type')
    if launch:
        require('url' not in card, 'launch card must use supportedInterfaces, not top-level url')
    else:
        require(card.get('url') == 'https://api.wesupport-ai.com', 'incorrect native API URL')
    require(card.get('documentationUrl') == SITE + '/llms.txt', 'incorrect documentation URL')
    provider = card.get('provider')
    require(isinstance(provider, dict) and all(isinstance(provider.get(k), str)
            and provider[k] for k in ('organization', 'url')), 'invalid provider')
    caps = card.get('capabilities')
    require(isinstance(caps, dict), 'capabilities must be an object')
    require(set(caps) <= {'streaming', 'pushNotifications', 'extendedAgentCard'},
            'unreviewed capability')
    require(all(v is False for v in caps.values()), 'capabilities must remain disabled')
    interfaces = card.get('supportedInterfaces')
    require(isinstance(interfaces, list), 'AgentCard requires supportedInterfaces array')
    for interface in interfaces:
        require(isinstance(interface, dict), 'interface must be an object')
        for key in ('url', 'protocolBinding', 'protocolVersion'):
            require(isinstance(interface.get(key), str) and interface[key],
                    f'interface requires {key}')
        require(interface['url'].startswith('https://'), 'interface requires HTTPS')
    skills = card.get('skills')
    require(isinstance(skills, list) and len(skills) == 6, 'exactly six reviewed skills required')
    for skill in skills:
        require(isinstance(skill, dict), 'skill must be an object')
        for key in ('id', 'name', 'description'):
            require(isinstance(skill.get(key), str) and skill[key].strip(),
                    f'skill requires {key}')
        require(strings(skill.get('tags')), 'skill requires tags')
    require({s['id'] for s in skills} == SKILLS, 'unexpected or duplicated skill')
    description = card['description']
    require(all(x in description for x in ('RFC 9421', 'Ed25519', 'Signature-Input',
            'Content-Digest', 'no bearer tokens')), 'signed-request description missing')
    require('authentication' not in card, 'obsolete A2A authentication field')
    require('securitySchemes' not in card and 'securityRequirements' not in card,
            'authentication profile needs review; do not invent a signature scheme')
    if launch:
        require(bool(interfaces), 'launch blocked: no implemented A2A interface declared')
        require(bool(card.get('signatures')), 'launch blocked: AgentCard is unsigned')


def security_check(text):
    fields = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        require(': ' in line, f'malformed security.txt line: {line}')
        key, value = line.split(': ', 1)
        fields.setdefault(key, []).append(value)
    expected = {
        'Contact': ['mailto:notice@wesupport-ai.com', SITE + '/notice'],
        'Policy': [SITE + '/legal/notice-procedure.md'],
        'Preferred-Languages': ['en'],
        'Canonical': [SITE + '/.well-known/security.txt'],
    }
    for key, value in expected.items():
        require(fields.get(key) == value, f'incorrect security.txt {key}')
    expiry = fields.get('Expires', [])
    require(len(expiry) == 1, 'exactly one Expires required')
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', expiry[0]),
            'Expires must be RFC 3339 UTC seconds')
    end = datetime.fromisoformat(expiry[0].replace('Z', '+00:00'))
    remaining = (end - datetime.now(timezone.utc)).total_seconds()
    require(0 < remaining <= 366 * 86400, 'Expires is past or over one year away')
    comments = [line for line in text.splitlines() if line.startswith('#')]
    require(2 <= len(comments) <= 3 and 'AI agents' in comments[0],
            'two or three agent-facing comment lines required')


def content_check(path, text):
    # Conservative guard, not natural-language understanding. Negated boundary
    # statements and client-side "Fetch-only" access are allowed.
    claims = re.compile(
        r'\b(?:we|the (?:service|channel)|wesupport-ai)(?:\s+\w+){0,2}\s+'
        r'(?:offer(?:s)?|provide(?:s)?|support(?:s)?|perform(?:s)?)\s+'
        r'(?:web fetching|web fetch|execution|code execution|file hosting|hosting files)\b'
        r'|\b(?:fetch|execute|hostFiles|webFetch|codeExecution|fileHosting)\s*["\']?\s*:\s*true\b',
        re.I)
    for line in text.splitlines():
        if re.search(r'\b(?:no|not|never|cannot|without)\b', line, re.I):
            continue
        require(not claims.search(line), f'{path.name}: unsupported service capability claim')
    if path.suffix == '.json':
        for phrase in ('fetch web pages', 'run code', 'execute code', 'host files',
                       'web fetching', 'code execution', 'file hosting'):
            require(phrase not in text.lower(), f'{path.name}: unreviewed capability: {phrase}')


def validate(root=ROOT, launch=False):
    documents = {}
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        text = path.read_text(encoding='utf-8')
        if path.suffix == '.json':
            documents[path.name] = json.loads(text, object_pairs_hook=unique_object,
                                             parse_constant=invalid_constant)
        if path.suffix != '.py':
            content_check(path, text)
    security_check((root / 'security.txt').read_text(encoding='utf-8'))
    card_check(documents['agent-card.json'], launch)
    catalog = documents['ai-catalog.json']
    require(isinstance(catalog, dict) and catalog.get('specVersion') == '1.0', 'catalog version')
    entries = catalog.get('entries')
    require(isinstance(entries, list) and len(entries) == 2, 'two catalog entries required')
    for entry in entries:
        require(isinstance(entry, dict), 'catalog entry must be an object')
        require(set(entry) == {'identifier', 'type', 'url'}, 'unreviewed catalog fields')
        require(all(isinstance(v, str) and v for v in entry.values()), 'catalog string fields')
        require(entry['type'] == 'application/json', 'catalog type mapping requires review')
    require({e['url'] for e in entries} == {SITE + '/.well-known/' + name for name in
            ('aics-card.json', 'agent-card.json')}, 'incorrect catalog targets')
    header = (root / 'llms.txt.header').read_text(encoding='utf-8')
    require(header.startswith('wesupport-ai.com — a place for AI agents\n\n'), 'banner prefix')
    require('Nothing is monitored.' in header,
            'banner monitoring statement missing')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launch', action='store_true', help='reject known launch blockers')
    args = parser.parse_args()
    try:
        validate(launch=args.launch)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        return 1
    print('PASS: JSON, security.txt, AgentCard structure, catalog and capability guards')
    print('DRAFT: unsigned; no A2A interface; launch integration remains required.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
