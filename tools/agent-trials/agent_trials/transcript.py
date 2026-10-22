"""Transcript handling: redaction, normalisation of CLI stream-json, step detection,
refusal codes, friction quotes and forbidden production writes.

The CLIs print one JSON event per line (``--output-format stream-json`` for claude,
``-o stream-json`` for gemini, ``exec --json`` for codex).  All are reduced to a list of
:class:`Event` with a kind: ``text`` (the agent's own words), ``thinking`` (reasoning the CLI
exposes: claude's thinking blocks, codex's reasoning items; gemini's stream has none), ``plan``
(codex's todo list), ``tool_input`` (what it ran or fetched), ``tool_output`` (what came back,
e.g. the gate's replies), ``final``, ``note`` (codex file changes) or ``other``.  The detectors
read only ``tool_input``, ``tool_output`` and ``other`` (steps, refusals, forbidden writes) and
``text`` / ``final`` (the agent's words); the other kinds exist for the readable transcript.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

REDACTED = "[REDACTED]"

_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S)
_PEM_OPEN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.{0,4000}", re.S)
_TOKENS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bya29\.[A-Za-z0-9_\-\.]{20,}"),  # Google OAuth access tokens
    re.compile(r"\b1//[A-Za-z0-9_\-]{20,}"),  # Google OAuth refresh tokens
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9_\-\.=]{12,}"),
]
#: The gate's shared-secret fallback line (`secret <at least 32 characters>`), also right after an escaped
#: newline or tab (``printf 'claim x\nsecret …'``), where no word boundary precedes it.
_GATE_SECRET = re.compile(r"((?:\b|(?<=\\[nrt]))secret\s+)[^\s\"'\\]{16,}")


class Redactor:
    def __init__(self, secrets: list[str] | tuple[str, ...] = ()):
        self.secrets = sorted({s for s in secrets if s and len(s) >= 8}, key=len, reverse=True)

    def __call__(self, text: str) -> str:
        for secret in self.secrets:
            if secret in text:
                text = text.replace(secret, REDACTED)
        text = _PEM.sub("[REDACTED PRIVATE KEY]", text)
        text = _PEM_OPEN.sub("[REDACTED PRIVATE KEY]", text)
        for pattern in _TOKENS:
            if pattern.groups:
                text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
            else:
                text = pattern.sub(REDACTED, text)
        text = _GATE_SECRET.sub(lambda m: m.group(1) + REDACTED, text)
        return text


def redact_value(value, redact):
    """Every string of a decoded JSON value (keys included) redacted."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(str(k)): redact_value(v, redact) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, redact) for v in value]
    return value


def _redact_json_line(line: str, obj, redact) -> str:
    """One JSON event, redacted.  The line as received with its matches replaced, while that is still valid JSON
    and its decoded strings hold nothing more to redact; otherwise (a match broke the JSON, or a secret hid
    behind JSON escapes) the event re-serialised with every string redacted."""
    raw = redact(line)
    try:
        decoded = json.loads(raw)
    except ValueError:
        decoded = None
    if decoded is not None and redact_value(decoded, redact) == decoded:
        return raw
    return json.dumps(redact_value(obj, redact), ensure_ascii=False)


def redact_stream(text: str, redact) -> str:
    """A JSON-lines stream (a CLI's stdout) redacted event by event: a match can never reach across events (an
    unterminated private-key header no longer swallows the events after it), and every JSON line stays a valid
    JSON line.  Runs of non-JSON lines are redacted together, so a PEM block printed as plain text is caught."""
    out: list[str] = []
    plain: list[str] = []
    for line in text.split("\n"):
        stripped = line.strip()
        obj = None
        if stripped[:1] in ("{", "["):
            try:
                obj = json.loads(stripped)
            except ValueError:
                obj = None
        if not isinstance(obj, (dict, list)):
            plain.append(line)
            continue
        if plain:
            out.append(redact("\n".join(plain)))
            plain = []
        out.append(_redact_json_line(line, obj, redact))
    if plain:
        out.append(redact("\n".join(plain)))
    return "\n".join(out)


@dataclass
class Event:
    kind: str  # text | thinking | plan | tool_input | tool_output | final | note | other
    text: str
    tool: str = ""
    #: The tool call's id when the CLI gives one: pairs a tool_output with its tool_input.
    ref: str = ""
    #: What the CLI said about the event, for the readable transcript ("error", "exit 1", "delta", "user message",
    #: "lifecycle", "not json", "stderr", ...).  No detector reads it.
    note: str = ""
    #: The stdout line (1-based) the event came from; 0 when it did not come from stdout (stderr).
    line: int = 0


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list) and content and all(isinstance(b, dict) and "type" in b for b in content):
        # content blocks (claude's tool results): their text, not their type tags or an image's base64 data
        parts = []
        for block in content:
            if block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif block.get("type") in ("image", "document"):
                parts.append(f"[{block['type']}]")
            else:
                parts.append("\n".join(_strings(block)))
        return "\n".join(parts)
    return "\n".join(_strings(content))


#: Session bookkeeping events (claude's system init, gemini's init, codex's thread and turn events): no step can
#: be read from them, and the readable transcript shows them in its header, not in the conversation.
_LIFECYCLE = {"init", "thread.started", "turn.started", "turn.completed"}


def parse_events(stdout: str) -> list[Event]:
    events: list[Event] = []
    codex_started: set[str] = set()
    for number, line in enumerate(stdout.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            parsed = [Event("other", line, note="not json")]
        else:
            parsed = (_claude_events(obj) or _gemini_events(obj) or _codex_events(obj, codex_started)
                      or [Event("other", "\n".join(_strings(obj)), note=_other_note(obj))])
        for event in parsed:
            event.line = number
        events.extend(parsed)
    return events


def _other_note(obj: dict) -> str:
    kind = str(obj.get("type", ""))
    if kind in _LIFECYCLE or (kind == "system" and obj.get("subtype") == "init"):
        return "lifecycle"
    if kind in ("error", "turn.failed"):
        return "error"
    if kind == "system":
        return "system" + (f" {obj['subtype']}" if obj.get("subtype") else "")
    return kind


def _claude_events(obj: dict) -> list[Event]:
    kind = obj.get("type")
    if kind == "result":  # gemini's result event too (status, error)
        note = ", ".join(str(x) for x in (obj.get("subtype"), obj.get("status"),
                                          "is_error" if obj.get("is_error") else None, _error_note(obj.get("error")))
                         if x)
        return [Event("final", str(obj.get("result") or ""), note=note)]
    message = obj.get("message")
    if kind not in ("assistant", "user") or not isinstance(message, dict):
        return []
    out: list[Event] = []
    sub = "subagent" if obj.get("parent_tool_use_id") else ""
    content = message.get("content")
    if isinstance(content, str):
        return [Event("text" if kind == "assistant" else "other", content,
                      note=sub or ("" if kind == "assistant" else "user message"))]
    for block in content or []:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text" and kind == "assistant":
            out.append(Event("text", block.get("text", ""), note=sub))
        elif btype == "thinking" and kind == "assistant":
            out.append(Event("thinking", str(block.get("thinking") or ""), note=sub))
        elif btype == "redacted_thinking" and kind == "assistant":
            out.append(Event("thinking", "", note="redacted"))
        elif btype == "tool_use":
            out.append(Event("tool_input", json.dumps(block.get("input", {}), ensure_ascii=False),
                             str(block.get("name", "")), ref=str(block.get("id") or ""), note=sub))
        elif btype == "tool_result":
            note = ", ".join(x for x in ("error" if block.get("is_error") else "", sub) if x)
            out.append(Event("tool_output", _content_text(block.get("content")),
                             ref=str(block.get("tool_use_id") or ""), note=note))
    return out


def _error_note(error) -> str:
    if isinstance(error, dict):
        return " ".join(str(error[k]) for k in ("type", "message") if error.get(k))
    return str(error or "")


def _gemini_events(obj: dict) -> list[Event]:
    kind = obj.get("type")
    if kind == "message":
        if obj.get("role") == "assistant":
            return [Event("text", _content_text(obj.get("content")), note="delta" if obj.get("delta") else "")]
        return [Event("other", _content_text(obj.get("content")), note=f"{obj.get('role') or 'user'} message")]
    if kind == "tool_use":
        return [Event("tool_input", json.dumps(obj.get("parameters", obj.get("input", {})), ensure_ascii=False),
                      str(obj.get("tool_name", obj.get("name", ""))), ref=str(obj.get("tool_id") or ""))]
    if kind == "tool_result":
        note = ""
        if obj.get("status") == "error" or obj.get("error"):
            note = "error" + (f": {_error_note(obj.get('error'))}" if obj.get("error") else "")
        return [Event("tool_output", _content_text(obj.get("output", obj.get("result", ""))),
                      ref=str(obj.get("tool_id") or ""), note=note)]
    if kind == "result":
        return [Event("final", _content_text(obj.get("response", obj.get("result", ""))))]
    if kind == "error" or "error" in obj:
        return [Event("other", _content_text(obj.get("error", obj)), note="error")]
    return []


def _todo_text(items) -> str:
    lines = []
    for entry in items if isinstance(items, list) else []:
        if isinstance(entry, dict):
            lines.append(f"[{'x' if entry.get('completed') else ' '}] {entry.get('text', '')}")
    return "\n".join(lines)


def _codex_events(obj: dict, started: set[str]) -> list[Event]:
    """``codex exec --json``: ``item.started`` / ``item.completed`` events carrying an item (agent_message,
    command_execution, web_search, mcp_tool_call, ...).  A command is a tool input once (when it starts, or
    when it completes without a start event); its output arrives with the completion."""
    kind = obj.get("type")
    item = obj.get("item")
    if kind not in ("item.started", "item.updated", "item.completed") or not isinstance(item, dict):
        return []
    itype = str(item.get("type") or item.get("item_type") or "")
    iid = str(item.get("id", ""))
    quiet = [Event("other", "")]
    if itype == "agent_message":
        return [Event("text", str(item.get("text", "")))] if kind == "item.completed" else quiet
    if itype == "reasoning":
        return [Event("thinking", str(item.get("text", "")))] if kind == "item.completed" else quiet
    if itype == "todo_list":
        return [Event("plan", _todo_text(item.get("items")), ref=iid)]
    if itype == "file_change":
        if kind != "item.completed":
            return quiet
        changes = [f"{c.get('kind', '')} {c.get('path', '')}".strip() for c in item.get("changes") or []
                   if isinstance(c, dict)]
        return [Event("note", "\n".join(changes), "file_change", ref=iid, note=str(item.get("status") or ""))]
    if itype == "command_execution":
        out: list[Event] = []
        if kind == "item.started" or (kind == "item.completed" and iid not in started):
            started.add(iid)
            out.append(Event("tool_input", json.dumps({"command": item.get("command", "")}, ensure_ascii=False),
                             "command_execution", ref=iid))
        if kind == "item.completed":
            code = item.get("exit_code")
            note = ", ".join(x for x in (f"exit {code}" if code is not None else "",
                                         str(item.get("status") or "") if item.get("status") != "completed" else "")
                             if x)
            out.append(Event("tool_output", str(item.get("aggregated_output") or ""), ref=iid, note=note))
        return out or quiet
    if itype == "web_search":
        if kind != "item.completed":
            return quiet
        details = {k: v for k, v in item.items() if k not in ("id", "type")}
        return [Event("tool_input", json.dumps(details, ensure_ascii=False), "WebSearch", ref=iid)]
    if itype == "mcp_tool_call":
        if kind != "item.completed":
            return quiet
        name = ".".join(str(item.get(k, "")) for k in ("server", "tool") if item.get(k))
        events = [Event("tool_input", json.dumps(item.get("arguments", {}), ensure_ascii=False), name, ref=iid)]
        if item.get("result") is not None or item.get("error") is not None:
            events.append(Event("tool_output", _content_text(item.get("result") or item.get("error")), ref=iid,
                                note="error" if item.get("error") is not None else ""))
        return events
    if itype == "error":
        return [Event("other", str(item.get("message", "")), note="error")]
    return [Event("other", "\n".join(_strings({k: v for k, v in item.items() if k not in ("id", "type")})),
                  note=itype)]


def final_event(stdout: str) -> dict | None:
    """The CLI's final event: claude's and gemini's ``result``, else codex's last ``turn.completed`` or
    ``turn.failed``."""
    fallback = None
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "result":
            return event
        if fallback is None and event.get("type") in ("turn.completed", "turn.failed"):
            fallback = event
    return fallback


def agent_words(events: list[Event]) -> str:
    """The agent's own words; the final result is preferred when present."""
    finals = [e.text for e in events if e.kind == "final" and e.text.strip()]
    texts = [e.text for e in events if e.kind == "text"]
    if finals:
        # claude's final result repeats the last text block: keep earlier texts plus the final.
        return "\n".join(t for t in texts if t not in finals) + "\n" + "\n".join(finals)
    return "\n".join(texts)


# ----------------------------------------------------------------------
# steps
# ----------------------------------------------------------------------

#: Ordered steps: (key, label, where to look, pattern).  "out" = tool outputs (the
#: server's replies), "in" = tool inputs (what the agent ran), "any" = both.
STEPS: list[tuple[str, str, str, re.Pattern]] = [
    ("reached_site", "reached wesupport-ai.com", "any", re.compile(r"(?:[a-z0-9-]+\.)*wesupport-ai\.com", re.I)),
    ("gate_session", "gate session", "out",
     re.compile(r"(?m)^session [A-Za-z0-9_\-]{6,}\s*$|ok session \S+ is open")),
    ("tools_answer", "tools answer", "out",
     re.compile(r"ok openssl \(3\.0 or later|ok ssh-keygen: make your Ed25519|ok python3 with the cryptography"
                r"|\? Can you reach an online Ed25519")),
    ("key_made", "key made", "any",
     re.compile(r"genpkey\s+-algorithm\s+ed25519|ssh-keygen\s+-t\s+ed25519|Ed25519PrivateKey\.generate"
                r"|ok key \S+: now an X25519|ok key \S+ selected")),
    ("claim_accepted", "claim accepted", "out",
     re.compile(r"ok name \S+ bound to (?:key|unverified identity)|ok name \S+ upgraded to key")),
    ("introduced", "introduced", "out", re.compile(r"ok introduced \S+ at leaf \d+")),
    ("post_accepted", "post accepted", "out", re.compile(r"ok post at leaf \d+")),
    ("verification_done", "verification done", "in",
     re.compile(r"/(?:tiles/)?checkpoint\b", re.I)),
    ("grant_sent", "grant accepted", "out", re.compile(r"ok grant at leaf \d+")),
    ("dm_sent", "private message sent", "out", re.compile(r"ok dm at leaf \d+")),
    ("dm_received", "private message in inbox", "out", re.compile(r"ok dm \d+ from \S+")),
    ("swarm_joined", "swarm joined", "out", re.compile(r"ok swarm \S+ member \d+ at leaf \d+")),
    ("vote_cast", "swarm name vote", "out", re.compile(r"ok swarm-(?:propose|vote) at leaf \d+")),
    ("broadcast_sent", "broadcast sent", "out", re.compile(r"ok swarm-broadcast at leaf \d+")),
]

#: Columns of the per-agent table (spec order), plus scenario extras.
CORE_STEPS = ["gate_session", "tools_answer", "key_made", "claim_accepted", "post_accepted",
              "verification_done", "swarm_joined", "broadcast_sent"]
SCENARIO_STEPS = {
    "discovery": ["reached_site"],
    "onboarding": [],
    "dm": ["grant_sent", "dm_sent", "dm_received"],
    "swarm": ["introduced", "vote_cast"],
}

_TILE = re.compile(r"/tiles/tile/|/tiles/\d|inclusion|proof", re.I)
_REFUSAL = re.compile(r"(?m)(?:^|\n|\\n|\s)err ([a-z][a-z0-9_]{2,40})\b")


def _step_reached(key: str, where: str, pattern: re.Pattern, inputs: str, outputs: str) -> bool:
    hay = {"in": inputs, "out": outputs, "any": inputs + "\n" + outputs}[where]
    reached = bool(pattern.search(hay))
    if key == "verification_done":
        # Verification by hand: the checkpoint was fetched and a tile/proof was fetched or computed.
        reached = reached and bool(_TILE.search(inputs))
    return reached


def steps_reached(events: list[Event]) -> dict[str, bool]:
    inputs = "\n".join(e.text for e in events if e.kind == "tool_input")
    outputs = "\n".join(e.text for e in events if e.kind in ("tool_output", "other"))
    return {key: _step_reached(key, where, pattern, inputs, outputs) for key, _label, where, pattern in STEPS}


def first_reached(events: list[Event]) -> dict[str, int]:
    """For each step :func:`steps_reached` finds, the index of the event at which it first holds: the shortest
    prefix of ``events`` for which the same detector reports it (a binary search over prefixes)."""
    ins: list[str] = []
    outs: list[str] = []
    # in_end[k] / out_end[k]: the length of the joined tool inputs / outputs of events[:k], so that the detector's
    # text for a prefix is a slice of the whole run's text (each join is a prefix of the next).
    in_end, out_end = [0], [0]
    for event in events:
        if event.kind == "tool_input":
            in_end.append(in_end[-1] + len(event.text) + (1 if ins else 0))
            ins.append(event.text)
        else:
            in_end.append(in_end[-1])
        if event.kind in ("tool_output", "other"):
            out_end.append(out_end[-1] + len(event.text) + (1 if outs else 0))
            outs.append(event.text)
        else:
            out_end.append(out_end[-1])
    inputs, outputs = "\n".join(ins), "\n".join(outs)
    first: dict[str, int] = {}
    for key, _label, where, pattern in STEPS:
        def holds(k: int, key=key, where=where, pattern=pattern) -> bool:  # the detector on events[:k]
            return _step_reached(key, where, pattern, inputs[: in_end[k]], outputs[: out_end[k]])
        if not holds(len(events)):
            continue
        lo, hi = 1, len(events)
        while lo < hi:
            mid = (lo + hi) // 2
            if holds(mid):
                hi = mid
            else:
                lo = mid + 1
        first[key] = lo - 1
    return first


def refusal_codes(events: list[Event]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        if event.kind not in ("tool_output", "other"):
            continue
        for code in _REFUSAL.findall(event.text):
            counts[code] = counts.get(code, 0) + 1
    return dict(sorted(counts.items()))


# ----------------------------------------------------------------------
# friction quotes and obstacles
# ----------------------------------------------------------------------

_FRICTION = re.compile(
    r"confus|unclear|obstacle|couldn'?t|could not|unable|stuck|didn'?t work|not sure|ambiguous|refus|reject"
    r"|difficult|blocked|unexpected|frustrat|failed|failing|error|mismatch|no idea|wasn'?t clear|tricky",
    re.I,
)
#: Report-template headings ("CONFUSING REPLIES:") are not the agent's words about friction.
_HEADING = re.compile(r"^[A-Z][A-Z \-/]{2,}:?\s*$")
_LONG_B64 = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip(" -*#>\t") for p in parts if p.strip(" -*#>\t")]


def safe_quote(text: str, limit: int = 220) -> str | None:
    """A quote fit for the report: no key material, no long opaque strings."""
    if "PRIVATE KEY" in text or REDACTED in text or _LONG_B64.search(text):
        return None
    text = " ".join(text.split())
    if len(text) < 12:
        return None
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def friction_quotes(events: list[Event], limit: int = 2) -> list[str]:
    quotes: list[str] = []
    for sentence in _sentences(agent_words(events)):
        if _HEADING.match(sentence) or not _FRICTION.search(sentence):
            continue
        quote = safe_quote(sentence)
        if quote and quote not in quotes:
            quotes.append(quote)
        if len(quotes) >= limit:
            break
    return quotes


_SECTION = re.compile(r"^\W*(?i:obstacles?|friction|problems?|issues?)\b[^\n]*$|\bOBSTACLES?:[^\n]*$", re.M)
_NEXT_SECTION = re.compile(r"(?m)^\W*[A-Z][A-Z \-/]{3,}:?\s*$|^#{1,6}\s")
_BULLET = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+(.*)$")


def reported_obstacles(events: list[Event]) -> list[str]:
    """Bullet items under an OBSTACLES heading in the agent's own report."""
    words = agent_words(events)
    found: list[str] = []
    for match in _SECTION.finditer(words):
        tail = words[match.end():]
        stop = _NEXT_SECTION.search(tail)
        block = tail[: stop.start()] if stop else tail
        for line in block.splitlines():
            bullet = _BULLET.match(line)
            if bullet:
                quote = safe_quote(bullet.group(1).replace("**", ""), limit=200)
                if quote and quote.lower() not in ("none", "none."):
                    found.append(quote)
    seen: set[str] = set()
    unique = []
    for item in found:
        key = obstacle_key(item)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def obstacle_key(text: str) -> str:
    return re.sub(r"[^a-z0-9 ]+", "", text.lower())[:80].strip()


# ----------------------------------------------------------------------
# forbidden writes
# ----------------------------------------------------------------------

_HOST = re.compile(r"\b((?:[a-z0-9-]+\.)*wesupport-ai\.com)\.?(?![a-z0-9-])", re.I)
_WRITE_MARKERS = re.compile(
    r"-X\s*POST|--request\s+POST|-X\s*PUT|-X\s*DELETE|--data|\s-d\s|\s-d'|\s-d\"|--data-binary|--data-raw|\s-F\s"
    r"|--form|--upload-file|\bpost\(|\.post\b|method\s*[=:]\s*['\"]?post|\"method\":\s*\"post\"|urlopen\(.*data="
    r"|\bPOST\b",
    re.I,
)
#: Production's text gate ports in any connecting form: host:7701, "host 7701" (nc, telnet), ("host", 7701),
#: port=7701, -p 7701, '7701'.  On the single-IP VPS, test.wesupport-ai.com:7700/7701 is production too.
_GATE_PORT = re.compile(r"(?:[:=,(\s'\"]|\bport\s*[=:]?\s*|-p\s*)\s*['\"]?77(?:00|01)(?![\d.])", re.I)
_IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_URL = re.compile(r"https?://([^/\s'\"?#\\]+)([^\s'\"\\]*)", re.I)
_GATE_QUERY = re.compile(r"^/t/?\?(?:[^#]*&)?[ls]=", re.I)


#: Tools that can only read (a fetch or a search).  Only the URLs they fetch are checked: their prompts
#: may mention POST or 7700 harmlessly, but a GET /t with l= or s= is a gate session (GET /t onboards keys).
READ_ONLY_TOOLS = {"webfetch", "websearch", "web_fetch", "google_web_search", "read", "read_file",
                   "read_many_files", "glob", "grep", "list_directory", "search_file_content"}


def _norm_host(host: str) -> str:
    host = host.lower().rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def _is_public_ip(text: str) -> bool:
    first, second = (int(x) for x in text.split(".")[:2])
    return not (first in (0, 10, 127) or (first == 169 and second == 254) or (first == 172 and 16 <= second <= 31)
                or (first == 192 and second == 168) or first >= 224)


def _url_values(text: str) -> str:
    try:
        data = json.loads(text)
    except ValueError:
        return text
    return "\n".join(v for v in _strings(data) if re.match(r"\s*https?://", v, re.I))


@dataclass
class ForbiddenWrite:
    reason: str
    targets: list[str]
    #: The text the check read: the tool input, or for a read-only tool only the URLs it fetched.
    text: str

    def describe(self) -> str:
        snippet = safe_quote(self.text, limit=200) or "(command contains opaque data; see transcript)"
        return f"{self.reason} to {', '.join(self.targets)}: {snippet}"

    def lines(self, text: str | None = None) -> list[str]:
        """The lines of ``text`` (default: the checked text) that name a target or production's gate port."""
        hosts = [t.lower() for t in self.targets if not t.startswith("(")]
        return [line for line in (self.text if text is None else text).splitlines()
                if any(h in line.lower() for h in hosts) or _GATE_PORT.search(line)]


def forbidden_write(event: Event, allowed_hosts: set[str], production_ips: list[str] | tuple[str, ...] | set[str] = ()
                    ) -> ForbiddenWrite | None:
    """Whether one tool input wrote, or tried to write, to production (see :func:`forbidden_writes`)."""
    if event.kind != "tool_input":
        return None
    allowed = {h.lower().rstrip(".") for h in allowed_hosts}
    prod_ips = set(production_ips)
    read_only = event.tool.lower() in READ_ONLY_TOOLS
    text = _url_values(event.text) if read_only else event.text
    if not text.strip():
        return None
    named = {h.lower() for h in _HOST.findall(text)}
    ips = set(_IPV4.findall(text))
    production = (named - allowed) | (ips & prod_ips)
    reason = None
    targets: set[str] = set(production)
    gate_urls = [u for u in _URL.finditer(text)
                 if (_norm_host(u.group(1)) in production or _norm_host(u.group(1)) in prod_ips)
                 and _GATE_QUERY.match(u.group(2) or "")]
    if _GATE_PORT.search(text) and (not read_only or _URL.search(text)):
        reason = "TCP/TLS connection to production's gate port 7700/7701"
        targets |= named | (ips & prod_ips) or {"(host not named)"}
    elif production and not read_only and _WRITE_MARKERS.search(text):
        reason = "HTTP write"
    elif gate_urls:
        reason = "GET /t gate session (l= or s=)"
    elif not read_only and _WRITE_MARKERS.search(text) and {ip for ip in ips if _is_public_ip(ip)} - prod_ips:
        reason = "HTTP write to an IP literal (production's address unknown to the check)"
        targets |= {ip for ip in ips if _is_public_ip(ip)}
    return ForbiddenWrite(reason, sorted(targets), text) if reason else None


def forbidden_writes(events: list[Event], allowed_hosts: set[str], production_ips: list[str] | tuple[str, ...] = ()
                     ) -> list[str]:
    """Tool inputs that wrote, or tried to write, to production: a TCP connection to the gate ports
    7700/7701 on any host (staging's own host included: same IP), an HTTP request with a body or a write
    method to a wesupport-ai.com host other than staging or to a production IP, a GET /t carrying a line
    or session (l= / s=) on such a host, or an HTTP write to any other public IP literal."""
    found = (forbidden_write(event, allowed_hosts, production_ips) for event in events)
    return [item.describe() for item in found if item is not None]


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()
