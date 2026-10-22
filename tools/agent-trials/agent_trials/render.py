"""Readable per-agent transcripts: ``transcript.md`` beside each agent's saved event stream.

An agent directory (``runs/<stamp>/<scenario>/<provider>-<n>/``) holds ``transcript.jsonl`` (the CLI's stdout as
received, redacted: claude's ``--output-format stream-json``, gemini's ``-o stream-json`` or codex's
``exec --json``), ``stderr.txt``, ``meta.json``, ``prompt.txt`` and, when the CLI ended with one, ``result.json``.
:func:`render_agent` turns them into Markdown: a header (provider, model, scenario, start and end, exit status,
wall time, whether the time limit was hit), then the conversation in order (the agent's text, any thinking or
plan the CLI exposes, each tool call and each tool result, results cut to ``max_chars``), the final report and
stderr.  Where the harness's step detector first saw each milestone, and every tool call its
forbidden-production-write detector flagged, is marked inline: the detectors run on exactly the events
REPORT.md is built from (:func:`load_trial`).

Everything shown passes through the redactor again (the run's known secrets when the runner renders, the
pattern rules when ``run.py render`` re-renders an old run).
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import transcript as tr

TRANSCRIPT_MD = "transcript.md"
RAW_STREAM = "transcript.jsonl"
STDERR = "stderr.txt"
#: Tool results (and other CLI events, stderr) are cut to this many characters by default.
DEFAULT_MAX_CHARS = 4000
#: Tool calls are shown whole up to this many characters; a longer one (a large heredoc) is cut in the middle.
MAX_INPUT_CHARS = 20000

STATUS_NOTE = {
    "ok": "finished",
    "timeout": "hit the wall-clock limit",
    "needs_sign_in": "needs sign-in",
    "error": "CLI exited with an error",
    "unavailable": "provider unavailable",
    "runner_error": "runner error",
}

#: What each CLI's stream exposes of the agent's reasoning.
_THINKING_NOTE = {
    "claude": "claude's stream-json carries thinking blocks when the model returns them",
    "gemini": "gemini's stream-json carries no thinking, only its messages, tool calls and results",
    "codex": "codex's exec --json carries reasoning items (summaries) and its todo list",
}
_SHELLS = {"bash", "sh", "zsh", "dash"}


@dataclass
class Trial:
    dir: Path
    meta: dict
    stdout: str
    stderr: str
    #: The stdout events, then stderr as one last ``other`` event: what REPORT.md's detectors read.
    events: list[tr.Event]
    allowed_hosts: set[str]
    production_ips: list[str]


def _read(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def load_trial(agent_dir: Path, meta: dict | None = None) -> Trial:
    agent_dir = Path(agent_dir)
    if meta is None:
        meta = json.loads((agent_dir / "meta.json").read_text())
    stdout = _read(agent_dir / RAW_STREAM)
    stderr = _read(agent_dir / STDERR)
    events = tr.parse_events(stdout)
    if stderr.strip():
        events.append(tr.Event("other", stderr, note="stderr"))
    staging = meta.get("staging_host") or tr.host_of(meta.get("base_url", ""))
    return Trial(agent_dir, meta, stdout, stderr, events, {staging} if staging else set(),
                 list(meta.get("production_ips") or ()))


def agent_dirs(path: Path) -> list[Path]:
    """The agent directories of a run directory, or ``path`` itself when it is one."""
    path = Path(path)
    if (path / "meta.json").exists():
        return [path]
    return sorted(p.parent for p in path.glob("*/*/meta.json"))


def write_transcript(agent_dir: Path, *, meta: dict | None = None, redact: Callable[[str], str] | None = None,
                     max_chars: int = DEFAULT_MAX_CHARS) -> Path:
    out = Path(agent_dir) / TRANSCRIPT_MD
    out.write_text(render_agent(agent_dir, meta=meta, redact=redact, max_chars=max_chars))
    return out


def render_run(path: Path, *, max_chars: int = DEFAULT_MAX_CHARS) -> list[Path]:
    return [write_transcript(d, max_chars=max_chars) for d in agent_dirs(path)]


def render_agent(agent_dir: Path, *, meta: dict | None = None, redact: Callable[[str], str] | None = None,
                 max_chars: int = DEFAULT_MAX_CHARS) -> str:
    return _Renderer(load_trial(agent_dir, meta), redact or tr.Redactor(), max_chars).render()


# ----------------------------------------------------------------------
# Markdown helpers
# ----------------------------------------------------------------------

def fence(text: str, lang: str = "text") -> str:
    """A fenced block that the content cannot close (longer than any backtick run in it)."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text.rstrip(chr(10))}\n{ticks}"


def quote(text: str) -> str:
    return "\n".join(f"> {line}" if line.strip() else ">" for line in text.rstrip().splitlines()) or ">"


def clip(text: str, limit: int, *, tail_share: float = 0.25) -> tuple[str, str]:
    """``text`` cut to ``limit`` characters (its start and its end), and a note giving the full length;
    ``limit`` <= 0 keeps everything."""
    if limit <= 0 or len(text) <= limit:
        return text, ""
    tail = int(limit * tail_share)
    head = limit - tail
    omitted = len(text) - limit
    shown = text[:head].rstrip("\n") + f"\n[... {omitted} characters omitted ...]\n" + (text[-tail:] if tail else "")
    where = f"the first {head}" + (f" and the last {tail}" if tail else "")
    return shown, f"full length {len(text)} characters; showing {where}"


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" + ("" if n == 1 else "s")


def _lines(first: int, last: int) -> str:
    if not first:
        return ""
    return f"line {first}" if last in (0, first) else f"lines {first}-{last}"


def _join_argv(argv: list) -> str:
    parts = [str(a) for a in argv]
    if len(parts) == 3 and os.path.basename(parts[0]) in _SHELLS and parts[1] in ("-c", "-lc"):
        return parts[2]
    return shlex.join(parts)


def _kv(args: dict) -> str:
    out: list[str] = []
    for key, value in args.items():
        if isinstance(value, str) and "\n" in value:
            out.append(f"{key}: |")
            out.extend(f"  {line}" for line in value.splitlines())
        elif isinstance(value, str):
            out.append(f"{key}: {value}")
        else:
            out.append(f"{key}: {json.dumps(value, ensure_ascii=False)}")
    return "\n".join(out)


def call_body(tool: str, text: str) -> tuple[str, str, list[str]]:
    """How to show a tool call: (fence language, body, caption lines)."""
    try:
        args = json.loads(text)
    except ValueError:
        return "text", text, []
    if not isinstance(args, dict):
        return "text", json.dumps(args, indent=2, ensure_ascii=False), []
    command = args.get("command")
    shell = ""
    if isinstance(command, str) and re.match(r"^\S*(?:bash|sh|zsh|dash) -l?c ", command):
        try:  # codex's "bash -lc '<script>'": show the script
            argv = shlex.split(command)
        except ValueError:
            argv = []
        if len(argv) == 3 and _join_argv(argv) != shlex.join(argv):
            shell, command = f"{os.path.basename(argv[0])} {argv[1]}", argv[2]
    if isinstance(command, list):
        if _join_argv(command) != shlex.join([str(a) for a in command]):
            shell = f"{os.path.basename(str(command[0]))} {command[1]}"
        command = _join_argv(command)
    if isinstance(command, str):
        rest = {k: v for k, v in args.items() if k != "command"}
        captions = [f"run with `{shell}`"] if shell else []
        description = rest.pop("description", None)
        if isinstance(description, str) and description.strip():
            captions.append(description.strip())
        if rest:
            captions.append("arguments: " + ", ".join(f"{k}={json.dumps(v, ensure_ascii=False)}"
                                                      for k, v in rest.items()))
        return "bash", command, captions
    todos = args.get("todos")
    if isinstance(todos, list) and all(isinstance(t, dict) for t in todos):
        marks = {"completed": "x", "in_progress": "~"}
        return "text", "\n".join(f"[{marks.get(str(t.get('status')), ' ')}] {t.get('content', t.get('text', ''))}"
                                 for t in todos), []
    return "text", _kv(args) if args else "(no arguments)", []


#: The CLI family of each provider (sonnet, glm53 and glm53flash run claude).
_FAMILY = {"gemini": "gemini", "sol": "codex", "sonnet": "claude", "glm53": "claude", "glm53flash": "claude"}


def _family(stdout: str, provider: str) -> str:
    if provider in _FAMILY:
        return _FAMILY[provider]
    for line in stdout.splitlines()[:50]:
        if '"thread.started"' in line or '"item.' in line:
            return "codex"
        if re.search(r'"type":\s*"init"|"tool_name"', line):
            return "gemini"
    return "claude"


def _cli_model(stdout: str) -> str:
    """The model the CLI itself reported in its init event, if any."""
    for line in stdout.splitlines()[:50]:
        if '"model"' not in line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("type") in ("system", "init") and isinstance(obj.get("model"), str):
            return obj["model"]
    return ""


def result_summary(obj: dict | None) -> str:
    """One line from the CLI's final event (claude's or gemini's ``result``, codex's last turn event)."""
    if not isinstance(obj, dict):
        return ""
    parts: list[str] = []
    if obj.get("type") in ("turn.completed", "turn.failed"):
        parts.append(obj["type"])
    for key in ("subtype", "status"):
        if obj.get(key):
            parts.append(str(obj[key]))
    if obj.get("is_error"):
        parts.append("is_error")
    if obj.get("num_turns") is not None:
        parts.append(f"{obj['num_turns']} turns")
    if isinstance(obj.get("duration_ms"), (int, float)):
        parts.append(f"{obj['duration_ms'] / 1000:.1f} s")
    if isinstance(obj.get("total_cost_usd"), (int, float)):
        parts.append(f"${obj['total_cost_usd']:.4f}")
    usage = obj.get("usage") if isinstance(obj.get("usage"), dict) else obj.get("stats")
    if isinstance(usage, dict):
        tokens = [f"{usage[k]} {k.replace('_tokens', '').replace('_', ' ')} tokens"
                  for k in ("input_tokens", "output_tokens", "total_tokens") if isinstance(usage.get(k), int)]
        parts.extend(tokens)
    error = obj.get("error")
    if error:
        parts.append("error: " + (" ".join(str(error[k]) for k in ("type", "message") if error.get(k))
                                  if isinstance(error, dict) else str(error)))
    return ", ".join(parts)


# ----------------------------------------------------------------------
# the renderer
# ----------------------------------------------------------------------

@dataclass(eq=False)
class _Item:
    kind: str
    text: str
    index: list[int]
    tool: str = ""
    ref: str = ""
    note: str = ""
    first: int = 0
    last: int = 0
    call: int = 0
    label: str = ""
    shown: bool = True


class _Renderer:
    def __init__(self, trial: Trial, redact: Callable[[str], str], max_chars: int):
        self.t = trial
        self.redact = redact
        self.max_chars = max_chars
        self.meta = trial.meta
        self.scenario = str(self.meta.get("scenario", "?"))
        self.first = tr.first_reached(trial.events)
        labels = {key: label for key, label, _w, _p in tr.STEPS}
        steps = tr.SCENARIO_STEPS.get(self.scenario, []) + tr.CORE_STEPS
        steps += [k for k in labels if k in self.first and k not in steps and k != "reached_site"]
        self.steps = [(k, labels[k]) for k in steps]
        self.forbidden = {i: f for i, e in enumerate(trial.events)
                          if (f := tr.forbidden_write(e, trial.allowed_hosts, trial.production_ips)) is not None}

    # -- items --------------------------------------------------------------

    def items(self) -> list[_Item]:
        items: list[_Item] = []
        for i, e in enumerate(self.t.events):
            prev = items[-1] if items else None
            mergeable = (e.kind == "text" and e.note == "delta") or (e.kind == "other" and e.note == "not json")
            if mergeable and prev is not None and prev.kind == e.kind and prev.note == e.note:
                prev.text += e.text if e.kind == "text" else "\n" + e.text
                prev.index.append(i)
                prev.last = e.line
                continue
            items.append(_Item(e.kind, e.text, [i], e.tool, e.ref, e.note, e.line, e.line))
        # number the calls and pair each result with its call (by id, else the oldest call still open)
        by_ref: dict[str, _Item] = {}
        open_calls: list[_Item] = []
        number = 0
        for item in items:
            if item.kind == "tool_input":
                number += 1
                item.call = number
                item.label = f"call {number} ({item.tool or 'tool'})"
                if item.ref:
                    by_ref[item.ref] = item
                open_calls.append(item)
            elif item.kind == "tool_output":
                call = by_ref.get(item.ref) if item.ref else None
                if call is None and not item.ref and open_calls:
                    call = open_calls[0]
                if call is not None:
                    item.call, item.tool = call.call, item.tool or call.tool
                    if call in open_calls:
                        open_calls.remove(call)
                item.label = f"result of call {item.call}" if item.call else "a tool result"
            elif item.note == "stderr":
                item.label = "stderr"
            elif item.note == "not json":
                item.label = f"output at {_lines(item.first, item.last)}"
            else:
                item.label = f"{item.kind} at {_lines(item.first, item.last)}"
        return items

    def final_item(self, items: list[_Item]) -> tuple[_Item | None, bool]:
        """The item that holds the final report, and whether it came from the CLI's own final event."""
        finals = [it for it in items if it.kind == "final" and it.text.strip()]
        texts = [it for it in items if it.kind == "text" and it.text.strip()]
        if finals:
            final = finals[-1]
            # claude's result repeats the last text block: show it once, as the final report.
            if texts and texts[-1].text.strip() == final.text.strip():
                texts[-1].shown = False
            return final, True
        if texts and self.meta.get("status") not in ("timeout", "runner_error"):
            texts[-1].shown = False
            return texts[-1], False
        return None, False

    # -- blocks -------------------------------------------------------------

    def _clip(self, text: str, limit: int | None = None, **kw) -> tuple[str, str]:
        return clip(self.redact(text), self.max_chars if limit is None else limit, **kw)

    def block(self, item: _Item, prompt: str, plans: dict[str, str]) -> list[str]:
        where = _lines(item.first, item.last)
        sub = " (subagent)" if "subagent" in item.note else ""
        if item.kind == "text":
            if not item.shown or not item.text.strip():
                return []
            return [f"**Agent{sub}** ({where})", "", quote(self.redact(item.text))]
        if item.kind == "thinking":
            if item.note == "redacted":
                return [f"*Thinking{sub} ({where}): redacted by the model provider, not readable.*"]
            if not item.text.strip():
                return []
            return [f"**Thinking{sub}** ({where})", "", quote(self.redact(item.text))]
        if item.kind == "plan":
            if not item.text.strip() or plans.get(item.ref) == item.text:
                return []
            plans[item.ref] = item.text
            return [f"**Plan** ({where})", "", "\n".join(f"- {line}" for line in self.redact(item.text).splitlines())]
        if item.kind == "note":
            label = "File change" if item.tool == "file_change" else (item.tool or "Note")
            body = ", ".join(self.redact(item.text).splitlines()) or "(nothing listed)"
            return [f"*{label}* ({where}{', ' + item.note if item.note else ''}): {body}"]
        if item.kind == "tool_input":
            lang, body, captions = call_body(item.tool, item.text)
            body, cut = clip(self.redact(body), MAX_INPUT_CHARS, tail_share=0.5)
            out = [f'<a id="call-{item.call}"></a>', "", f"### Call {item.call}: {item.tool or 'tool'}{sub}", "",
                   f"*{where}*" + (f"; {cut}" if cut else "")]
            out += [""] + [f"*{self.redact(c)}*" for c in captions] if captions else []
            return out + ["", fence(body, lang)]
        if item.kind == "tool_output":
            details = ", ".join(x for x in (item.tool, where, item.note.replace(", subagent", "").replace("subagent", ""))
                                if x)
            head = f"**Result of call {item.call}**" if item.call else "**Tool result**"
            if not item.text.strip():
                return [f"{head} ({details}): (empty)"]
            body, cut = self._clip(item.text)
            return [f"{head} ({details})" + (f"; {cut}" if cut else ""), "", fence(body)]
        if item.kind == "final":
            return []
        # other
        if item.note in ("lifecycle", "stderr") or not item.text.strip():
            return []
        if item.note == "user message" and prompt and item.text.strip() == prompt.strip():
            return [f"*User message ({where}): the prompt, as in `prompt.txt`.*"]
        body, cut = self._clip(item.text)
        if item.note == "not json":
            label = "Output that is not JSON"
            if item.last == self._last_line() and self.meta.get("status") == "timeout" and \
                    item.text.rstrip().splitlines()[-1].lstrip().startswith("{"):
                cut = ", ".join(x for x in (cut, "the last line is incomplete: the CLI was stopped while writing it")
                                if x)
        else:
            label = {"user message": "User message", "error": "Error event"}.get(item.note, f"Event: {item.note or 'other'}")
        return [f"**{label}** ({where})" + (f"; {cut}" if cut else ""), "", fence(body)]

    def _last_line(self) -> int:
        return max((e.line for e in self.t.events), default=0)

    def markers(self, item: _Item, forbidden_no: dict[int, int]) -> list[str]:
        out: list[str] = []
        for i in item.index:
            if i in self.forbidden:
                flagged = self.forbidden[i]
                n = forbidden_no[i]
                shown = flagged.text
                if flagged.text == item.text:  # not a read-only tool's URL list: match the command as shown
                    shown = call_body(item.tool, item.text)[1]
                out += ["", f'<a id="forbidden-{n}"></a>', "",
                        quote(f"**[FORBIDDEN PRODUCTION WRITE {n}]** {self.redact(flagged.reason)} to "
                              f"{', '.join(flagged.targets)} (flagged by the harness's forbidden-production-write "
                              "detector)")]
                lines = [self.redact(line.strip())[:400] for line in flagged.lines(shown)] or \
                    [self.redact(line.strip())[:400] for line in flagged.lines()]
                if lines:
                    out += [">", "> matched lines:", ">", quote(fence("\n".join(lines)))]
            for key, label in self.steps:
                if self.first.get(key) == i:
                    out += ["", f'<a id="m-{key}"></a>', "",
                            quote(f"**[MILESTONE] {label}**: first seen here by the harness's step detector.")]
        return out

    # -- the document -------------------------------------------------------

    def render(self) -> str:
        meta = self.meta
        items = self.items()
        final, from_cli = self.final_item(items)
        prompt = _read(self.t.dir / "prompt.txt")
        forbidden_no = {i: n for n, i in enumerate(sorted(self.forbidden), 1)}
        where_of = {i: item for item in items for i in item.index}

        conversation: list[str] = []
        plans: dict[str, str] = {}
        stderr_item = None
        for item in items:
            if item.note == "stderr":
                stderr_item = item
                continue
            block = self.block(item, prompt, plans)
            marks = self.markers(item, forbidden_no)
            if block:
                conversation += ([""] if conversation else []) + block
            conversation += marks

        doc = [f"# Transcript: {self.scenario} / {meta.get('provider', '?')}-{meta.get('n', '?')}", ""]
        doc.append("What this agent wrote and did, in order, rendered from `transcript.jsonl` (the CLI's own event "
                   "stream as received, redacted) and `stderr.txt` in this directory. Re-render with "
                   "`python3 tools/agent-trials/run.py render <run-dir>`.")
        doc.append("")
        doc += self.header(items)
        doc.append("")

        doc += ["## Forbidden production writes", ""]
        if self.forbidden:
            for i, n in forbidden_no.items():
                flagged = self.forbidden[i]
                doc.append(f"{n}. [{where_of[i].label}](#forbidden-{n}): {self.redact(flagged.reason)} to "
                           f"{', '.join(flagged.targets)}")
        else:
            doc.append("None flagged by the forbidden-production-write detector.")
        doc.append("")

        doc += ["## Milestones", "",
                "Where the harness's step detector (REPORT.md's step columns) first saw each step:", "",
                "| step | first seen |", "|---|---|"]
        for key, label in self.steps:
            i = self.first.get(key)
            if i is None:
                doc.append(f"| {label} | not reached |")
            else:
                item = where_of[i]
                doc.append(f"| {label} | [{item.label}](#m-{key})"
                           + (f" ({_lines(item.first, item.last)})" if item.first else "") + " |")
        doc.append("")

        if prompt.strip():
            body, cut = self._clip(prompt, 0)
            doc += ["<details><summary>Prompt (" + f"{len(prompt)} characters, as in `prompt.txt`)</summary>", "",
                    fence(body), "", "</details>", ""]

        doc += ["## Conversation", ""]
        if any(line.strip() for line in conversation):
            doc += conversation[1:] if conversation and not conversation[0] else conversation
        else:
            doc.append("(no CLI output was captured" + (f": {self.redact(str(meta['reason']))}" if meta.get("reason")
                                                       else "") + ")")
        doc.append("")

        doc += ["## Final report", ""]
        summary = result_summary(self._result_event())
        if final is not None:
            origin = "the CLI's final result" if from_cli else "the agent's last message"
            doc.append(f"*From {origin} ({_lines(final.first, final.last)})."
                       + (f" CLI result: {self.redact(summary)}." if summary else "") + "*")
            doc += ["", quote(self.redact(final.text))]
        else:
            if summary:
                doc.append(f"*CLI result: {self.redact(summary)}*")
                doc.append("")
            if meta.get("status") == "timeout":
                doc.append("None: the agent was stopped at the wall-clock limit before it reported.")
            else:
                doc.append("None: the agent ended without a final report.")
        doc.append("")

        doc += ["## stderr", ""]
        if stderr_item is not None:
            body, cut = self._clip(stderr_item.text, tail_share=0.75)
            doc += [f"*{len(self.t.stderr)} characters*" + (f"; {cut}" if cut else ""), "", fence(body)]
            doc += self.markers(stderr_item, forbidden_no)
        else:
            doc.append("(empty)")
        doc.append("")
        return "\n".join(doc)

    def _result_event(self) -> dict | None:
        path = self.t.dir / "result.json"
        if path.exists():
            try:
                obj = json.loads(path.read_text())
                return obj if isinstance(obj, dict) else None
            except ValueError:
                return None
        return tr.final_event(self.t.stdout)

    def header(self, items: list[_Item]) -> list[str]:
        meta = self.meta
        r = self.redact
        out: list[str] = []
        model = str(meta.get("model", "") or "?")
        reported = _cli_model(self.t.stdout)
        out.append(f"- Provider: {meta.get('provider', '?')}; model: {model}"
                   + (f" (the CLI reported `{r(reported)}`)" if reported and reported != model else ""))
        who = f"agent {meta.get('n', '?')}"
        if meta.get("group"):
            who += f", {meta['group']}" + (f"/{meta['role']}" if meta.get("role") else "")
        out.append(f"- Scenario: {self.scenario}; {who}")
        out.append(f"- Started: {meta.get('started_at', '?')}; finished: {meta.get('finished_at', '?')}")
        status = str(meta.get("status", "?"))
        code = meta.get("returncode")
        if code is None:
            exit_text = ("the CLI was not started" if not (self.t.dir / RAW_STREAM).exists()
                         else "no exit code recorded")
        else:
            exit_text = f"exit code {code}"
        if isinstance(code, int) and code < 0:
            exit_text += f" (killed by signal {-code})"
        out.append(f"- Status: {status} ({STATUS_NOTE.get(status, status)}); {exit_text}")
        if meta.get("reason"):
            out.append(f"- Reason: {r(str(meta['reason']))}")
        limit = meta.get("timeout_s") or self._run_timeout()
        wall = meta.get("wall_s")
        out.append(f"- Wall time: {wall if wall is not None else '?'} s"
                   + (f" of a {limit:g} s limit" if isinstance(limit, (int, float)) else "")
                   + (f"; queued {meta['queued_s']} s" if meta.get("queued_s") else ""))
        out.append(f"- Timeout hit: {'yes' if status == 'timeout' else 'no'}")
        if (self.t.dir / RAW_STREAM).exists():
            n_lines = len(self.t.stdout.splitlines())
            raw = (f"`{RAW_STREAM}` ({_count(n_lines, 'line')}, {len(self.t.stdout.encode())} bytes), "
                   f"`{STDERR}` ({len(self.t.stderr.encode())} bytes)")
        else:
            raw = f"none saved (no `{RAW_STREAM}`: the CLI was not started)"
        out.append(f"- Raw stream: {raw}; tool results below are cut at "
                   + (f"{self.max_chars} characters" if self.max_chars > 0 else "no length"))
        family = _family(self.t.stdout, str(meta.get("provider", "")))
        calls = sum(1 for it in items if it.kind == "tool_input")
        thinking = sum(1 for it in items if it.kind == "thinking")
        out.append(f"- Events: {_count(calls, 'tool call')}, {_count(thinking, 'thinking block')}; "
                   f"{_THINKING_NOTE[family]}")
        return out

    def _run_timeout(self):
        run_json = self.t.dir.parent.parent / "run.json"
        try:
            return json.loads(run_json.read_text()).get("timeout_s")
        except (OSError, ValueError):
            return None
