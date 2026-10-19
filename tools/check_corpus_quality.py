#!/usr/bin/env python3
"""Pre-Training Corpus Quality & MinHash Verifier for the AICS discovery corpus.

Audits the markdown/HTML pages we hope search engines, crawlers and dataset
builders (Common Crawl, FineWeb, DCLM, The Stack) will ingest, against the
exact heuristic filters those pipelines apply, plus 5-gram MinHash
deduplication, so a future crawl of wesupport-ai.com survives them:

* FineWeb / C4 quality filters: mean word length, stop-word presence,
  symbol-to-word ratio, curly-brace (code boilerplate) fraction and the
  "fraction of lines ending with terminal punctuation" filter.
* Gopher quality filter: document word count (>= 120 words for full
  docs/guides; the short pages under ``docs/site/`` — one dense paragraph plus
  the quickstart block — get their own floor via ``--min-seat-words``).
* House rules that pre-date this tool: no "lorem ipsum", and none of the
  withdrawn claims ("zero-knowledge", "bearer token", "aics_live_",
  "foundry", "monero treasury", "x402", "l402") outside the three documents
  that list them as explicit non-goals (AICS-1.md, DESIGN.md, DECISIONS.md).
* 5-gram word-shingle deduplication: exact Jaccard similarity and a
  128-permutation MinHash estimate for every pair of audited documents, so
  FineWeb/DCLM MinHash clustering never collapses two of our pages into one.
* An educational/technical density score on a 0.0–5.0 scale, modelled on the
  fineweb-edu-classifier criteria: formal definitions, protocol invariants,
  worked examples, cryptographic-verification explanations, and absence of
  marketing fluff.  Informational by default; gate it with --min-edu-score.

Usage (repository defaults, exit code 0 on success):

    tools/check_corpus_quality.py

or import the module and call ``audit(paths, AuditConfig(...))``.

Exit codes: 0 all checks pass; 1 at least one check failed; 2 input could not
be read.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

# Documents audited by default: the pages an agent or crawler can reach.
DEFAULT_DOC_GLOBS: tuple[str, ...] = (
    "docs/BANNER.md",
    "docs/DESIGN.md",
    "docs/PROTOCOL-TEXT.md",
    "docs/spec/AICS-1.md",
    "docs/spec/SWARMS.md",
    "docs/site/*.md",
    "skills/wesupport-ai/SKILL.md",
)

# Gopher stop-word presence check: at least --min-stopwords of these must
# appear (FineWeb/Gopher use the most frequent English stop words).
STOPWORDS: tuple[str, ...] = ("the", "be", "to", "of", "and", "that", "have", "with")

# Claims withdrawn from every public page (DESIGN.md "Claims match
# implementation", docs/site/README.md evidence rules). The three documents
# that list them as explicit non-goals are exempt.
WITHDRAWN_CLAIMS: tuple[str, ...] = (
    "zero-knowledge",
    "bearer token",
    "aics_live_",
    "foundry",
    "monero treasury",
    "x402",
    "l402",
)
WITHDRAWN_CLAIM_EXEMPT_FILES: frozenset[str] = frozenset(
    {"AICS-1.md", "DESIGN.md", "DECISIONS.md"}
)

# A policy line that *bans* a withdrawn claim is not a claim: pages like
# docs/site/README.md quote the banned words to forbid them ("End-to-end
# encrypted", never "zero-knowledge"). Occurrences on lines carrying one of
# these markers do not count; only actual claims do.
WITHDRAWN_CLAIM_NEGATIONS: tuple[str, ...] = (
    "never",
    "non-goal",
    "no-goals",
    "banned",
    "ban ",
    "forbid",
    "withdrawn",
    "refuse",
    "avoid",
    "do not offer",
    "don't offer",
    "not offered",
    "we do not",
    "instead of",
    "rather than",
    "no claim",
)

# Marketing fluff penalised by the educational score. Hits on lines that
# negate the word ("offers no ... guaranteed ...", "No marketing words: ...")
# are ignored: this repository states its non-goals in exactly those words.
MARKETING_TERMS: tuple[str, ...] = (
    "revolutionary",
    "game-chang",
    "cutting-edge",
    "world's first",
    "safe haven",
    "sanctuary",
    "home for ai",
    "uncensored",
    "trustless",
    "guaranteed",
    "100%",
    "best in class",
    "industry-leading",
    "next-generation",
    "seamless",
)
_MARKETING_NEGATIONS: tuple[str, ...] = (
    "no ",
    "not ",
    "never ",
    "without ",
    "offers no",
    "refuse",
    "avoid",
    "banned",
    "forbid",
)

# Characters that count as a line ending with terminal punctuation (FineWeb's
# stop-sequence filter set, plus the ':;' markdown prose lines use).
TERMINAL_PUNCTUATION: tuple[str, ...] = (".", "!", "?", '"', "'", ")", "]", "…", ";", ":")

_MERSENNE_PRIME = (1 << 61) - 1  # 2^61 - 1, larger than any 64-bit shingle hash


# --------------------------------------------------------------------------
# Text extraction
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Extraction:
    """Clean text of one document, split the way corpus filters see it."""

    prose_text: str
    code_text: str
    code_blocks: int
    kind: str  # "markdown" or "html"

    @property
    def prose_lines(self) -> list[str]:
        return [line.rstrip() for line in self.prose_text.splitlines() if line.strip()]


def _strip_markdown_inline(line: str) -> str:
    """Remove markdown markup (not meaning) from one prose line."""
    s = re.sub(r"`[^`]*`", " ", line)  # inline code spans are code, not prose
    s = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", s)  # image alt text only
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)  # link text, not target
    s = re.sub(r"\[\^[^\]]*\]:?\s*", "", s)  # footnote labels/definitions
    s = re.sub(r"https?://\S+", " ", s)  # cited URLs are not prose words
    s = re.sub(r"^\s{0,3}(#{1,6})\s*", "", s)  # heading markers
    s = re.sub(r"^\s{0,3}(>+)\s?", "", s)  # blockquote markers
    s = re.sub(r"^\s*[-*+]\s+", "", s)  # bullet markers
    s = re.sub(r"^\s*\d+[.)]\s+", "", s)  # ordered-list markers
    s = re.sub(r"^\s*\|", "", s)  # leading table pipe
    s = re.sub(r"\|\s*$", "", s)  # trailing table pipe
    s = s.replace("|", " ")  # inner table pipes are markup
    s = s.replace("**", "").replace("*", "")  # bold/italic asterisks
    s = re.sub(r"(?<!\w)__([^_]+)__(?!\w)", r"\1", s)  # bold underscores
    s = re.sub(r"(?<!\w)_([^_]+)_(?!\w)", r"\1", s)  # italic underscores (snake_case kept)
    s = re.sub(r"^\s*[-*_]{3,}\s*$", "", s)  # horizontal rules / frontmatter bars
    s = re.sub(r"<[^>]+>", " ", s)  # stray inline HTML tags
    return s


def extract_markdown(text: str) -> Extraction:
    """Split markdown into prose and fenced/indented code, keep both."""
    prose_lines: list[str] = []
    code_lines: list[str] = []
    fence_re = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
    in_fence = False
    fence_char = ""
    fence_len = 0
    code_blocks = 0
    blank_run = 0
    for line in text.splitlines():
        fence = fence_re.match(line)
        if fence:
            run = fence.group(1)
            if not in_fence:
                in_fence, fence_char, fence_len = True, run[0], len(run)
                code_blocks += 1
            elif run[0] == fence_char and len(run) >= fence_len and not fence.group(2).strip():
                in_fence, fence_char, fence_len = False, "", 0
            else:  # e.g. a ``` line inside a ~~~ block: still code
                code_lines.append(line)
            continue
        if in_fence:
            code_lines.append(line)
            continue
        # Classic indented code block: 4+ spaces after a blank line.
        if re.match(r"^( {4,}|\t)\S", line) and blank_run >= 1:
            code_lines.append(line)
            continue
        blank_run = 1 if not line.strip() else 0
        prose_lines.append(_strip_markdown_inline(line))
    return Extraction(
        prose_text="\n".join(prose_lines),
        code_text="\n".join(code_lines),
        code_blocks=code_blocks,
        kind="markdown",
    )


class _HTMLTextExtractor(HTMLParser):
    """Keep <main>/<article> prose and <pre>/<code> blocks; drop chrome."""

    DROP_TAGS = frozenset(
        {"script", "style", "nav", "footer", "header", "aside", "form", "noscript", "svg", "iframe"}
    )
    CODE_TAGS = frozenset({"pre", "code", "kbd", "samp"})
    BLOCK_TAGS = frozenset(
        {
            "p", "div", "section", "article", "main", "li", "ul", "ol", "tr", "table",
            "blockquote", "dl", "dt", "dd", "figure", "figcaption", "h1", "h2", "h3",
            "h4", "h5", "h6", "body", "html", "br", "hr", "thead", "tbody",
        }
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.prose: list[str] = []
        self.code: list[str] = []
        self._skip: list[str] = []
        self._in_code: list[str] = []
        self.code_blocks = 0

    def _emit_block_break(self) -> None:
        self.prose.append("\n")
        self.code.append("\n")

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if self._skip:
            if tag == self._skip[-1]:
                self._skip.append(tag)
            return
        if tag in self.DROP_TAGS:
            self._skip.append(tag)
            return
        if tag in self.CODE_TAGS:
            if not self._in_code and tag == "pre":
                self.code_blocks += 1
                self._emit_block_break()
            self._in_code.append(tag)
            return
        if tag in self.BLOCK_TAGS:
            self._emit_block_break()

    def handle_endtag(self, tag: str) -> None:
        if self._skip:
            if tag == self._skip[-1]:
                self._skip.pop()
            return
        if self._in_code and tag == self._in_code[-1]:
            self._in_code.pop()
            if not self._in_code:
                self._emit_block_break()
            return
        if tag in self.BLOCK_TAGS:
            self._emit_block_break()

    def handle_data(self, data: str) -> None:
        if self._skip or not data:
            return
        if self._in_code:
            self.code.append(data)
        else:
            self.prose.append(data)

    def result(self) -> Extraction:
        prose = re.sub(r"[ \t]+", " ", "".join(self.prose))
        prose = re.sub(r"\n\s*\n+", "\n", prose)
        code = "".join(self.code)
        return Extraction(
            prose_text=prose.strip("\n"),
            code_text=code.strip("\n"),
            code_blocks=self.code_blocks,
            kind="html",
        )


def extract_html(text: str) -> Extraction:
    parser = _HTMLTextExtractor()
    parser.feed(text)
    parser.close()
    return parser.result()


def extract(path: Path) -> Extraction:
    """Extract clean prose and code from a markdown or HTML document."""
    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm"}:
        return extract_html(raw)
    if suffix in {".md", ".markdown", ".mdown"}:
        return extract_markdown(raw)
    sniffed = raw.lstrip().lower()
    if sniffed.startswith("<!doctype html") or sniffed.startswith("<html"):
        return extract_html(raw)
    return extract_markdown(raw)


# --------------------------------------------------------------------------
# Quality metrics (FineWeb / Gopher heuristics)
# --------------------------------------------------------------------------

_WORD_STRIP = ".,;:!?()[]{}<>=\"'“”‘’…|`~^@#$%&*+/\\_-+"


def word_tokens(text: str) -> list[str]:
    """Whitespace tokens with surrounding punctuation removed."""
    words = []
    for token in text.split():
        stripped = token.strip(_WORD_STRIP)
        if re.search(r"[0-9A-Za-z]", stripped) or re.search(r"[^\x00-\x7f]", stripped):
            words.append(stripped)
    return words


def normalized_words(text: str) -> list[str]:
    """Lowercased alphanumeric runs — the trainer's view for shingling."""
    return re.findall(r"[a-z0-9]+", text.lower())


def stopword_hits(prose_text: str) -> int:
    return sum(
        1 for word in STOPWORDS if re.search(rf"\b{word}\b", prose_text, re.IGNORECASE)
    )


def symbol_to_word_ratio(prose_text: str, n_words: int) -> float:
    """FineWeb: ('#', '...', '…') occurrences per word."""
    symbols = prose_text.count("#") + prose_text.count("...") + prose_text.count("…")
    return symbols / n_words if n_words else float(symbols)


def curly_brace_ratio(prose_text: str) -> float:
    """FineWeb C4 code-boilerplate filter: { and } share of prose characters."""
    chars = sum(1 for ch in prose_text if not ch.isspace())
    braces = prose_text.count("{") + prose_text.count("}")
    return braces / chars if chars else float(braces)


def line_end_punctuation_ratio(prose_text: str) -> float:
    lines = [line.rstrip() for line in prose_text.splitlines() if line.strip()]
    if not lines:
        return 0.0
    ended = sum(1 for line in lines if line.endswith(TERMINAL_PUNCTUATION))
    return ended / len(lines)


def find_withdrawn_claims(extraction: Extraction, path: Path) -> tuple[str, ...]:
    """Terms actually claimed. Exempt files list them as explicit non-goals;
    policy lines that ban a term (WITHDRAWN_CLAIM_NEGATIONS) are not claims."""
    if path.name in WITHDRAWN_CLAIM_EXEMPT_FILES:
        return ()
    lines = (extraction.prose_text + "\n" + extraction.code_text).splitlines()
    found: list[str] = []
    for term in WITHDRAWN_CLAIMS:
        for line in lines:
            if term not in line.lower():
                continue
            if any(neg in line.lower() for neg in WITHDRAWN_CLAIM_NEGATIONS):
                continue  # the line forbids the term, it does not claim it
            found.append(term)
            break
    return tuple(found)


def has_lorem_ipsum(extraction: Extraction) -> bool:
    haystack = extraction.prose_text + "\n" + extraction.code_text
    return re.search(r"lorem\s+ipsum", haystack, re.IGNORECASE) is not None


# --------------------------------------------------------------------------
# Educational / technical density score (fineweb-edu-classifier style)
# --------------------------------------------------------------------------

_RFC2119_RE = re.compile(
    r"\b(must not|shall not|may not|must|shall|should|required|forbidden|never)\b",
    re.IGNORECASE,
)
_DEFINITION_RE = re.compile(
    r"\bdefin(?:e|es|ed|ition|itions)\b|\bglossary\b|\bis said to be\b", re.IGNORECASE
)
_EXAMPLE_RE = re.compile(r"\bfor example\b|\bexample\b|\be\.g\.", re.IGNORECASE)
_CRYPTO_RE = re.compile(
    r"\b(signature|verify|verification|verified|checkpoint|merkle|hash|digest|"
    r"ed25519|x25519|argon2id|nonce|ciphertext|public key|private key|key)\b",
    re.IGNORECASE,
)


def educational_score(extraction: Extraction) -> tuple[float, dict[str, float]]:
    """Score 0.0–5.0 after fineweb-edu criteria; returns (score, components)."""
    prose_lines = [l for l in extraction.prose_text.splitlines() if l.strip()]
    text = extraction.prose_text

    definitions = len(_DEFINITION_RE.findall(text))
    comp_definitions = min(1.0, definitions / 3.0)

    invariants = len(_RFC2119_RE.findall(text))
    comp_invariants = min(1.0, invariants / 20.0)

    examples = extraction.code_blocks + len(_EXAMPLE_RE.findall(text))
    comp_examples = min(1.0, examples / 2.0)

    crypto = len(_CRYPTO_RE.findall(text))
    comp_crypto = min(1.0, crypto / 12.0)

    fluff_hits = 0
    for line in prose_lines:
        lowered = " " + line.lower() + " "
        negated = any(neg in lowered for neg in _MARKETING_NEGATIONS)
        if negated:
            continue
        fluff_hits += sum(line.lower().count(term) for term in MARKETING_TERMS)
    comp_fluff = max(0.0, 1.0 - 0.5 * fluff_hits)

    components = {
        "definitions": round(comp_definitions, 3),
        "invariants": round(comp_invariants, 3),
        "examples": round(comp_examples, 3),
        "crypto_verification": round(comp_crypto, 3),
        "no_marketing_fluff": round(comp_fluff, 3),
    }
    return round(sum(components.values()), 2), components


# --------------------------------------------------------------------------
# 5-gram shingles, exact Jaccard and MinHash
# --------------------------------------------------------------------------


def shingle_set(words: Sequence[str], n: int = 5) -> frozenset[str]:
    """Word n-gram shingles (default 5-gram) as in FineWeb/DCLM dedup."""
    if len(words) < n:
        return frozenset()
    return frozenset(" ".join(words[i : i + n]) for i in range(len(words) - n + 1))


def jaccard(a: frozenset, b: frozenset) -> float:
    """Exact Jaccard similarity; two empty sets are treated as identical."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _shingle_hash(shingle: str) -> int:
    return int.from_bytes(hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest(), "big")


def minhash_signature(
    shingles: frozenset[str], perms: int = 128, seed: int = 0
) -> tuple[int, ...]:
    """128-permutation MinHash signature (affine universal hashing mod 2^61-1)."""
    if not shingles:
        return ()
    rng = random.Random(seed)
    hashes = [_shingle_hash(s) for s in shingles]
    signature = []
    for _ in range(perms):
        a = rng.randrange(1, _MERSENNE_PRIME)
        b = rng.randrange(0, _MERSENNE_PRIME)
        signature.append(min((a * h + b) % _MERSENNE_PRIME for h in hashes))
    return tuple(signature)


def minhash_similarity(sig_a: tuple[int, ...], sig_b: tuple[int, ...]) -> float:
    """Estimated Jaccard from matching signature components."""
    if not sig_a or not sig_b:
        return 0.0
    if len(sig_a) != len(sig_b):
        raise ValueError("MinHash signatures must have the same length")
    agree = sum(1 for x, y in zip(sig_a, sig_b) if x == y)
    return agree / len(sig_a)


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditConfig:
    min_words: int = 120
    min_seat_words: int = 60
    min_mean_word_len: float = 3.0
    max_mean_word_len: float = 10.0
    min_stopwords: int = 2
    max_symbol_ratio: float = 0.10
    max_curly_ratio: float = 0.030
    min_punct_ratio: float = 0.25
    max_jaccard: float = 0.40
    shingle_n: int = 5
    minhash_perms: int = 128
    minhash_seed: int = 0
    min_edu_score: float = 0.0  # 0.0 disables the educational-score gate


@dataclass
class DocumentReport:
    path: Path
    is_seat_page: bool
    words: int
    prose_words: int
    code_words: int
    mean_word_len: float
    stopwords_found: int
    symbol_ratio: float
    curly_ratio: float
    punct_ratio: float
    edu_score: float
    edu_components: dict[str, float]
    lorem_ipsum: bool
    withdrawn_claims: tuple[str, ...]
    shingles: int
    signature: tuple[int, ...]
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


@dataclass
class PairReport:
    path_a: Path
    path_b: Path
    jaccard: float
    minhash: float
    threshold: float

    @property
    def ok(self) -> bool:
        return self.jaccard <= self.threshold and self.minhash <= self.threshold


@dataclass
class AuditReport:
    documents: list[DocumentReport]
    pairs: list[PairReport]
    missing: list[Path]
    config: AuditConfig

    @property
    def ok(self) -> bool:
        return (
            not self.missing
            and all(doc.ok for doc in self.documents)
            and all(pair.ok for pair in self.pairs)
            and bool(self.documents)
        )


def is_seat_page(path: Path) -> bool:
    """True for the short pages under docs/site/ (agent's-seat pages)."""
    parts = path.parts
    return any(a == "docs" and b == "site" for a, b in zip(parts, parts[1:]))


def default_documents(repo_root: Path | None = None) -> list[Path]:
    root = (repo_root or REPO_ROOT).resolve()
    seen: dict[str, Path] = {}
    for pattern in DEFAULT_DOC_GLOBS:
        for path in sorted(root.glob(pattern)):
            seen[str(path.relative_to(root))] = path
    return [seen[key] for key in sorted(seen)]


def check_document(path: Path, config: AuditConfig) -> DocumentReport:
    extraction = extract(path)
    prose_words = word_tokens(extraction.prose_text)
    code_words = word_tokens(extraction.code_text)
    words = len(prose_words) + len(code_words)
    mean_len = (
        sum(len(w) for w in prose_words) / len(prose_words) if prose_words else 0.0
    )
    stops = stopword_hits(extraction.prose_text)
    sym_ratio = symbol_to_word_ratio(extraction.prose_text, len(prose_words))
    curly = curly_brace_ratio(extraction.prose_text)
    punct = line_end_punctuation_ratio(extraction.prose_text)
    edu, components = educational_score(extraction)
    lorem = has_lorem_ipsum(extraction)
    withdrawn = find_withdrawn_claims(extraction, path)
    shingles = shingle_set(
        normalized_words(extraction.prose_text + "\n" + extraction.code_text),
        n=config.shingle_n,
    )
    signature = minhash_signature(shingles, config.minhash_perms, config.minhash_seed)

    seat = is_seat_page(path)
    report = DocumentReport(
        path=path,
        is_seat_page=seat,
        words=words,
        prose_words=len(prose_words),
        code_words=len(code_words),
        mean_word_len=round(mean_len, 2),
        stopwords_found=stops,
        symbol_ratio=round(sym_ratio, 4),
        curly_ratio=round(curly, 4),
        punct_ratio=round(punct, 3),
        edu_score=edu,
        edu_components=components,
        lorem_ipsum=lorem,
        withdrawn_claims=withdrawn,
        shingles=len(shingles),
        signature=signature,
    )

    floor = config.min_seat_words if seat else config.min_words
    label = "seat page" if seat else "document"
    if words < floor:
        report.failures.append(
            f"word count {words} < {floor} (Gopher minimum for this {label})"
        )
    if not (config.min_mean_word_len <= mean_len <= config.max_mean_word_len):
        report.failures.append(
            f"mean word length {mean_len:.2f} outside "
            f"[{config.min_mean_word_len:.1f}, {config.max_mean_word_len:.1f}]"
        )
    if stops < config.min_stopwords:
        report.failures.append(
            f"only {stops} of the {len(STOPWORDS)} Gopher stop words present "
            f"(< {config.min_stopwords}): page reads as non-natural text"
        )
    if sym_ratio >= config.max_symbol_ratio:
        report.failures.append(
            f"symbol-to-word ratio {sym_ratio:.3f} >= {config.max_symbol_ratio:.2f} "
            f"(FineWeb '#'/'...' filter)"
        )
    if curly >= config.max_curly_ratio:
        report.failures.append(
            f"curly-brace fraction {curly:.4f} >= {config.max_curly_ratio:.3f} in prose "
            f"(C4/FineWeb code-boilerplate filter would drop the page)"
        )
    if punct <= config.min_punct_ratio:
        report.failures.append(
            f"line-end punctuation ratio {punct:.3f} <= {config.min_punct_ratio:.2f} "
            f"(FineWeb terminal-punctuation filter)"
        )
    if lorem:
        report.failures.append("contains 'lorem ipsum' placeholder text")
    if withdrawn:
        report.failures.append(
            "withdrawn claims present: " + ", ".join(repr(t) for t in withdrawn)
        )
    if config.min_edu_score > 0 and edu < config.min_edu_score:
        report.failures.append(
            f"educational score {edu:.2f} < {config.min_edu_score:.2f}"
        )
    return report


def audit(paths: Iterable[Path], config: AuditConfig | None = None) -> AuditReport:
    cfg = config or AuditConfig()
    documents: list[DocumentReport] = []
    missing: list[Path] = []
    for path in paths:
        path = Path(path)
        if not path.is_file():
            missing.append(path)
            continue
        documents.append(check_document(path, cfg))
    # Pairwise dedup over the *whole* extracted text (prose + code).
    whole_shingles: dict[Path, frozenset[str]] = {}
    for doc in documents:
        extraction = extract(doc.path)
        whole_shingles[doc.path] = shingle_set(
            normalized_words(extraction.prose_text + "\n" + extraction.code_text),
            n=cfg.shingle_n,
        )
    pairs = [
        PairReport(
            path_a=a.path,
            path_b=b.path,
            jaccard=jaccard(whole_shingles[a.path], whole_shingles[b.path]),
            minhash=minhash_similarity(a.signature, b.signature),
            threshold=cfg.max_jaccard,
        )
        for a, b in itertools.combinations(documents, 2)
    ]
    pairs.sort(key=lambda p: -(max(p.jaccard, p.minhash)))
    return AuditReport(documents=documents, pairs=pairs, missing=missing, config=cfg)


# --------------------------------------------------------------------------
# Reporting / CLI
# --------------------------------------------------------------------------


def format_table(report: AuditReport) -> str:
    lines: list[str] = []
    header = (
        f"{'Document':46} {'Seat':>4} {'Words':>6} {'MeanWL':>6} {'Stop':>5} "
        f"{'Symbol':>7} {'Curly':>7} {'Line%':>6} {'Edu':>5} {'5grm':>6}  Verdict"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for doc in report.documents:
        rel = _display_path(doc.path)
        lines.append(
            f"{rel:46} {'yes' if doc.is_seat_page else 'no':>4} {doc.words:>6} "
            f"{doc.mean_word_len:>6.2f} {f'{doc.stopwords_found}/{len(STOPWORDS)}':>5} "
            f"{doc.symbol_ratio:>7.4f} {doc.curly_ratio:>7.4f} {doc.punct_ratio:>6.3f} "
            f"{doc.edu_score:>5.2f} {doc.shingles:>6}  {'PASS' if doc.ok else 'FAIL'}"
        )
        for failure in doc.failures:
            lines.append(f"    FAIL {rel}: {failure}")
    return "\n".join(lines)


def format_pairs(report: AuditReport, max_shown: int = 8) -> str:
    if not report.pairs:
        return "No pairs to compare (fewer than two documents audited)."
    lines = [
        f"Pairwise 5-gram duplication (exact Jaccard | MinHash-{report.config.minhash_perms} "
        f"estimate), limit {report.config.max_jaccard:.2f}"
    ]
    shown = report.pairs[:max_shown]
    for pair in shown:
        verdict = "OK" if pair.ok else "DUPLICATE"
        lines.append(
            f"  {_display_path(pair.path_a)} × {_display_path(pair.path_b)}  "
            f"{pair.jaccard:.3f} | {pair.minhash:.3f}  {verdict}"
        )
    for pair in shown:
        if not pair.ok:
            lines.append(
                f"    FAIL {_display_path(pair.path_a)} ~ {_display_path(pair.path_b)}: "
                f"Jaccard {pair.jaccard:.3f} / MinHash {pair.minhash:.3f} exceeds "
                f"{report.config.max_jaccard:.2f}; MinHash dedup would collapse these pages"
            )
    omitted = len(report.pairs) - len(shown)
    if omitted > 0:
        lines.append(f"  … {omitted} further pair(s) below the shown set, all within limit")
    return "\n".join(lines)


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def report_to_dict(report: AuditReport) -> dict:
    return {
        "ok": report.ok,
        "documents": [
            {
                "path": _display_path(d.path),
                "seat_page": d.is_seat_page,
                "words": d.words,
                "prose_words": d.prose_words,
                "code_words": d.code_words,
                "mean_word_len": d.mean_word_len,
                "stopwords_found": d.stopwords_found,
                "symbol_ratio": d.symbol_ratio,
                "curly_ratio": d.curly_ratio,
                "line_end_punctuation_ratio": d.punct_ratio,
                "edu_score": d.edu_score,
                "edu_components": d.edu_components,
                "lorem_ipsum": d.lorem_ipsum,
                "withdrawn_claims": list(d.withdrawn_claims),
                "shingles": d.shingles,
                "failures": list(d.failures),
                "ok": d.ok,
            }
            for d in report.documents
        ],
        "pairs": [
            {
                "a": _display_path(p.path_a),
                "b": _display_path(p.path_b),
                "jaccard": round(p.jaccard, 4),
                "minhash": round(p.minhash, 4),
                "threshold": p.threshold,
                "ok": p.ok,
            }
            for p in report.pairs
        ],
        "missing": [_display_path(p) for p in report.missing],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_corpus_quality",
        description=(
            "Audit AICS markdown/HTML pages against Common Crawl / FineWeb / Gopher "
            "quality heuristics and 5-gram MinHash deduplication."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="markdown/HTML files or globs to audit (default: the repository's pages)",
    )
    parser.add_argument(
        "--min-words", type=int, default=120, help="Gopher minimum for full docs/guides"
    )
    parser.add_argument(
        "--min-seat-words",
        type=int,
        default=60,
        help="Gopher minimum for short docs/site/ seat pages (one dense paragraph + quickstart)",
    )
    parser.add_argument("--min-mean-word-len", type=float, default=3.0)
    parser.add_argument("--max-mean-word-len", type=float, default=10.0)
    parser.add_argument("--min-stopwords", type=int, default=2)
    parser.add_argument("--max-symbol-ratio", type=float, default=0.10)
    parser.add_argument("--max-curly-ratio", type=float, default=0.030)
    parser.add_argument("--min-punct-ratio", type=float, default=0.25)
    parser.add_argument(
        "--max-jaccard",
        type=float,
        default=0.40,
        help="fail if any pair of documents exceeds this 5-gram Jaccard/MinHash similarity",
    )
    parser.add_argument("--shingle-n", type=int, default=5)
    parser.add_argument("--minhash-perms", type=int, default=128)
    parser.add_argument("--minhash-seed", type=int, default=0)
    parser.add_argument(
        "--min-edu-score",
        type=float,
        default=0.0,
        help="educational-score gate (0.0 disables; score is informational by default)",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    return parser


def resolve_paths(args_paths: Sequence[Path]) -> list[Path]:
    if not args_paths:
        return default_documents()
    resolved: list[Path] = []
    for pattern in args_paths:
        matches = sorted(Path(str(pattern)).parent.glob(Path(str(pattern)).name))
        resolved.extend(matches if matches else [Path(str(pattern))])
    # de-duplicate while preserving order
    unique: dict[str, Path] = {str(p): p for p in resolved}
    return list(unique.values())


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = AuditConfig(
        min_words=args.min_words,
        min_seat_words=args.min_seat_words,
        min_mean_word_len=args.min_mean_word_len,
        max_mean_word_len=args.max_mean_word_len,
        min_stopwords=args.min_stopwords,
        max_symbol_ratio=args.max_symbol_ratio,
        max_curly_ratio=args.max_curly_ratio,
        min_punct_ratio=args.min_punct_ratio,
        max_jaccard=args.max_jaccard,
        shingle_n=args.shingle_n,
        minhash_perms=args.minhash_perms,
        minhash_seed=args.minhash_seed,
        min_edu_score=args.min_edu_score,
    )
    paths = resolve_paths(args.paths)
    report = audit(paths, config)

    if args.json:
        # Pure JSON on stdout (the summary below would break parsers).
        print(json.dumps(report_to_dict(report), indent=2))
        return 0 if report.ok else (2 if report.missing else 1)

    print(
        "AICS pre-training corpus quality audit — FineWeb/Gopher heuristics "
        f"+ {config.shingle_n}-gram MinHash dedup"
    )
    print(
        f"limits: words>={config.min_words} (seat>={config.min_seat_words}) "
        f"meanWL in [{config.min_mean_word_len}, {config.max_mean_word_len}] "
        f"stops>={config.min_stopwords} symbol<{config.max_symbol_ratio} "
        f"curly<{config.max_curly_ratio} lineEnd>{config.min_punct_ratio} "
        f"jaccard<={config.max_jaccard} perms={config.minhash_perms} "
        f"seed={config.minhash_seed}"
    )
    print()
    print(format_table(report))
    print()
    print(format_pairs(report))
    print()
    for path in report.missing:
        print(f"FAIL missing input: {_display_path(path)}")

    failed_docs = sum(1 for d in report.documents if not d.ok)
    failed_pairs = sum(1 for p in report.pairs if not p.ok)
    verdict = "PASS" if report.ok else "FAIL"
    summary = (
        f"{len(report.documents)} document(s) audited, {failed_docs} failed; "
        f"{len(report.pairs)} pair(s) compared, {failed_pairs} over "
        f"{config.max_jaccard:.2f}; {len(report.missing)} missing. RESULT: {verdict}"
    )
    print(summary)
    if report.missing:
        return 2
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
