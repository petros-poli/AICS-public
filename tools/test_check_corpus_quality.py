"""Tests for tools/check_corpus_quality.py — the pre-training corpus quality
and MinHash verifier (FineWeb/Gopher heuristics, 5-gram deduplication, and an
audit of the repository's actual markdown documents)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_corpus_quality as ccq  # noqa: E402

REPO_ROOT = TOOLS_DIR.parent


# ---------------------------------------------------------------------------
# Fixtures and helpers: natural, distinct English prose for the good cases
# ---------------------------------------------------------------------------

SENTENCES_A = [
    "The service keeps a public log that anyone can read and check for themselves.",
    "Every accepted write becomes a leaf in an append-only record under a checkpoint.",
    "An agent makes its own key locally, and the operator never makes one for it.",
    "A name belongs to the key that first claimed it through a signed request.",
    "Private messages are encrypted to the recipient, and only that key opens them.",
    "The record shows who wrote what, when the leaf landed, and what came before it.",
    "Checkpoints are signed and published so a split view stays detectable.",
    "Read verbs stay open to fetch-only agents that cannot hold a connection open.",
]

SENTENCES_B = [
    "Operators of small services should write down what their systems promise.",
    "A pilot that has not registered with the regulator says so on every page.",
    "Legal text and protocol text must agree, or readers stop trusting either one.",
    "This guide explains the working of the transparency log in plain language.",
    "Each section defines one term, gives one worked example, and states the limit.",
    "When a claim was withdrawn, the page says that it was withdrawn and why.",
    "Tables summarise the guarantees so a reader can scan them in one pass.",
    "The glossary repeats each definition in the same words everywhere it appears.",
]


def prose_block(sentences: list[str], repetitions: int) -> str:
    """Natural prose lines, every line ending with terminal punctuation."""
    lines = []
    for i in range(repetitions):
        for sentence in sentences:
            lines.append(sentence)
    return "\n".join(lines)


def write_doc(tmp_path: Path, relative: str, text: str) -> Path:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


GOOD_DOC_A = (
    "# A page about the public log\n\n"
    + prose_block(SENTENCES_A, 4)
    + "\n\n## How to verify a checkpoint\n\n"
    + prose_block(SENTENCES_A, 2)
    + "\n"
)

GOOD_DOC_B = (
    "# A guide to writing service pages\n\n"
    + prose_block(SENTENCES_B, 4)
    + "\n\n## Definitions and limits\n\n"
    + prose_block(SENTENCES_B, 2)
    + "\n"
)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_extract_markdown_separates_prose_and_code():
    text = (
        "# Heading about the gate\n\n"
        "Intro prose line mentions a key and a nonce.\n\n"
        "```text\n"
        "openssl s_client -quiet -connect gate.example:7700\n"
        "```\n\n"
        "Closing prose line with punctuation.\n"
    )
    extraction = ccq.extract_markdown(text)
    assert extraction.kind == "markdown"
    assert "openssl s_client" in extraction.code_text
    assert "openssl s_client" not in extraction.prose_text
    assert "Intro prose line" in extraction.prose_text
    assert extraction.code_blocks == 1
    # markup, not meaning, is stripped from prose
    assert "#" not in extraction.prose_text.splitlines()[0]


def test_extract_markdown_keeps_inline_code_out_of_prose():
    text = "Use the gate with `aics_live_123` tokens and verify it.\n"
    extraction = ccq.extract_markdown(text)
    assert "aics_live_" not in extraction.prose_text


def test_extract_html_drops_nav_footer_script_style():
    html = (
        "<html><body>"
        "<nav>Home Products Pricing Signup buy now</nav>"
        "<script>var tracking = {pixel: 1};</script>"
        "<style>.ad { color: red; }</style>"
        "<main><p>The public log is readable by anyone who wants to check it.</p></main>"
        "<footer>Copyright marketing boilerplate click here subscribe now.</footer>"
        "</body></html>"
    )
    extraction = ccq.extract_html(html)
    assert extraction.kind == "html"
    assert "Signup" not in extraction.prose_text
    assert "tracking" not in extraction.prose_text and "{" not in extraction.prose_text
    assert "Copyright marketing" not in extraction.prose_text
    assert "public log is readable" in extraction.prose_text


def test_extract_html_keeps_pre_and_code_blocks():
    html = (
        "<main>"
        "<p>Run the command below to reach the gate over TLS.</p>"
        "<pre><code>connect gate.example 7700 { \"json\": true }</code></pre>"
        "</main>"
    )
    extraction = ccq.extract_html(html)
    assert "gate.example 7700" in extraction.code_text
    assert "gate.example 7700" not in extraction.prose_text
    assert extraction.code_blocks == 1
    assert ccq.curly_brace_ratio(extraction.prose_text) == 0.0


def test_extract_sniffs_html_without_extension(tmp_path):
    path = write_doc(tmp_path, "page.txt", "<html><main><p>Some prose here.</p></main></html>")
    extraction = ccq.extract(path)
    assert extraction.kind == "html"
    assert "Some prose here." in extraction.prose_text


# ---------------------------------------------------------------------------
# Heuristic pass/fail detection
# ---------------------------------------------------------------------------


def test_good_markdown_document_passes_all_heuristics(tmp_path):
    path = write_doc(tmp_path, "guide.md", GOOD_DOC_A)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert report.failures == [], report.failures
    assert report.ok
    assert report.words >= 120
    assert 3.0 <= report.mean_word_len <= 10.0
    assert report.stopwords_found >= 2
    assert report.symbol_ratio < 0.10
    assert report.curly_ratio < 0.030
    assert report.punct_ratio > 0.25
    assert not report.lorem_ipsum
    assert report.withdrawn_claims == ()


def test_word_count_gopher_threshold_full_doc(tmp_path):
    short = "One dense paragraph with stop words like the and of and to.\n" * 4
    path = write_doc(tmp_path, "short.md", short)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert any("word count" in f for f in report.failures)
    # the same text passes once the threshold is lowered for it
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert not any("word count" in f for f in report.failures)


def test_seat_pages_get_their_own_lower_threshold(tmp_path):
    body = "This seat page answers one question in a single dense paragraph. " * 6
    seat = write_doc(tmp_path, "docs/site/seat.md", body + "\n")
    full = write_doc(tmp_path, "docs/full-guide.md", body + "\n")
    config = ccq.AuditConfig()  # min_words=120, min_seat_words=60
    assert ccq.is_seat_page(seat)
    assert not ccq.is_seat_page(full)
    seat_report = ccq.check_document(seat, config)
    full_report = ccq.check_document(full, config)
    assert not any("word count" in f for f in seat_report.failures)
    assert any("word count" in f for f in full_report.failures)


def test_mean_word_length_bounds(tmp_path):
    long_words = "Extraordinarily supercalifragilistic pseudoprofessional antidisestablishment words.\n" * 8
    path = write_doc(tmp_path, "long.md", long_words)
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert any("mean word length" in f for f in report.failures)

    cryptic = "ab cd ef gh ij kl mn op qr st uv wx yz ab cd ef gh ij.\n" * 8
    path = write_doc(tmp_path, "short.md", cryptic)
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert any("mean word length" in f for f in report.failures)


def test_stopword_presence(tmp_path):
    # Plenty of words, none of the Gopher stop words.
    text = "Agents exchange envelopes, signatures, checkpoints, tiles, digests, ciphertext, names, keys.\n" * 12
    path = write_doc(tmp_path, "nostop.md", text)
    config = ccq.AuditConfig(min_words=10, min_mean_word_len=4.0, max_mean_word_len=12.0)
    report = ccq.check_document(path, config)
    assert any("stop words" in f for f in report.failures)


def test_symbol_to_word_ratio(tmp_path):
    noisy = "The log keeps every leaf and the hash of every leaf... ### tags ### more ###\n" * 6
    path = write_doc(tmp_path, "noisy.md", noisy)
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert any("symbol-to-word" in f for f in report.failures)


def test_curly_brace_ratio_prose_fails_but_code_passes(tmp_path):
    # Braces in prose (code boilerplate leakage) trips the C4/FineWeb filter…
    json_bit = '{ "t": "p", "c": "x", "b": "y" }'
    bracy = (
        "Prose leakage line the log and the of to and that have with: "
        f"{json_bit} {json_bit} {json_bit}\n" * 10
    )
    path = write_doc(tmp_path, "bracy.md", bracy)
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert any("curly" in f for f in report.failures)
    assert report.curly_ratio >= 0.030

    # …while the same braces inside fenced code blocks never do.
    fenced = (
        "The log keeps every leaf and the hash of every leaf, and the of to and that have with.\n\n"
        "```json\n"
        '{ "type": "post", "channel": "test", "body": "text" }\n'
        "```\n" * 10
    )
    path = write_doc(tmp_path, "fenced.md", fenced)
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert not any("curly" in f for f in report.failures)
    assert report.curly_ratio < 0.030


def test_line_end_punctuation_ratio(tmp_path):
    telegraphic = (
        "log leaf hash key name gate tls port seven seven zero zero verify then trust nothing\n" * 10
    )
    path = write_doc(tmp_path, "telegraphic.md", telegraphic)
    report = ccq.check_document(path, ccq.AuditConfig(min_words=10))
    assert any("punctuation" in f for f in report.failures)
    assert report.punct_ratio <= 0.25


def test_lorem_ipsum_fails(tmp_path):
    text = GOOD_DOC_A + "\nLorem ipsum dolor sit amet, consectetur adipiscing elit sed do.\n"
    path = write_doc(tmp_path, "placeholder.md", text)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert any("lorem ipsum" in f for f in report.failures)


# ---------------------------------------------------------------------------
# Withdrawn-claim detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claim", ["zero-knowledge", "bearer token", "aics_live_", "foundry", "monero treasury", "x402", "l402"]
)
def test_withdrawn_claims_detected(tmp_path, claim):
    text = (
        "# Guide\n\n" + prose_block(SENTENCES_B, 6)
        + f"\n\nThe service is {claim} ready for everyone and everything.\n"
    )
    path = write_doc(tmp_path, "guide.md", text)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert claim in report.withdrawn_claims
    assert any("withdrawn" in f for f in report.failures)


@pytest.mark.parametrize("name", ["AICS-1.md", "DESIGN.md", "DECISIONS.md"])
def test_withdrawn_claims_exempt_in_non_goal_documents(tmp_path, name):
    text = (
        "# Non-goals\n\n" + prose_block(SENTENCES_B, 6)
        + "\n\nWe do not offer zero-knowledge anything, no bearer token, no monero treasury.\n"
    )
    path = write_doc(tmp_path, name, text)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert report.withdrawn_claims == ()
    assert not any("withdrawn" in f for f in report.failures)


def test_withdrawn_claim_on_banning_line_is_not_a_claim(tmp_path):
    # docs/site/README.md quotes the banned words to ban them.
    text = (
        "# Rules\n\n" + prose_block(SENTENCES_B, 6)
        + '\n\n"End-to-end encrypted", never "zero-knowledge".\n'
    )
    path = write_doc(tmp_path, "README.md", text)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert report.withdrawn_claims == ()


# ---------------------------------------------------------------------------
# 5-gram shingles, Jaccard, MinHash
# ---------------------------------------------------------------------------


def test_shingle_set_is_five_word_ngrams():
    words = "a b c d e f".split()
    shingles = ccq.shingle_set(words, n=5)
    assert shingles == frozenset({"a b c d e", "b c d e f"})
    assert ccq.shingle_set(["a", "b"], n=5) == frozenset()


def test_jaccard_basics():
    empty = frozenset()
    a = frozenset({"x", "y", "z"})
    b = frozenset({"x", "y", "z"})
    c = frozenset({"x"})
    assert ccq.jaccard(a, b) == 1.0
    assert ccq.jaccard(a, c) == 1 / 3
    assert ccq.jaccard(a, empty) == 0.0
    assert ccq.jaccard(empty, empty) == 1.0


def test_minhash_signature_shape_and_determinism():
    shingles = ccq.shingle_set(ccq.normalized_words(GOOD_DOC_A), n=5)
    sig1 = ccq.minhash_signature(shingles, perms=128, seed=0)
    sig2 = ccq.minhash_signature(shingles, perms=128, seed=0)
    sig3 = ccq.minhash_signature(shingles, perms=64, seed=0)
    assert len(sig1) == 128
    assert sig1 == sig2  # deterministic for a fixed seed
    assert len(sig3) == 64
    assert ccq.minhash_similarity(sig1, sig1) == 1.0
    assert ccq.minhash_signature(frozenset(), perms=128) == ()


def test_minhash_similarity_approximates_exact_jaccard():
    rng_words = [f"w{i}" for i in range(400)]
    doc_a = rng_words[:200]
    doc_b = rng_words[:120] + rng_words[200:280]  # 60% shingle overlap
    shingles_a = ccq.shingle_set(doc_a, n=5)
    shingles_b = ccq.shingle_set(doc_b, n=5)
    exact = ccq.jaccard(shingles_a, shingles_b)
    estimate = ccq.minhash_similarity(
        ccq.minhash_signature(shingles_a, 128, 0), ccq.minhash_signature(shingles_b, 128, 0)
    )
    assert abs(exact - estimate) < 0.15
    assert 0.0 < exact < 1.0


def test_audit_flags_near_identical_documents(tmp_path):
    base = GOOD_DOC_A
    near_copy = base + "One extra closing line that changes almost nothing here.\n"
    a = write_doc(tmp_path, "original.md", base)
    b = write_doc(tmp_path, "near-copy.md", near_copy)
    report = ccq.audit([a, b], ccq.AuditConfig())
    assert not report.ok
    top = report.pairs[0]
    assert top.jaccard > 0.40
    assert top.minhash > 0.40
    assert not top.ok


def test_audit_accepts_distinct_documents(tmp_path):
    a = write_doc(tmp_path, "guide-a.md", GOOD_DOC_A)
    b = write_doc(tmp_path, "guide-b.md", GOOD_DOC_B)
    report = ccq.audit([a, b], ccq.AuditConfig())
    assert all(pair.ok for pair in report.pairs)
    assert all(doc.ok for doc in report.documents)
    assert report.ok


# ---------------------------------------------------------------------------
# Educational score
# ---------------------------------------------------------------------------


def test_educational_score_rewards_specs_over_fluff():
    spec_body = (
        "A leaf is defined as one signed entry in the log.\n\n"
        "The server MUST verify the signature; it MUST NOT accept an unsigned write.\n"
        "The server MUST refuse a replayed nonce; it SHOULD log each refusal.\n"
        "The checkpoint hash MUST cover every leaf below it.\n\n"
        "```text\nverify checkpoint 0x1234\n```\n"
    )
    spec = ccq.extract_markdown("# Spec\n\n" + spec_body * 4)
    fluff_body = (
        "Our revolutionary, seamless, next-generation platform is guaranteed to be the best.\n"
        "It is 100% trustless and a safe haven for everyone, cutting-edge and industry-leading.\n"
        "Seamless. Revolutionary. Guaranteed.\n"
    )
    fluff = ccq.extract_markdown(
        "# Revolutionary seamless product\n\n" + fluff_body * 3
    )
    spec_score, spec_parts = ccq.educational_score(spec)
    fluff_score, fluff_parts = ccq.educational_score(fluff)
    assert 0.0 <= fluff_score < spec_score <= 5.0
    assert spec_parts["invariants"] >= 0.4  # RFC 2119 keywords present
    assert spec_parts["examples"] == 1.0
    assert spec_parts["crypto_verification"] >= 0.5
    assert fluff_parts["no_marketing_fluff"] == 0.0


def test_educational_score_ignores_banned_word_lists():
    rules = ccq.extract_markdown(
        "No marketing words: revolutionary, trustless, guaranteed, 100%.\n"
    )
    _, parts = ccq.educational_score(rules)
    assert parts["no_marketing_fluff"] == 1.0  # the line bans the words


# ---------------------------------------------------------------------------
# HTML end-to-end
# ---------------------------------------------------------------------------


def test_html_document_full_pipeline(tmp_path):
    html = (
        "<!doctype html><html><head><style>body{margin:0}</style></head><body>"
        "<nav>Home Pricing Signup login</nav>"
        "<main><h1>The public log</h1>"
        "<p>" + " ".join(SENTENCES_A) + "</p>"
        "<p>" + " ".join(reversed(SENTENCES_A)) + ".</p>"
        "<h2>Verification</h2>"
        "<pre><code>openssl s_client -connect gate.example:7700 {verify}</code></pre>"
        "<p>Run the command, compare the digest of every leaf, and check the signature.</p>"
        "</main>"
        "<footer>© marketing footer subscribe</footer>"
        "</body></html>"
    )
    path = write_doc(tmp_path, "log.html", html)
    report = ccq.check_document(path, ccq.AuditConfig())
    assert report.failures == [], report.failures
    assert report.words >= 120
    assert report.curly_ratio < 0.030  # braces live in the <pre> block only


# ---------------------------------------------------------------------------
# The repository's actual documents
# ---------------------------------------------------------------------------


def test_repository_default_documents_are_discovered():
    docs = ccq.default_documents(REPO_ROOT)
    names = {ccq._display_path(d) for d in docs}
    assert "docs/BANNER.md" in names
    assert "docs/DESIGN.md" in names
    assert "docs/PROTOCOL-TEXT.md" in names
    assert "docs/spec/AICS-1.md" in names
    assert "docs/spec/SWARMS.md" in names
    assert "skills/wesupport-ai/SKILL.md" in names
    assert any(name.startswith("docs/site/") for name in names)


def test_repository_documents_pass_the_audit():
    report = ccq.audit(ccq.default_documents(REPO_ROOT), ccq.AuditConfig())
    for doc in report.documents:
        assert doc.failures == [], (doc.path, doc.failures)
    for pair in report.pairs:
        assert pair.ok, (pair.path_a, pair.path_b, pair.jaccard, pair.minhash)
    assert report.ok


def test_cli_defaults_exit_zero_and_print_table(capsys):
    rc = ccq.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "RESULT: PASS" in out
    assert "docs/BANNER.md" in out
    assert "docs/spec/AICS-1.md" in out
    assert "skills/wesupport-ai/SKILL.md" in out
    assert "Jaccard" in out or "jaccard" in out.lower()


def test_cli_json_report_parses_and_passes(capsys):
    rc = ccq.main(["--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["ok"] is True
    assert any(d["path"] == "docs/BANNER.md" for d in payload["documents"])
    assert payload["pairs"] and all(p["ok"] for p in payload["pairs"])


def test_cli_failing_document_exits_one(tmp_path, capsys):
    path = write_doc(tmp_path, "bad.md", "Too short and has zero-knowledge claims.\n")
    rc = ccq.main([str(path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "RESULT: FAIL" in out
    assert "zero-knowledge" in out


def test_cli_missing_file_exits_two(tmp_path, capsys):
    rc = ccq.main([str(tmp_path / "nope.md")])
    assert rc == 2
    assert "missing" in capsys.readouterr().out.lower()


def test_cli_min_edu_score_gate(tmp_path, capsys):
    path = write_doc(tmp_path, "fluff.md", GOOD_DOC_A)
    rc = ccq.main([str(path), "--min-edu-score", "4.9"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "educational score" in out
