"""Interop findings against the packages, as data.

Each finding names the file and line on git HEAD, the specification text it
departs from, and the expected versus actual bytes or behaviour that an
interop test observed.  Tests that demonstrate a finding are marked
``xfail(strict=True, raises=...)`` with the finding ID and the exception the
departure raises today, so the suite stays green while a finding is open, any
other exception (an API rename in a sibling, a broken driver) fails the test,
and the suite turns red (XPASS) the moment the package is fixed, which is the
cue to remove the marker.  ``documents`` lists the tests that document the
finding (they assert the departing bytes, or use the departing form as a
control): they do not XPASS when the package is fixed, most fail outright, so
they are deleted or converted together with the finding.  ``README.md`` lists the same IDs; a
test keeps the two in sync.  Packages are never patched from here.

A fixed finding is not deleted (IDs stay consecutive and the fixtures name
them): its ``status`` becomes ``"retired"``, ``note`` says what the package
now does, its markers are removed so that the tests that demonstrated it guard
the fix, and ``file``/``line`` keep the place where it was found (no longer
checked against git HEAD).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Finding:
    id: str
    package: str
    file: str
    line: int
    spec: str
    summary: str
    expected: str
    actual: str
    severity: str  # interop-breaking | strictness | spec-text | packaging
    needle: str = ""  # text that appears on ``file:line`` at git HEAD (checked by tests/test_findings.py)
    #: ``tests/<file>.py::<test>``: tests that document the finding and do not XPASS when it is fixed
    documents: tuple[str, ...] = ()
    #: "open", or "retired" once the package follows AICS-1 and the demonstrating tests pass without markers
    status: str = "open"
    #: for a retired finding: what the package does now (no commit is named; git history has the change)
    note: str = ""

    @property
    def open(self) -> bool:
        return self.status == "open"

    def as_dict(self) -> dict:
        return asdict(self)


FINDINGS: dict[str, Finding] = {f.id: f for f in [
    Finding(
        "F01", "aics-identity", "packages/aics-identity/src/aics_identity/envelope.py", 286,
        "AICS-1 §4.1 envelope_hash = hexH(J(E)); §4.2 prev = hexH(J(previous accepted E))",
        "envelope_hash() hashes only {v, protected, payload, sig} (_CORE_MEMBERS, line 110) and drops 'auth', "
        "so next_chain/check_successor/chain_breaks compute a different prev than AICS-1 for every AICS-1 envelope",
        "A.1 envelope hash 6fcbe0486d4169e7ae2d771792f5735f5642d260e2bafa4d6124dc355e159ba4",
        "envelope_hash(A.1) = ace130d38828b0ef3c024aa8172e122a0596ce10d9cb01e1821338f6e00bfe8e; chain_breaks() "
        "reports a 'prev' break at position 1 of every AICS-1 chain of two or more envelopes (positions 1 and 2 of a "
        "valid 3-envelope chain aics-conformance accepts), so for a chain broken at position 2 its first reported "
        "break is position 1",
        "interop-breaking",
        needle='for name in _CORE_MEMBERS',
        status="retired",
        note=("envelope_hash() hashes the complete envelope, auth included (hexH(J(E)), §4.1), and refuses an object "
              "without exactly the five envelope members; next_chain, check_successor and chain_breaks use it, so "
              "the A.1 hash is reproduced and a broken AICS-1 chain is reported at the position aics-conformance and "
              "the reference report")),
    Finding(
        "F02", "aics-identity", "packages/aics-identity/src/aics_identity/envelope.py", 269,
        "AICS-1 §4.1 seen is null for initial bootstrap or {checkpoint_note_hash,size}; §4.2 a new client MAY use null",
        "validate_chain_fields() calls validate_seen() whenever the member is present, so verify_envelope() "
        "rejects every AICS-1 envelope with \"seen\":null (all three Appendix A leaves 0-2)",
        "verify_envelope(entries[1].payload.envelope) returns the payload",
        "MalformedEnvelope('seen must be an object') raised at envelope.py:199",
        "interop-breaking",
        needle='validate_seen(protected["seen"])',
        status="retired",
        note=("validate_seen() accepts null (initial bootstrap) or exactly {checkpoint_note_hash, size}; "
              "verify_envelope() verifies envelopes with seen null, the Appendix A leaves 0-2 included, and agrees "
              "with aics-conformance on every seen case")),
    Finding(
        "F03", "aics-identity", "packages/aics-identity/src/aics_identity/envelope.py", 413,
        "AICS-1 §4.1 protected has exactly {alg,origin,type,kid,created,expires,nonce,seq,prev,seen}, auth is "
        "{scheme:'ed25519-jcs'}, kid is the signing did:key (§3.1)",
        "sign_envelope() cannot produce an AICS-1 envelope: _protected_header() emits only alg/kid/created/expires/"
        "nonce (+seq/prev/seen when given), there is no origin/type/auth, and the default kid is the 16-character "
        "key_id (line 454), not a did:key",
        "protected members alg,created,expires,kid,nonce,origin,prev,seen,seq,type and a top-level auth member",
        "protected members alg,created,expires,kid,nonce,prev,seen,seq; no auth; kid like 'Kpx3...' (16 chars); "
        "aics-conformance rejects it (KeyError 'auth')",
        "interop-breaking",
        needle='def _protected_header(',
        status="retired",
        note=("sign_envelope() requires origin and type, writes exactly the §4.1 protected members and auth {scheme: "
              "ed25519-jcs}, and its kid is the signing key's did:key (any other kid raises): its envelopes are the "
              "reference's bytes and aics-conformance verifies them")),
    Finding(
        "F04", "aics-identity", "packages/aics-identity/src/aics_identity/envelope.py", 599,
        "AICS-1 §4.3 REQUIRED: created <= t+30, created >= t-300, created < expires <= created+300, t < expires",
        "verify_envelope() defaults accept envelopes AICS-1 refuses: t == expires (line 570 rejects only "
        "t > expires), expires == created (line 531 rejects only expires < created) and lifetimes over 300 s "
        "(max_lifetime defaults to None, line 480)",
        "rejection for t == expires, for expires == created and for expires - created = 301",
        "all three accepted with the default arguments",
        "strictness",
        needle='if current > expires + max_clock_skew',
        status="retired",
        note=("check_freshness(), which verify_envelope() calls, applies §4.3 as written: created <= t+30, created "
              ">= t-300, created < expires <= created+300 and t < expires, so all three envelopes are refused with "
              "the default arguments")),
    Finding(
        "F05", "aics-identity", "packages/aics-identity/src/aics_identity/sealed.py", 415,
        "AICS-1 §8.1 plaintext = uint32be(len(header_bytes)) || header_bytes || content_bytes; Appendix A.4",
        "seal() frames the plaintext as JCS(header) || 0x0A || body and open_sealed() splits at the first LF "
        "(_split_plaintext, line 432), so sealed boxes do not interoperate with aics-conformance in either "
        "direction and the Appendix A.4 ciphertext cannot be opened",
        "A.4 plaintext 000000b5 7b22656e... ('hello\\n' content), opened by crypto_box_seal_open",
        "open_sealed(A.4) raises MalformedSealed (byte 3 is 0xb5); aics-identity plaintexts start 7b22 with no "
        "length prefix and aics-conformance raises 'invalid inner framing'",
        "interop-breaking",
        needle='inner.canonical_bytes() + b"\\n" + body_bytes',
        status="retired",
        note=("seal() frames uint32be(len(header)) || header || content (frame_plaintext) and open_sealed() splits "
              "by that length (split_plaintext): the A.4 ciphertext opens, and sealed boxes cross between "
              "aics-identity, aics-conformance and the reference in both directions")),
    Finding(
        "F06", "aics-identity", "packages/aics-identity/src/aics_identity/http_signatures.py", 96,
        "AICS-1 §12.1 one signature label 'aics'; keyid MUST equal the envelope kid (a did:key)",
        "DEFAULT_LABEL is 'sig1' and the README's AICS recipe (README.md lines 167-181) signs with label sig1 and "
        "keyid=keys.key_id(...); AICS_VERIFY_POLICY (line 114) does not constrain the label, so a request made "
        "the documented way is refused by an AICS-1 verifier",
        "Signature-Input: aics=(\"@method\" \"@authority\" \"@path\" \"content-digest\");...;keyid=\"did:key:z...\"",
        "Signature-Input: sig1=(...); aics-conformance's server binding answers 403 bad_signature; "
        "verify_request(**AICS_VERIFY_POLICY) accepts a request signed under label sig1",
        "interop-breaking",
        needle='DEFAULT_LABEL = "sig1"',
        status="retired",
        note=("DEFAULT_LABEL is 'aics', the default keyid is the signing key's did:key, sign_request(..., "
              "envelope=E) takes keyid, created, expires and nonce from the envelope (the README recipe), and "
              "AICS_VERIFY_POLICY requires the label aics, so a request signed under sig1 is refused")),
    Finding(
        "F07", "aics-identity", "packages/aics-identity/src/aics_identity/linesig.py", 109,
        "AICS-1 §11.3 signature input is exactly UTF8(session_id) || LF || UTF8(C), with no final LF; §11.2 "
        "MUST NOT silently repair signed content; signature failures are not opportunities to reinterpret bytes",
        "verify_line() defaults to leeway=True (line 199) and also accepts signatures over "
        "'<session>\\n<line>\\n' (line 122) and over the line stripped of spaces/tabs/CR (line 114); aics "
        "verify-line inherits this unless --strict, while aics-conformance verifies with leeway=False",
        "only the bytes 73657373...0a<line> without a trailing 0a verify",
        "a signature over the same bytes plus 0x0a: aics verify-line exit 0, aics-conformance rejects",
        "strictness",
        needle='leeway: bool = True',
        status="retired",
        note=("verify_line() defaults to leeway=False: only UTF8(session) || LF || UTF8(line) verifies, and "
              "leeway=True is an explicit opt-out for tools outside the protocol. The aics CLI's verify-line follows "
              "the same default (F26 retired)")),
    Finding(
        "F08", "aics-tlog", "packages/aics-tlog/src/aics_tlog/checkpoint.py", 288,
        "AICS-1 §6.2 parsers ... reject duplicate lines for a recognized (name,key_id) ... and ignore unknown keys, "
        "including repeated unknown-key lines",
        "verify_checkpoint() rejects any repeated (name, key ID) pair, unknown keys included; aics-witness "
        "ignores them (service.py _verify_log_signatures) and cosigns, so the cosigned note that "
        "merge_cosignatures() returns is then rejected by aics-tlog, aics and aics-conformance",
        "a note with two identical foreign signature lines verifies (they are ignored)",
        "CheckpointVerifyResult.error 'duplicate signature line for <name> <keyid>'; aics verify checkpoint "
        "exits 2 with evidence reason 'bad_signature' when the origin serves it (a validly log-signed note "
        "reported as evidence against the log); aics-conformance verify.head() raises the same error",
        "interop-breaking",
        needle='No duplicate (name, key ID) signature lines',
        status="retired",
        note=("verify_checkpoint() refuses a repeated line only for a recognized (name, key ID) and ignores the "
              "lines of unknown keys, repeated ones included, so the note aics-witness cosigns verifies in "
              "aics-tlog, aics (exit 0) and aics-conformance")),
    Finding(
        "F09", "aics-tlog", "packages/aics-tlog/src/aics_tlog/cosign.py", 56,
        "AICS-1 §6.3 every counted timestamp MUST satisfy now-max_checkpoint_age <= timestamp <= now+30",
        "DEFAULT_MAX_FUTURE_SECONDS = 300 applies whenever a max age is given without a future bound, so "
        "verify_checkpoint(policy=...) and 'aics-tlog verify-checkpoint --max-age N' (the third-party check "
        "printed in aics evidence bundles) count cosignatures dated up to now+300",
        "a cosignature dated now+31 does not count (aics-conformance passes max_future_seconds=30, verify.py line "
        "24; aics calls verify_checkpoint with quorum 0 and applies its own DEFAULT_MAX_SKEW = 30, checkpoints.py "
        "line 54)",
        "aics-tlog counts it: ok=True, cosignature_count=1",
        "strictness",
        needle='DEFAULT_MAX_FUTURE_SECONDS = 300',
        status="retired",
        note=("DEFAULT_MAX_FUTURE_SECONDS is 30: with a max age and no explicit future bound a cosignature dated "
              "more than 30 s ahead does not count, in the library, under a WitnessPolicy and in 'aics-tlog "
              "verify-checkpoint --max-age'")),
    Finding(
        "F10", "aics-tlog", "packages/aics-tlog/src/aics_tlog/bundle.py", 62,
        "AICS-1 §14.3 wire bundle {entry_bytes:U64,index:uint,inclusion_proof:[B64],checkpoint_note:U64,"
        "envelope:E,body_or_ct:U64-or-null}",
        "Bundle uses 'entry_bytes_b64' (padded standard base64), the raw note text for checkpoint_note and "
        "standard base64 for body_or_ct (lines 78-83); neither side accepts the other's bundle",
        "{\"entry_bytes\": \"<U64>\", \"checkpoint_note\": \"<U64 of the note bytes>\", ...}",
        "{\"entry_bytes_b64\": \"<B64>\", \"checkpoint_note\": \"<note text>\", ...}: aics-conformance raises "
        "KeyError 'entry_bytes'; Bundle.from_dict(spec bundle) raises \"bundle is missing 'entry_bytes_b64'\"",
        "interop-breaking",
        needle='"entry_bytes_b64"',
        status="retired",
        note=("Bundle.to_dict()/from_dict() are exactly the §14.3 wire bundle (entry_bytes, the complete "
              "checkpoint_note and body_or_ct in U64; the pre-0.2 form is refused), so aics-tlog, aics-conformance "
              "and the reference exchange one bundle form, byte for byte, library and CLI")),
    Finding(
        "F11", "aics-conformance", "packages/aics-conformance/src/aics_conformance/guarantees/g5.py", 10,
        "AICS-1 §14.6 steps 1-2: authenticate the notes by origin and log signatures; equal sizes with different "
        "roots are direct evidence of equivocation; state whether each also met its witness policy",
        "G5 authenticates every head with verify.head() (verify.py line 25), which requires the witness quorum "
        "(also with historical=True), before comparing roots; a log-signed conflicting note without "
        "cosignatures, or with a witness line that does not verify, is reported as a quorum or cosignature "
        "failure, exactly like a consistent but uncosigned mirror head, and the roots are never compared",
        "aics gossip-check: exit 2, classification 'log-equivocation', both notes in the evidence bundle; "
        "AICS-1: split-proven, note 2 did not meet its witness policy",
        "G5: verdict fail, verification 'invalid', reason 'quorum not met: 0 valid fresh cosignatures < 1' or "
        "'cosignature from witness-a.interop.test/w1 failed verification' (the notes are in "
        "details.evidence.checkpoint_notes but no split is stated); verify.head(historical=True) raises the same "
        "errors, so verify.continuity is never reached",
        "interop-breaking",
        needle='ctx.head(source)',
        status="retired",
        note=("G5 now authenticates every view by origin and log signature alone (verify.authenticate), compares all "
              "of them, and only then requires the witness policy; verify.head(historical=True) states "
              "witness_policy_met instead of raising. Both F11 pairs are split-proven, the evidence states which "
              "note met its policy, and a consistent unwitnessed mirror still fails as 'quorum not met'")),
    Finding(
        "F12", "aics-conformance", "packages/aics-conformance/src/aics_conformance/fakes/server.py", 132,
        "AICS-1 §12.1 the receiver recomputes Content-Digest over the actual HTTP content bytes before parsing JSON",
        "the fake server (the package's only RFC 9421 verifier) re-serializes the parsed body as J({envelope,body}) "
        "and verifies the digest over that (request bytes are dropped at line 207), so a valid request whose JSON "
        "body is not JCS is refused and a request whose body bytes differ from the digested ones is accepted when "
        "they parse to the same JSON value",
        "202 for a correctly signed request with a pretty-printed JSON body; 403 for a body changed after signing",
        "403 bad_signature (aics-identity verify_request and the independent verifier accept the same request); "
        "202 for the fixture request whose signed body gained a trailing space (both other verifiers refuse it)",
        "strictness",
        needle='J(dict(envelope=env,body=',
        status="retired",
        note=("FakeServer.request passes the request bytes to submit(content=...), which verifies Content-Digest "
              "over them; submit() without content= raises TypeError instead of re-serializing the parsed JSON")),
    Finding(
        "F13", "aics + aics-conformance", "packages/aics-cli/src/aics_cli/card.py", 357,
        "AICS-1 (0.2-draft) §13.1 version: \"0.2-draft\"; spec_versions tlog-checkpoint/signed-note/"
        "tlog-cosignature/tlog-witness \"1.1.0\"",
        "both card verifiers still require the 0.1-draft card: aics card.py line 357 (version) and line 64 "
        "(SPEC_VERSIONS all 1.0.0); aics-conformance card.py lines 9 and 47; the conformance fake serves a "
        "0.1-draft card (fakes/server.py lines 54, 68)",
        "a card with version 0.2-draft and the 1.1.0 pins verifies",
        "aics verify card exit 2 (schema: $.version, $.spec_versions); aics-conformance 'card exact schema'; both "
        "accept the 0.1-draft card, which AICS-1 0.2-draft refuses",
        "interop-breaking",
        needle='equals="0.1-draft"',
        status="retired",
        note=("aics card.py and aics-conformance card.py accept version 0.2-draft with the v1.1.0 pins only, and "
              "refuse a 0.1-draft card with a version problem ($.version / 'card version must be 0.2-draft'); the "
              "conformance fake serves the 0.2-draft card")),
    Finding(
        "F14", "aics-conformance", "packages/aics-conformance/src/aics_conformance/checks/gate.py", 70,
        "packaging: the committed package must contain the data it reads",
        "data/banner.txt is excluded by the repository .gitignore rule '**/data/' (line 11), so it is absent on "
        "git HEAD; gate.banner (checks/gate.py line 70), the fake gate (fakes/gate.py line 39) and "
        "FakeServer.request (fakes/server.py line 194, read before routing every path except checkpoint, tiles "
        "and /t, so POST /v2/entries too) raise FileNotFoundError in a clean checkout such as CI",
        "git ls-files lists packages/aics-conformance/src/aics_conformance/data/banner.txt",
        "the file exists only as an ignored local file",
        "packaging",
        needle='data/banner.txt',
        status="retired",
        note=("the banner is docs/BANNER.md's fenced block in aics_conformance/dialogue.py (BANNER_TEXT; BANNER is "
              "the pre-client variant, equal to wellknown/llms.txt.header); no source reads data/banner.txt or any "
              "package data")),
    Finding(
        "F15", "aics-witness + aics + aics-conformance", "packages/aics-witness/pyproject.toml", 23,
        "packaging: sibling path sources must agree to be co-installable",
        "aics-witness declares aics-tlog as an editable path source while aics (pyproject line 32) and "
        "aics-conformance (line 13) declare the same directory non-editable; uv refuses to resolve them together "
        "('conflicting URLs for package aics-tlog'); this suite needs override-dependencies to install all five",
        "one consistent source declaration",
        "uv sync fails without [tool.uv] override-dependencies",
        "packaging",
        needle='editable = true',
        status="retired",
        note='aics-witness declares aics-tlog as a non-editable path source, like aics and aics-conformance'),
    Finding(
        "F16", "aics-tlog", "packages/aics-tlog/src/aics_tlog/__init__.py", 66,
        "packaging: one version per release",
        "__version__ is '0.1.0' (printed by aics-tlog --version) while the distribution is 0.2.0 (pyproject.toml "
        "line 3)",
        "0.2.0", "0.1.0", "packaging",
        needle='__version__ = "0.1.0"',
        status="retired",
        note=("__version__ is '0.2.0', the distribution version (aics-tlog's tests/test_version.py keeps the module, "
              "the CLI and the metadata equal)")),
    Finding(
        "F17", "docs", "docs/spec/AICS-1.md", 396,
        "AICS-1 §11.4 item 2 allows an exact-byte file 'where the tool cannot sign a pipe'",
        "the printed openssl recipe 'printf ... | openssl pkeyutl -sign -inkey aics.key -rawin | base64' fails on "
        "OpenSSL 3 and 4 ('unable to determine file size for oneshot operation'); AICS-1 §11.4 item 2 (line 396) and "
        "aics-conformance dialogue.py line 17, which copies it, print only the pipe form (PROTOCOL-TEXT §3 now writes "
        "the message to a file and signs with -in, and that recipe signs)",
        "a signature on stdout", "empty output, error from openssl pkeyutl", "spec-text",
        needle='| openssl pkeyutl -sign -inkey aics.key -rawin |',
        status="retired",
        note=("AICS-1 §11.4 item 2 prints the file form (printf ... > aics-signing-input; openssl pkeyutl -sign "
              "-inkey aics.key -rawin -in aics-signing-input | base64 | tr -d '\\n'), which signs on OpenSSL 3 and 4; "
              "aics-conformance's dialogue.openssl_sign prints the same text, and its onboarding check expects it in "
              "the openssl tools reply as item 2 places it")),
    Finding(
        "F18", "aics-tlog", "packages/aics-tlog/src/aics_tlog/tree.py", 238,
        "AICS-1 §14.2 step 1: for sizes m=n require identical roots and an empty proof; for m=0 require the "
        "standard empty root and an empty proof",
        "verify_consistency() returns True for old_size 0 whatever the old root is (line 238-240) and False for "
        "two size-0 trees (new_size <= 0, line 236); 'aics-tlog verify-consistency --old-size 0' (proof-file "
        "mode) therefore accepts a log-signed size-0 head whose root is not SHA-256(''), which aics, aics-witness "
        "and aics-conformance all reject",
        "verify_consistency(0, 12, H('not the empty tree'), root12, []) is False; "
        "verify_consistency(0, 0, H(''), H(''), []) is True",
        "True and False respectively; the CLI exits 0 with \"ok\": true for the bad empty root",
        "strictness",
        needle='if old_size == 0:',
        status="retired",
        note=("verify_consistency() requires the empty-tree root and an empty proof for old size 0 and identical "
              "roots for equal sizes: a size-0 head with another root is refused (library and 'aics-tlog "
              "verify-consistency') and two empty trees are consistent")),
    Finding(
        "F19", "aics-conformance", "packages/aics-conformance/src/aics_conformance/verify.py", 169,
        "AICS-1 §14.3 package {bundle,trust_bundle,policy_cards:[U64],entry_prefix:[U64],checkpoint_notes:[U64]}; "
        "§2 objects have exactly the specified members",
        "offline_package() reads package['trust_policy'] (line 169), a member AICS-1 does not define, and G8 "
        "builds its saved package with it (guarantees/g8.py line 8), so a package written to the specification "
        "is refused and the package G8 writes is not an AICS-1 package",
        "verify.offline_package(spec package) verifies; the G8 package has exactly the five members",
        "KeyError 'trust_policy'; with trust_policy added the same package verifies",
        "interop-breaking",
        needle="package['trust_policy']",
        status="retired",
        note=("offline_package() requires exactly the five §14.3 members (a package with trust_policy is refused) "
              "and takes the witness policy from the verifier's pins; G8 writes exactly those members; saved "
              "checkpoint notes must be log-signed and agree with the package prefix")),
    Finding(
        "F20", "aics", "packages/aics-cli/src/aics_cli/trust.py", 139,
        "AICS-1 §6.4 README and PyPI carry the same bytes and their hexH digest; disagreements MUST stop bootstrap",
        "bundle_from_text() takes the aics1= value from a README block and ignores its sha256 line, so 'aics "
        "policy init --bundle' pins a block whose stated digest contradicts its bytes (and records the "
        "recomputed digest as trust_bundle_sha256), while the same contradiction in the PyPI constant is "
        "refused (published_bundle, line 207)",
        "policy init exits non-zero for 'sha256: 000...0' under a valid aics1= line",
        "exit 0, the bundle is pinned",
        "strictness",
        needle='re.search(r"aics1=(',
        status="retired",
        note=("bundle_from_text() checks a README block's sha256 line against the bundle bytes and refuses a "
              "contradicting, malformed or repeated digest (exit 1), as for the PyPI constant")),
    Finding(
        "F21", "aics-conformance", "packages/aics-conformance/src/aics_conformance/policy.py", 28,
        "AICS-1 §6.4 bundle is exactly {v:1,origin,log_vkey,policy_kid,owner_kid,bootstrap_card_hash}; §2 unknown "
        "members MUST be rejected; §3.1 log, policy and owner keys MUST be distinct",
        "Policy.__post_init__ only checks that five keys are present and that log_vkey parses, so the operator's "
        "trust-bundle.json is accepted without v, with v=2 or v=true, with unknown members, with "
        "policy_kid == owner_kid, with an uppercase card hash or with a scheme in the origin; aics and the "
        "reference refuse all seven",
        "ValueError for each of the seven variants",
        "all seven accepted",
        "strictness",
        needle="for k in ('origin','log_vkey','policy_kid','owner_kid','bootstrap_card_hash')",
        status="retired",
        note=("Policy.__post_init__ calls check_trust_bundle(): exactly the six members, v the integer 1, an origin "
              "without scheme or trailing slash, an Ed25519 log vkey, distinct log/policy/owner keys and a lowercase "
              "hex card hash; all seven variants raise ValueError")),
    Finding(
        "F22", "aics-conformance", "packages/aics-conformance/src/aics_conformance/schema.py", 36,
        "AICS-1 (0.2-draft) §17.2 refusal registry includes the charter-compatible spellings secret_format, rate, "
        "seq, fork, sig, no_grant, size, format, name, key_state, poll_rule (CHANGELOG 0.1 -> 0.2); §13.1 card "
        "reasons MUST equal §17's registries",
        "ENUMS['refusal'] is the 0.1-draft list of 30 detailed codes, so schema.validate_entry() rejects a refusal "
        "leaf carrying any of the eleven registered charter spellings ('unknown refusal code') and "
        "card.verify_card() rejects a card that lists the complete §17.2 registry (card.py line 40, 'reason "
        "registry differs')",
        "refusal leaves with reason_code 'rate' (etc.) validate; a card with the 42-code refusal list verifies",
        "all eleven leaves refused; the card refused with 'reason registry differs'",
        "interop-breaking",
        needle="refusal=set('malformed",
        status="retired",
        note=("ENUMS['refusal'] is the §17.2 0.2-draft registry (schema.REFUSAL, 41 codes: 30 detailed plus the 11 "
              "charter-compatible spellings), secret_format:<id> instances matched separately; the fake's card lists "
              "it")),
    Finding(
        "F23", "aics-identity", "packages/aics-identity/src/aics_identity/envelope.py", 597,
        "AICS-1 §4.3 REQUIRED: created <= t+30 and t < expires; the 30-second allowance applies only to future "
        "creation times, not expiry",
        "verify_envelope() has one symmetric max_clock_skew (line 479, default 0) for both bounds, created > "
        "current + max_clock_skew (line 568) and current > expires + max_clock_skew (line 570): the default refuses "
        "an envelope created up to 30 s ahead, which AICS-1 accepts, and the only setting that admits it "
        "(max_clock_skew=30) also accepts an envelope up to 30 s past its expiry",
        "verify_envelope(created=t+30, expires=t+330, now=t) returns the payload; an envelope with expires=t-1 is "
        "refused at t under every setting",
        "NotYetValidEnvelope for created=t+30 (and t+29) with the default arguments; with max_clock_skew=30 an "
        "envelope created at t-200 with expires=t-1 is accepted at t",
        "strictness",
        needle="if created > current + max_clock_skew",
        status="retired",
        note=("check_freshness() applies max_clock_skew to future creation times only (default 30 s, which a caller "
              "may lower and never raise) and never extends expiry: created = t+30 verifies with the defaults, and "
              "an envelope that expired at t-1 is refused under every setting")),
    Finding(
        "F24", "aics", "packages/aics-cli/src/aics_cli/card.py", 447,
        "AICS-1 §13.1 reasons MUST equal §17's registries for the advertised profile plus only those active "
        "secret_format:<id> instances; §17.2 invalid_signature and other unregistered synonyms MUST NOT silently "
        "become new codes, and secret_format:<pattern_id> is a closed expansion over the card's enumerated patterns",
        "schema_problems() checks reason_codes only for the six registry names and lists of unique non-empty "
        "strings (lines 447-450) and never compares them with §17.2, so 'aics verify card' and 'aics policy init' "
        "accept a card whose refusal registry adds an unregistered code, drops a registered one or names a "
        "secret_format id the card has no pattern for",
        "aics verify card exits 2 with a $.reason_codes problem for a refusal list that adds 'invalid_signature' or "
        "'whatever', drops 'malformed', or adds 'secret_format:no_such_pattern'",
        "exit 0 (bootstrap true, no problem reported) for all four",
        "strictness",
        needle='rc = card["reason_codes"]',
        status="retired",
        note=("schema_problems() compares every reason registry with §17.2 (REASON_REGISTRIES): the refusal registry "
              "must equal the 41 codes plus exactly one secret_format:<id> per card pattern, so all four variants "
              "exit 2 with a $.reason_codes problem")),
    Finding(
        "F25", "aics-conformance", "packages/aics-conformance/src/aics_conformance/card.py", 40,
        "AICS-1 §13.1 reasons equal §17's registries plus only those active secret_format:<id> instances; §17.2 "
        "secret_format:<pattern_id> is a closed expansion over the card's enumerated patterns, not arbitrary text",
        "verify_card() drops every 'secret_format:' entry before comparing a registry with ENUMS (line 40), so a "
        "card whose refusal list names a secret_format id absent from its secret_patterns is accepted",
        "verify_card() refuses a refusal list with 'secret_format:no_such_pattern' (the card's only pattern is "
        "github_pat)",
        "the card is accepted",
        "strictness",
        needle="if not x.startswith('secret_format:')",
        status="retired",
        note=("verify_card() checks secret_patterns and requires each registry to equal §17.2, the refusal registry "
              "plus exactly the card's own secret_format:<id> instances ('reason registry differs' otherwise)")),
    Finding(
        "F26", "aics", "packages/aics-cli/src/aics_cli/commands.py", 187,
        "AICS-1 §11.3 signature input is exactly UTF8(session_id) || LF || UTF8(C), with no final LF; §11.2 "
        "MUST NOT silently repair signed content; signature failures are not opportunities to reinterpret bytes",
        "cmd_verify_line() passes leeway=True to aics-identity verify_line() unless --strict is given (line 187; "
        "cli.py line 96 documents --strict as the exception), so 'aics verify-line' still accepts signatures over "
        "'<session>\\n<line>\\n' and over the line stripped of spaces, tabs and CR, although aics-identity's own "
        "default is now the exact bytes (F07 retired) and aics-conformance verifies with leeway=False",
        "aics verify-line without --strict exits 2 for a signature over the §11.3 bytes plus 0x0a",
        "exit 0 (form raw); only 'aics verify-line --strict' refuses it",
        "strictness",
        needle="leeway = not args.strict",
        status="retired",
        note=("aics verify-line verifies exactly UTF8(session) || LF || UTF8(line) by default, as aics-identity and "
              "aics-conformance do: a signature over the bytes plus 0x0a, or over the stripped line, exits 2. The "
              "wider forms are accepted only with the explicit --leeway flag (for files written outside the "
              "protocol); --strict stays accepted as the default it now names")),
    Finding(
        "F27", "aics-server", "packages/aics-server/src/aics_server/card.py", 534,
        "AICS-1 §13.1 retention {dm_seconds:uint, capsule_max_seconds:uint, ciphertext_budget_bytes:uint, eviction}; "
        "ciphertext_budget_bytes is positive, every quota has an explicit finite value; §8.2 the card MUST specify "
        "a deterministic capacity rule over a published ciphertext-byte budget",
        "build_skeleton() writes retention.ciphertext_budget_bytes null (line 534; G3's assumption says null means "
        "no budget is configured) and no limit or setting fills it, so the card the server builds, signs, serves "
        "and the owner logs is not a §13.1 card: aics-conformance verify_card refuses it, and with it G7, G10 and "
        "rates.published fail against the server (with a reviewed card body that fills the budget, AICS_CARD_FILE, "
        "every check passes)",
        "a positive ciphertext_budget_bytes (the card's capacity rule) and G7, G10 and rates.published passing "
        "against the server's own card",
        "aics-conformance: 'retention bounds' for G7, G10 and rates.published; aics verify card: "
        "'$.retention.ciphertext_budget_bytes: must be an integer from 0 to 2^53-1' (exit 2)",
        "interop-breaking",
        needle='"ciphertext_budget_bytes": None,',
        status="retired",
        note=("the card the server builds states retention.ciphertext_budget_bytes from limits.ciphertext_budget_bytes "
              "(DEFAULT_LIMITS, or AICS_LIMITS_FILE), a positive uint the server enforces with the §8.2 capacity rule "
              "(eviction by earliest (ts, index) after the 90-day minimum, else a reported resource exhaustion); it "
              "refuses to sign a card without one, a reviewed body must state the budget the server applies, and "
              "publish_policy(kind=card) logs only a §13.1 card signed by the policy key. G7, G10 and rates.published "
              "pass against the server's own card, and aics verify card accepts it as the bootstrap card")),
    Finding(
        "F28", "aics-server", "packages/aics-server/src/aics_server/db.py", 1384,
        "AICS-1 §13.1 registration limits count authenticated registration attempts per submitting key, with an "
        "additional global pre-identity bucket; §10.2 authenticated decisions admitted to processing MUST be logged",
        "the published limits.registrations window is one window for the whole service (db.py line 1384, "
        "_admit_registration: 'the global registration window (429, no leaf)'), so once count claims arrived "
        "within interval_seconds, a fresh key's first claim is refused with a 429 and no refusal leaf; the card "
        "states the window as AICS-1 defines it, per submitting key, and the global bucket is limits.preidentity",
        "with the published registrations {count: 30, interval_seconds: 60}, 31 fresh keys each claiming once within "
        "the window are all accepted (no key is over a per-key registration limit)",
        "claims 1-30 are accepted (202) and the 31st and later fresh keys get HTTP 429 without an entry",
        "strictness",
        needle="self._registrations = _Window(",
        status="retired",
        note=("limits.registrations is a window per submitting key; keyless and pre-identity traffic share the "
              "global limits.preidentity bucket, and an authenticated claim over its key's window is logged as a "
              "rate_limit refusal: 31 fresh keys claiming once each within the published window are all accepted")),
]}


def finding(fid: str, *, raises: type[BaseException] | tuple[type[BaseException], ...]):
    """``@finding("F27", raises=AssertionError)``: strict xfail carrying the finding's summary.

    ``raises`` is the exception the departure raises today (``AssertionError``
    for a test that asserts the AICS-1 behaviour), so that any other
    exception, such as an ImportError or TypeError after a sibling's API
    changed, fails the test instead of passing as XFAIL.  Preconditions inside
    such a test use ``pytest.fail``, which is never mistaken for the finding.
    """
    import pytest as _pytest

    f = FINDINGS[fid]
    if not f.open:
        raise ValueError(f"{fid} is {f.status}: its tests pass and guard the fix, so they carry no marker")
    return _pytest.mark.xfail(strict=True, raises=raises, reason=f"{fid} [{f.package}] {f.summary[:160]}")


BEGIN, END = "<!-- findings:begin -->", "<!-- findings:end -->"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def markdown() -> str:
    """The README "Findings" block, rendered from FINDINGS (tests/test_findings.py keeps them equal)."""
    out = ["| ID | Package | Severity | Status | Where (git HEAD; where it was found, if retired) |",
           "| --- | --- | --- | --- | --- |"]
    for f in FINDINGS.values():
        out.append(f"| [{f.id}](#{f.id.lower()}) | {f.package} | {f.severity} | {f.status} | `{f.file}:{f.line}` |")
    for f in FINDINGS.values():
        out += ["", f"### {f.id}", "",
                f"**{f.package}**, `{f.file}` line {f.line} ({f.severity}"
                + (")." if f.open else f"; {f.status}, the cited line is where it was found)."), "",
                f"- Specification: {f.spec.rstrip('.')}.",
                f"- Finding: {f.summary.rstrip('.')}.",
                f"- Expected: {f.expected.rstrip('.')}.",
                f"- Actual{'' if f.open else ' (when found)'}: {f.actual.rstrip('.')}."]
        if not f.open:
            out.append(f"- Retired: {f.note.rstrip('.')}.")
        if f.documents:
            out.append("- Documented by (delete or convert with the finding; they do not XPASS): "
                       + ", ".join(f"`{t}`" for t in f.documents) + ".")
    return "\n".join(out) + "\n"


def write_readme(path) -> bool:
    """Replace the block between the markers; returns True when the file changed."""
    from pathlib import Path

    p = Path(path)
    text = p.read_text("utf-8")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    new = f"{head}{BEGIN}\n{markdown()}{END}{tail}"
    if new != text:
        p.write_text(new, "utf-8")
    return new != text


if __name__ == "__main__":  # python -m aics_interop.findings: refresh the README block
    from pathlib import Path

    readme = Path(__file__).resolve().parents[2] / "README.md"
    print("README.md updated" if write_readme(readme) else "README.md already current")
