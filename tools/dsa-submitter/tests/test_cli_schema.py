"""Groups O and Q: the CLI surface and schema spot-checks."""

from conftest import minimal_statement

from dsa_submitter import cli, schema, state

CLOSED_LISTS = (
    "DECISION_VISIBILITY", "DECISION_MONETARY", "DECISION_PROVISION",
    "DECISION_ACCOUNT", "ACCOUNT_TYPES", "DECISION_GROUNDS", "CONTENT_TYPES",
    "STATEMENT_CATEGORIES", "CATEGORY_SPECIFICATIONS", "TERRITORIAL_SCOPES",
    "SOURCE_TYPES", "AUTOMATED_DECISIONS", "YES_NO",
)


# --- O: cli ----------------------------------------------------------------

def test_parser_accepts_scan_submit_status():
    parser = cli.build_parser()
    assert parser.parse_args(["scan"]).command == "scan"
    assert parser.parse_args(["submit", "--decisions", "x.jsonl"]).command == "submit"
    assert parser.parse_args(["status"]).command == "status"


def test_status_prints_submitted_failed_and_pending(tmp_path, capsys):
    path = tmp_path / "state.json"
    state.save(str(path), {
        "version": 1,
        "entries_scanned": 15,
        "leaves": {
            "2": {"status": "submitted", "kind": "tombstone",
                  "reason_code": "illegal_on_notice", "puid": "aics-leaf-2",
                  "uuid": "uuid-1", "id": 123, "submitted_at": "2026-10-19T00:00:00Z"},
            "4": {"status": "failed", "kind": "tombstone", "reason_code": "order",
                  "puid": "aics-leaf-4", "status_code": 422,
                  "error": "HTTP 422: The given data was invalid."},
            "10": {"status": "pending", "kind": "suspension", "reason_code": "flood",
                   "puid": "aics-leaf-10", "reason": "needs operator input"},
        },
    })
    rc = cli.main(["status", "--state", str(path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "leaf 2" in out and "submitted uuid=uuid-1" in out
    assert "leaf 4" in out and "FAILED (HTTP 422)" in out
    assert "leaf 10" in out and "pending" in out


def test_cli_scan_against_the_fake(fake_aics, tmp_path, capsys):
    rc = cli.main(["scan", "--base-url", fake_aics.url,
                   "--state", str(tmp_path / "state.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert f"tree size {fake_aics.tree_size}" in out
    assert "5 pending restriction(s)" in out
    assert "reason=illegal_on_notice" in out


# --- Q: schema spot-checks -------------------------------------------------

def test_every_closed_list_is_non_empty():
    for name in CLOSED_LISTS:
        values = getattr(schema, name)
        assert values, name
        assert all(isinstance(value, str) for value in values), name


def test_bad_category_is_rejected():
    statement = minimal_statement()
    statement["category"] = "STATEMENT_CATEGORY_MADE_UP"
    assert any("category" in error for error in schema.validate_statement(statement))


def test_missing_decision_types_are_rejected():
    statement = minimal_statement()
    del statement["decision_visibility"]
    errors = schema.validate_statement(statement)
    assert any("required when" in error for error in errors)


def test_illegal_ground_requires_the_legal_ground():
    statement = minimal_statement()
    del statement["illegal_content_legal_ground"]
    errors = schema.validate_statement(statement)
    assert any("illegal_content_legal_ground" in error for error in errors)


def test_end_date_before_application_date_is_rejected():
    statement = minimal_statement()
    statement["end_date_account_restriction"] = "2020-01-01"
    errors = schema.validate_statement(statement)
    assert any("after or equal to the application date" in error for error in errors)


def test_bad_puid_charset_is_rejected():
    statement = minimal_statement()
    statement["puid"] = "aics leaf 2!"
    assert any("puid" in error for error in schema.validate_statement(statement))


def test_decision_facts_500_chars_pass_but_5001_fail():
    statement = minimal_statement()
    statement["decision_facts"] = "x" * 500
    assert schema.validate_statement(statement) == []
    statement["decision_facts"] = "x" * 5001
    assert any("decision_facts" in error for error in schema.validate_statement(statement))
