"""Checks on data/corpus/requirements-v6.1.json, the parsed Requirements Companion Document."""
import json
from pathlib import Path

import pytest

CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "corpus" / "requirements-v6.1.json"
RESPONSIBILITY_FIELDS = ("responsibility_iaas", "responsibility_paas", "responsibility_saas")
VALID_RESPONSIBILITIES = {"CJIS/CSO", "Agency", "Service Provider", "Both", "TBD", None}

# Rows whose responsibility cells are filled black in the PDF (they hold hidden
# text but display no value): (section, start of shall_text).
BLACK_FILLED_ROWS = [
    ("AT-3", "4. Organizational Personnel with Security Responsibilities"),
    ("IA-5", "j. All credential service providers (CSPs)"),
    ("IA-5", "k. Privacy requirements that apply to all CSPs"),
    ("IA-5", "l. General requirements applicable to AAL2"),
    ("IA-5", "m. Biometric Requirements"),
    ("IA-5", "n. Authenticator binding refers to"),
    ("IA-5", "o. Session Management:"),
    ("IA-5", "(2) Reauthentication Requirements"),
    ("IA-12 (3)", "Requirements v and w apply to the collection of biometric"),
    ("IA-12 (3)", "In addition to those requirements presented in the General section"),
]


@pytest.fixture(scope="module")
def rows():
    with CORPUS_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def find_row(rows, section, shall_prefix):
    matches = [r for r in rows if r["section_v6_0"] == section and r["shall_text"].startswith(shall_prefix)]
    assert len(matches) == 1, f"expected exactly one row for {section} {shall_prefix!r}, found {len(matches)}"
    return matches[0]


def test_row_count(rows):
    assert len(rows) == 1528


def test_every_responsibility_value_is_a_known_enum_or_null(rows):
    for index, row in enumerate(rows):
        for field in RESPONSIBILITY_FIELDS:
            assert field in row, f"row {index} is missing {field}"
            assert row[field] in VALID_RESPONSIBILITIES, f"row {index} {field}={row[field]!r}"


def test_au3_1_wrapped_service_provider_cells(rows):
    wrapped = find_row(rows, "AU-3 (1)", "e. The III portion of the log shall clearly identify:")
    operator = find_row(rows, "AU-3 (1)", "1. The operator")
    assert wrapped["responsibility_saas"] == "Service Provider"
    assert operator["responsibility_saas"] == "Agency"


def test_si2_row_is_restored_with_warning_and_no_inferred_fields(rows):
    row = find_row(rows, "AT-3", "e. SI-2 Flaw Remediation")
    assert "missing_source_text" in row["extraction_warning"].split("+")
    assert row["audit_sanction_status"] is None
    assert row["audit_sanction_date"] is None
    assert row["priority"] is None
    assert [row[f] for f in RESPONSIBILITY_FIELDS] == ["Both", "Both", "Both"]


def test_textless_coloured_row_takes_value_from_colour(rows):
    row = find_row(rows, "AT-3", "· Organizational Personnel with Security Responsibilities:")
    assert "missing_source_text" in row["extraction_warning"].split("+")
    assert [row[f] for f in RESPONSIBILITY_FIELDS] == ["Both", "Both", "Both"]
    assert row["audit_sanction_status"] is None
    assert row["priority"] is None


@pytest.mark.parametrize("section,shall_prefix", BLACK_FILLED_ROWS)
def test_black_filled_rows_are_null(rows, section, shall_prefix):
    row = find_row(rows, section, shall_prefix)
    assert [row[f] for f in RESPONSIBILITY_FIELDS] == [None, None, None]


def test_responsibility_fields_are_all_null_or_all_set(rows):
    for index, row in enumerate(rows):
        nulls = [row[f] is None for f in RESPONSIBILITY_FIELDS]
        assert all(nulls) or not any(nulls), f"row {index} has a partly null responsibility set"


def test_only_missing_source_text_rows_are_the_two_known(rows):
    flagged = [r["shall_text"][:40] for r in rows if "missing_source_text" in (r.get("extraction_warning") or "").split("+")]
    assert len(flagged) == 2
