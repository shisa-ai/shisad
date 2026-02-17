"""Unit checks for CSV export escaping helpers."""

from __future__ import annotations

import pytest

from shisad.daemon.handlers._csv import escape_csv_field, render_csv_row


def test_escape_csv_field_handles_plain_values() -> None:
    assert escape_csv_field("hello") == "hello"
    assert escape_csv_field(123) == "123"
    assert escape_csv_field(None) == ""


def test_escape_csv_field_quotes_comma_quote_and_newline_values() -> None:
    assert escape_csv_field("a,b") == '"a,b"'
    assert escape_csv_field('a"b') == '"a""b"'
    assert escape_csv_field("a\nb") == '"a\nb"'
    assert escape_csv_field("a\rb") == '"a\rb"'


@pytest.mark.parametrize("value", ["=1+1", "+1+1", "-1+1", "@SUM(A1:A2)"])
def test_escape_csv_field_defuses_formula_prefixes(value: str) -> None:
    escaped = escape_csv_field(value)
    assert escaped.startswith("'")


@pytest.mark.parametrize(
    "value",
    [
        " =1+1",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "\x01=1+1",
    ],
)
def test_escape_csv_field_defuses_formula_prefixes_after_leading_controls(value: str) -> None:
    escaped = escape_csv_field(value)
    assert escaped.startswith("'") or escaped.startswith("\"'")


def test_escape_csv_field_removes_nul_bytes_before_formula_check() -> None:
    assert escape_csv_field("\x00=1+1") == "'=1+1"
    assert escape_csv_field("a\x00b") == "ab"


def test_escape_csv_field_defuses_then_quotes_when_needed() -> None:
    assert escape_csv_field("=SUM(A1,A2)") == '"\'=SUM(A1,A2)"'


def test_render_csv_row_escapes_each_column() -> None:
    row = render_csv_row(["id-1", "a,b", '=cmd|"/C calc"'])
    assert row == 'id-1,"a,b","\'=cmd|""/C calc"""'
