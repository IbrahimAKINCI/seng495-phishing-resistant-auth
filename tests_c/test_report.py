"""Tests for the results table generator, with rows whose table is known in advance."""
import pytest

from harness import report

MACHINE = {"os": "TestOS", "processor": "x", "cpu_count": 8, "python": "3.12.0"}


def row(attack, method, expected, actual, time, detail="", commit="abcdef1234567"):
    return {"time": time, "attack": attack, "method": method, "expected": expected, "actual": actual,
            "confirmed": expected == actual, "detail": detail, "commit": commit, "parameters": {},
            "machine": MACHINE}


def test_table_has_one_line_per_attack_and_method():
    rows = [
        row("replay", "password", "succeeded", "succeeded", "2026-11-04T10:00:00+00:00"),
        row("replay", "password+totp", "blocked", "blocked", "2026-11-04T10:00:01+00:00", "401"),
    ]
    text = report.build_table(rows)
    assert "| replay | password | succeeded | succeeded | yes |  |" in text
    assert "| replay | password+totp | blocked | blocked | yes | 401 |" in text
    assert "Commit: abcdef1" in text
    assert "TestOS, 8 CPUs, Python 3.12.0" in text


def test_only_the_latest_result_of_a_pair_is_used():
    rows = [
        row("replay", "password", "blocked", "succeeded", "2026-11-04T10:00:00+00:00"),
        row("replay", "password", "blocked", "blocked", "2026-11-04T11:00:00+00:00"),
    ]
    text = report.build_table(rows)
    assert text.count("| replay | password |") == 1
    assert "| replay | password | blocked | blocked | yes |" in text


def test_a_refuted_expectation_is_shown_as_a_finding():
    text = report.build_table([row("x", "password", "blocked", "succeeded", "2026-11-04T10:00:00+00:00")])
    assert "**NO (finding)**" in text


def test_pipe_in_detail_does_not_break_the_table():
    text = report.build_table([row("x", "password", "blocked", "blocked", "2026-11-04T10:00:00+00:00", "a|b")])
    assert "a/b" in text and "a|b" not in text


def test_no_results_is_an_error():
    with pytest.raises(ValueError):
        report.build_table([])


def test_main_writes_the_file(tmp_path):
    import json
    source = tmp_path / "in.jsonl"
    source.write_text(json.dumps(row("replay", "password", "succeeded", "succeeded",
                                     "2026-11-04T10:00:00+00:00")) + "\n", encoding="utf-8")
    target = tmp_path / "out" / "table.md"
    assert report.main(["report", str(source), str(target)]) == 0
    assert "| replay | password |" in target.read_text(encoding="utf-8")
    assert report.main(["report", str(tmp_path / "none.jsonl"), str(target)]) == 1
