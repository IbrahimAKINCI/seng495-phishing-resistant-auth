"""Contract test for the two log formats (Section 8) and the per-run measurements.

The sample lines are the exact shape the service writes (taken from the format in
Section 8), so a change to the format on either side breaks this test."""
import json

import pytest

from harness import logs

FRICTION = [
    {"run_id": "r1", "flow": "login", "method": "password", "event": "flow_start", "t_ms": 0, "detail": ""},
    {"run_id": "r1", "flow": "login", "method": "password", "event": "step", "t_ms": 900, "detail": "field:username"},
    {"run_id": "r1", "flow": "login", "method": "password", "event": "keystroke", "t_ms": 910, "detail": "username"},
    {"run_id": "r1", "flow": "login", "method": "password", "event": "keystroke", "t_ms": 950, "detail": "username"},
    {"run_id": "r1", "flow": "login", "method": "password", "event": "step", "t_ms": 1700, "detail": "field:password"},
    {"run_id": "r1", "flow": "login", "method": "password", "event": "step", "t_ms": 2300, "detail": "click:submit"},
    {"run_id": "r1", "flow": "login", "method": "password", "event": "flow_end", "t_ms": 2400, "detail": ""},
    # a second run that failed
    {"run_id": "r2", "flow": "login", "method": "passkey", "event": "flow_start", "t_ms": 0, "detail": ""},
    {"run_id": "r2", "flow": "login", "method": "passkey", "event": "error", "t_ms": 500, "detail": "cancelled"},
    {"run_id": "r2", "flow": "login", "method": "passkey", "event": "flow_end", "t_ms": 600, "detail": ""},
]
TIMING = [
    {"request_id": "a1", "endpoint": "/session/login/password", "method": "password", "status": 200, "server_ms": 61.2},
    {"request_id": "a2", "endpoint": "/session/login/password", "method": "password", "status": 200, "server_ms": 59.8},
    {"request_id": "a3", "endpoint": "/session/login/password", "method": "password", "status": 401, "server_ms": 3.0},
    {"request_id": "a4", "endpoint": "/auth/webauthn/login/verify", "method": "passkey", "status": 200, "server_ms": 4.5},
]


def test_run_summary_uses_the_step_rule_and_counts():
    runs = {r.run_id: r for r in logs.friction_runs(FRICTION)}
    r1 = runs["r1"]
    # the three steps of password login in Section 7.1: username, password, submit
    assert (r1.steps, r1.keystrokes, r1.errors) == (3, 2, 0)
    assert r1.elapsed_ms == 2400
    assert r1.complete


def test_a_run_with_an_error_is_counted_but_not_complete():
    r2 = {r.run_id: r for r in logs.friction_runs(FRICTION)}["r2"]
    assert r2.errors == 1 and r2.elapsed_ms == 600
    assert not r2.complete


def test_a_run_without_flow_end_has_no_elapsed_time():
    rows = [e for e in FRICTION if not (e["run_id"] == "r1" and e["event"] == "flow_end")]
    r1 = {r.run_id: r for r in logs.friction_runs(rows)}["r1"]
    assert r1.elapsed_ms is None and not r1.complete


def test_steps_outside_the_browser_are_added_by_the_harness():
    rows = [e for e in FRICTION if e["run_id"] == "r2" and e["event"] != "error"]
    r2 = logs.friction_runs(rows, extra_steps={"r2": 1})[0]   # the authenticator prompt
    assert r2.steps == 1


def test_server_times_filter_by_endpoint_method_and_status():
    assert logs.server_times(TIMING, method="password") == [61.2, 59.8]      # the 401 is left out
    assert logs.server_times(TIMING, method="password", ok_only=False) == [61.2, 59.8, 3.0]
    assert logs.server_times(TIMING, endpoint="/auth/webauthn/login/verify") == [4.5]


@pytest.mark.parametrize("missing", ["run_id", "flow", "method", "event", "t_ms"])
def test_friction_row_missing_a_field_is_rejected(missing):
    row = {k: v for k, v in FRICTION[0].items() if k != missing}
    with pytest.raises(logs.LogFormatError):
        logs.check_friction_row(row)


def test_friction_row_with_unknown_event_or_wrong_type_is_rejected():
    with pytest.raises(logs.LogFormatError):
        logs.check_friction_row({**FRICTION[0], "event": "jump"})
    with pytest.raises(logs.LogFormatError):
        logs.check_friction_row({**FRICTION[0], "t_ms": "0"})
    with pytest.raises(logs.LogFormatError):
        logs.check_friction_row({**FRICTION[0], "t_ms": True})


@pytest.mark.parametrize("missing", ["request_id", "endpoint", "method", "server_ms"])
def test_timing_row_missing_a_field_is_rejected(missing):
    row = {k: v for k, v in TIMING[0].items() if k != missing}
    with pytest.raises(logs.LogFormatError):
        logs.check_timing_row(row)


def test_read_jsonl_reads_lines_and_reports_bad_ones(tmp_path):
    good = tmp_path / "good.jsonl"
    good.write_text("\n".join(json.dumps(r) for r in TIMING) + "\n", encoding="utf-8")
    assert logs.read_jsonl(good) == TIMING
    assert logs.read_jsonl(tmp_path / "missing.jsonl") == []
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"a": 1}\nnot json\n', encoding="utf-8")
    with pytest.raises(logs.LogFormatError):
        logs.read_jsonl(bad)
