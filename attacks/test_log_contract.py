"""Contract test (Section 8): the lines the running service really writes must match the
format Module C reads. This complements tests_c/test_logs.py, which uses sample lines."""
from harness import logs

from .conftest import new_username, register, session_login


def test_service_writes_server_timing_lines_in_the_agreed_format(service, http):
    username = new_username()
    register(http, username)
    assert session_login(http, username).status_code == 200
    assert session_login(http, username, password="wrong password here").status_code == 401

    rows = logs.read_jsonl(service.results_dir / "server_timing.jsonl")
    mine = [r for r in rows if r["endpoint"] in ("/auth/register", "/session/login/password")]
    assert len(mine) >= 3
    for row in rows:
        logs.check_timing_row(row)

    # the successful login is measured; the failed one is left out by default
    ok = logs.server_times(rows, endpoint="/session/login/password")
    all_ = logs.server_times(rows, endpoint="/session/login/password", ok_only=False)
    assert len(all_) > len(ok)
    assert all(ms > 0 for ms in all_)


def test_service_writes_friction_lines_in_the_agreed_format(service, http):
    event = {"run_id": "contract-1", "flow": "login", "method": "password", "event": "flow_start", "t_ms": 0}
    assert http.post("/metrics/events", json={"events": [event]}).status_code == 204
    rows = logs.read_jsonl(service.results_dir / "friction.jsonl")
    assert any(r["run_id"] == "contract-1" for r in rows)
    for row in rows:
        logs.check_friction_row(row)
