"""T-B5 (client pages are served) and T-B6 (friction log and server timing log)."""
import json

from app.friction import logs

from .conftest import login, register


def read(name):
    path = logs.RESULTS_DIR / name
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def clear():
    for name in (logs.FRICTION_FILE, logs.TIMING_FILE):
        (logs.RESULTS_DIR / name).unlink(missing_ok=True)


def test_client_pages_are_served(browser):
    for page, text in [("/", "Log in"), ("/register.html", "Create an account"), ("/home.html", "Passkeys"),
                       ("/recover.html", "Recover your account"), ("/app.js", "createPasskey"), ("/friction.js", "Friction")]:
        r = browser.get(page)
        assert r.status_code == 200 and text in r.text, page


def test_api_routes_are_not_hidden_by_the_client(browser):
    assert browser.get("/health").json() == {"status": "ok"}
    assert browser.get("/session/me").status_code == 401


def test_friction_events_are_written_in_the_section_8_format(browser):
    clear()
    events = [
        {"run_id": "r1", "flow": "login", "method": "password", "event": "flow_start", "t_ms": 0},
        {"run_id": "r1", "flow": "login", "method": "password", "event": "step", "t_ms": 900, "detail": "field:username"},
        {"run_id": "r1", "flow": "login", "method": "password", "event": "keystroke", "t_ms": 950},
        {"run_id": "r1", "flow": "login", "method": "password", "event": "flow_end", "t_ms": 2400},
    ]
    assert browser.post("/metrics/events", json={"events": events}).status_code == 204
    rows = read(logs.FRICTION_FILE)
    assert [r["event"] for r in rows] == ["flow_start", "step", "keystroke", "flow_end"]
    assert set(rows[0]) == {"run_id", "flow", "method", "event", "t_ms", "detail"}


def test_unknown_friction_event_is_rejected(browser):
    bad = {"run_id": "r", "flow": "login", "method": "password", "event": "jump", "t_ms": 1}
    assert browser.post("/metrics/events", json={"events": [bad]}).status_code == 422


def test_server_timing_log_has_one_line_per_auth_request(browser):
    clear()
    register(browser)
    login(browser)
    browser.get("/session/me")  # not an authentication request, so not logged
    rows = read(logs.TIMING_FILE)
    assert [r["endpoint"] for r in rows] == ["/auth/register", "/session/login/password"]
    assert rows[1]["method"] == "password" and rows[1]["status"] == 200 and rows[1]["server_ms"] > 0
    assert set(rows[0]) == {"request_id", "endpoint", "method", "status", "server_ms"}
