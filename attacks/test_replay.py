"""A2: replay of a captured credential (docs/threat_model.md, FR-C7 / Week 6).

Attacker model: the attacker has captured what the victim sent to the login, for
example on a look-alike page, and sends it again to the real service.

Expected results, written down before the tests were run (threat model, row A2):
    password        succeeded  (a password can be reused)
    password+totp   blocked    (a one-time code is accepted once)
    passkey         blocked    (not tested here: it needs a software authenticator,
                                which is planned with the origin mismatch test)

Each test has a control: the first use of the credential must be accepted, otherwise
a "blocked" result would only show that the test set-up is broken."""
import time

import httpx

from .conftest import PASSWORD, enrol_totp, new_username, register, session_login


def new_machine(service) -> httpx.Client:
    """A second client with its own cookie jar: the attacker's machine."""
    return httpx.Client(base_url=service.base_url, timeout=30)


def test_password_replay_succeeds(service, http, report):
    username = new_username()
    register(http, username)

    # control: the victim's own login is accepted
    assert session_login(http, username).status_code == 200

    # attack: the captured username and password are sent again from another machine
    with new_machine(service) as attacker:
        r = session_login(attacker, username)
    actual = "succeeded" if r.status_code == 200 else "blocked"

    assert report("replay", "password", "succeeded", actual, f"second login status {r.status_code}")
    assert actual == "succeeded"


def test_totp_code_replay_is_blocked(service, http, report):
    username = new_username()
    register(http, username)
    assert session_login(http, username).status_code == 200
    app = enrol_totp(http)          # the confirmation code used up the current time step

    # The victim logs in. The code for the next 30 seconds is already valid because the
    # service accepts one window ahead, so the test does not have to wait.
    captured_code = app.at(time.time() + 30)

    with new_machine(service) as victim_browser:
        step1 = victim_browser.post("/session/login/password", json={"username": username, "password": PASSWORD})
        assert step1.json()["status"] == "totp_required"
        first = victim_browser.post("/session/login/totp",
                                    json={"pending_id": step1.json()["pending_id"], "code": captured_code})
        # control: the first use of the code is accepted
        assert first.status_code == 200, first.text

    # attack: the attacker knows the password (phishing) and replays the captured code
    # in a brand new login, so the pending login is a fresh one
    with new_machine(service) as attacker:
        pending = attacker.post("/session/login/password", json={"username": username, "password": PASSWORD})
        assert pending.json()["status"] == "totp_required"
        replay = attacker.post("/session/login/totp",
                               json={"pending_id": pending.json()["pending_id"], "code": captured_code})
        # the same code on the pending login of the first attempt, which is already used
        reuse = attacker.post("/session/login/totp",
                              json={"pending_id": step1.json()["pending_id"], "code": captured_code})

    got_session = replay.status_code == 200 or reuse.status_code == 200
    actual = "succeeded" if got_session else "blocked"
    detail = f"replay status {replay.status_code}, reuse of used pending login status {reuse.status_code}"

    assert report("replay", "password+totp", "blocked", actual, detail)
    assert actual == "blocked"
    assert replay.status_code == 401 and reuse.status_code == 401
