"""Friction measured in a real browser (Week 5 metric collection, FR-C1, Section 7.1).

The browser (Chromium, driven by Playwright) logs in through the client pages written by
Module B. The client writes friction events; Module C's harness turns them into a step
count, a keystroke count, errors and elapsed time.

Expected step counts come from the definition of a step in the requirements (Section 7.1),
worked out by hand for each login, not from the code under test:
    password        username field, password field, click "Log in"                     = 3
    password+totp   the three above, open the authenticator app and read the code,
                    code field, click "Verify"                                         = 6
    passkey         click "Log in with passkey", answer the authenticator prompt       = 2
Steps outside the browser (reading the code, answering the prompt) cannot be seen by the
client, so the harness adds them (`extra_steps`).
"""
import pytest

from .driver import login_with_password, login_with_passkey, login_with_password_and_totp, passkey_login

EXPECTED_STEPS = {"password": 3, "password+totp": 6, "passkey": 2}


def test_password_login_takes_three_steps(env):
    run = login_with_password(env)
    assert run.method == "password"
    assert run.steps == EXPECTED_STEPS["password"]
    assert run.errors == 0 and run.complete
    assert run.keystrokes == len(env.username) + len(env.password)
    assert run.elapsed_ms is not None and run.elapsed_ms > 0


def test_password_and_totp_login_takes_six_steps(make_env):
    env = make_env(with_totp=True)
    run = login_with_password_and_totp(env)
    assert run.method == "password+totp"
    assert run.steps == EXPECTED_STEPS["password+totp"]
    assert run.errors == 0 and run.complete
    assert run.keystrokes == len(env.username) + len(env.password) + 6


def test_passkey_login_works_in_a_real_browser(env):
    """Control for the passkey friction test: with Chrome's virtual authenticator the login
    really succeeds and gives a session, so a friction number is not taken from a failed run."""
    passkey_login(env)
    me = env.page.request.get(f"{env.service.base_url}/session/me")
    assert me.status == 200 and me.json()["username"] == env.username
    assert me.json()["methods"] == ["passkey"]


@pytest.mark.xfail(reason="finding: the login page logs flow_start when it loads and again when the passkey "
                          "button is pressed, so a passkey login has two flow_start events under one run_id "
                          "(and its timer restarts at the click). Module B, Issue #32.")
def test_passkey_login_takes_two_steps(env):
    run = login_with_passkey(env)
    assert run.method == "passkey"
    assert run.steps == EXPECTED_STEPS["passkey"]
    assert run.errors == 0 and run.complete
