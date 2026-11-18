"""What a user does in the browser, and how the friction of it is read back.

Every measured run opens a page with its own ?run=<id>, so its events can be told apart
(Issue #20: one run_id holds exactly one flow)."""
import json
import time
import uuid

from harness import logs

FRICTION_FILE = "friction.jsonl"


def new_run_id() -> str:
    return "e2e-" + uuid.uuid4().hex[:12]


def read_run(env, run_id: str, timeout: float = 10.0) -> list[dict]:
    """The client sends its events with sendBeacon, a moment after the flow ends, so wait
    until the run has its flow_end."""
    path = env.service.results_dir / FRICTION_FILE
    deadline = time.time() + timeout
    while True:
        rows = []
        if path.exists():
            rows = [r for r in map(json.loads, path.read_text(encoding="utf-8").splitlines()) if r["run_id"] == run_id]
        if any(r["event"] == "flow_end" for r in rows) or time.time() > deadline:
            return rows
        time.sleep(0.1)


def summarize(env, run_id: str, extra_steps: int = 0) -> logs.RunSummary:
    rows = read_run(env, run_id)
    assert rows, f"no friction events for run {run_id}"
    (run,) = logs.friction_runs(rows, extra_steps={run_id: extra_steps})
    return run


def fill(page, selector: str, text: str) -> None:
    """Types like a person: one key press per character, then leaves the field."""
    page.locator(selector).press_sequentially(text)
    page.locator(selector).blur()


def login_with_password(env):
    run_id = new_run_id()
    page = env.page
    page.goto(f"{env.service.base_url}/?run={run_id}")
    fill(page, "#username", env.username)
    fill(page, "#password", env.password)
    page.click("#login-btn")
    page.wait_for_url("**/home.html")
    return summarize(env, run_id)


def login_with_password_and_totp(env):
    run_id = new_run_id()
    page = env.page
    page.goto(f"{env.service.base_url}/?run={run_id}")
    fill(page, "#username", env.username)
    fill(page, "#password", env.password)
    page.click("#login-btn")
    page.wait_for_selector("#totp-form:not(.hidden)")
    # The person opens the authenticator app and reads the code: a step outside the browser.
    # The code made when the app was enrolled is already used; the service also accepts the
    # next 30-second window, so the test does not have to wait.
    code = env.totp.at(time.time() + 30)
    fill(page, "#totp-code", code)
    page.click("#totp-btn")
    page.wait_for_url("**/home.html")
    return summarize(env, run_id, extra_steps=1)


def add_virtual_authenticator(env) -> None:
    """Chrome's virtual authenticator (DevTools): a software passkey device that answers
    every prompt at once, so no hardware key is needed."""
    env.cdp.send("WebAuthn.enable")
    env.cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})


def enrol_passkey(env) -> None:
    """Set-up, not measured: log in with the password and add a passkey on the home page,
    then forget the session so the next page is a clean login page."""
    page = env.page
    page.goto(f"{env.service.base_url}/?run={new_run_id()}")
    fill(page, "#username", env.username)
    fill(page, "#password", env.password)
    page.click("#login-btn")
    page.wait_for_url("**/home.html")
    with page.expect_response("**/auth/webauthn/register/verify") as registered:
        page.click("#add-passkey-btn")
    assert registered.value.status == 201, "the passkey was not registered"
    page.context.clear_cookies()


def passkey_login(env) -> str:
    """Adds a virtual authenticator, registers a passkey (not measured), then logs in with it.
    Returns the run id of the measured login."""
    add_virtual_authenticator(env)
    enrol_passkey(env)
    run_id = new_run_id()
    page = env.page
    page.goto(f"{env.service.base_url}/?run={run_id}")
    page.click("#passkey-btn")
    page.wait_for_url("**/home.html")
    return run_id


def login_with_passkey(env):
    run_id = passkey_login(env)
    # answering the authenticator prompt (touch, fingerprint or PIN) is a step outside the browser
    return summarize(env, run_id, extra_steps=1)
