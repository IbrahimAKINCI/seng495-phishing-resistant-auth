"""A7: repeated login attempts against the FR-A7 limits (threat model A7, FR-C3).

Two scenarios, both just repeated calls to the login endpoint from one address, recorded
as two separate attacks so neither result overwrites the other in the results table:
  - "brute_force": many attempts on one account
  - "credential_stuffing": many attempts across many invented accounts, a list of
    username/attempt pairs most of which match no account (standing in for the 1,000
    generated leaked pairs of FR-C3)

Limits under test (FR-A7): 5 failed logins on one account within 15 minutes block that
account for 15 minutes, and 20 failed logins from one address block that address for
15 minutes. A blocked request gets HTTP 429.

Expected results, written down before the tests were run (threat model, row A7):
    password        blocked   (limited only by FR-A7)
    password+totp   blocked   (a right password gives no session without the code)
    passkey         not_applicable (no password to guess)

Each test starts its own service, because it makes many failed logins from 127.0.0.1
and would otherwise block every later test in the module.
"""
import httpx

from .conftest import PASSWORD, enrol_totp, new_username, register, session_login
from .server import running_service

PASSKEY_ONLY_POLICY = "passkey_only"

ACCOUNT_LIMIT = 5   # FR-A7: failures on one account in 15 minutes
ADDRESS_LIMIT = 20  # FR-A7: failures from one address in 15 minutes


def client(svc) -> httpx.Client:
    return httpx.Client(base_url=svc.base_url, timeout=30)


def attempt(machine: httpx.Client, username: str, candidate: str) -> httpx.Response:
    return machine.post("/session/login/password", json={"username": username, "password": candidate})


def test_many_attempts_on_one_account_are_stopped_by_the_account_limit(report):
    """Many wrong attempts on one account. The account limit (5) is reached before
    the address limit (20), so this shows the account limit specifically."""
    with running_service() as svc, client(svc) as caller:
        victim = new_username()
        register(caller, victim)

        statuses = [attempt(caller, victim, f"guess-{i}").status_code for i in range(ACCOUNT_LIMIT + 3)]
        blocked_from = statuses.index(429) if 429 in statuses else None

        # control: a different account is not affected
        other = new_username()
        register(caller, other)
        other_status = attempt(caller, other, "also wrong").status_code

    actual = "blocked" if blocked_from == ACCOUNT_LIMIT else "succeeded"
    detail = f"blocked after {blocked_from} attempts (limit {ACCOUNT_LIMIT}); other account answered {other_status}"
    assert report("brute_force", "password", "blocked", actual, detail)
    assert blocked_from == ACCOUNT_LIMIT
    assert other_status != 429


def test_many_accounts_from_one_address_are_stopped_by_the_address_limit(report):
    """One attempt each on many different accounts, most of which do not exist. This
    stays under the account limit (1 attempt per account) but reaches the address
    limit (20) first."""
    with running_service() as svc, client(svc) as caller:
        real_accounts = [new_username() for _ in range(3)]
        for name in real_accounts:
            register(caller, name)

        # one wrong attempt per candidate account; most candidates do not exist
        candidates = real_accounts + [f"unknown-{i}" for i in range(ADDRESS_LIMIT + 5 - len(real_accounts))]
        statuses = [attempt(caller, name, "candidate-password").status_code for name in candidates]
        blocked_from = statuses.index(429) if 429 in statuses else None

    actual = "blocked" if blocked_from == ADDRESS_LIMIT else "succeeded"
    detail = f"blocked after {blocked_from} attempts across accounts (limit {ADDRESS_LIMIT})"
    assert report("credential_stuffing", "password", "blocked", actual, detail)
    assert blocked_from == ADDRESS_LIMIT


def test_knowing_the_password_is_not_enough_without_the_code(report):
    """The caller knows the right password (for example from a leaked list that still
    matches) but not the TOTP code. The password step alone never gives a session, and
    guessing the code is stopped by the same account limit as a wrong password would be."""
    with running_service() as svc, client(svc) as caller:
        victim = new_username()
        register(caller, victim)
        session_login(caller, victim)
        enrol_totp(caller)

        # the right password alone only asks for the code, it never gives a session
        pending = attempt(caller, victim, PASSWORD)
        asked_for_code = pending.status_code == 200 and pending.json().get("status") == "totp_required"
        pending_id = pending.json().get("pending_id")

        statuses = [
            caller.post("/session/login/totp", json={"pending_id": pending_id, "code": f"{i:06d}"}).status_code
            for i in range(ACCOUNT_LIMIT + 3)
        ]
        blocked_from = statuses.index(429) if 429 in statuses else None
        got_session_without_code = any(s == 200 for s in statuses)

    actual = "blocked" if asked_for_code and not got_session_without_code and blocked_from == ACCOUNT_LIMIT else "succeeded"
    detail = f"password alone asked for code: {asked_for_code}; code guessing blocked after {blocked_from} attempts"
    assert report("brute_force", "password+totp", "blocked", actual, detail)
    assert actual == "blocked"


def test_passkey_has_no_password_to_guess(report):
    """Under passkey_only there is no password at all: the login route refuses before
    any password is looked at, with the same answer whatever is sent (issue #7). The
    attack this test module is about (repeated password guesses) does not apply."""
    with running_service(policy=PASSKEY_ONLY_POLICY) as svc, client(svc) as caller:
        victim = new_username()
        register(caller, victim)

        r = attempt(caller, victim, PASSWORD)
        refused_before_checking = r.status_code == 403

    actual = "not_applicable" if refused_before_checking else "succeeded"
    for attack in ("brute_force", "credential_stuffing"):
        assert report(attack, "passkey", "not_applicable", actual,
                      f"password login refused with status {r.status_code} under {PASSKEY_ONLY_POLICY}")
    assert actual == "not_applicable"
