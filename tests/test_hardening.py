"""Issue #7: Module A hardening.

1. No password oracle under the policy: a right and a wrong password get the same answer.
2. A challenge (and a TOTP code) can be used only once, even by two requests at the same time.
3. Rate limits on /auth/register and /auth/webauthn/login/options.
4. The client-address limit is documented in app/auth/router.py (_ip)."""
from app.auth import config, service
from app.auth.clock import clock
from app.auth.db import SessionLocal
from app.auth.errors import AuthError
from app.auth.models import Challenge

from .conftest import PASSWORD, add_passkey, as_user, enrol_totp, register, use_policy


def password_login(client, username, password):
    return client.post("/auth/login/password", json={"username": username, "password": password})


# ---------- 1. password oracle ----------

def test_passkey_only_gives_the_same_answer_for_right_and_wrong_password(client, authenticator):
    uid = register(client, "alice")
    add_passkey(client, authenticator, uid)
    use_policy("passkey_only")
    right = password_login(client, "alice", PASSWORD)
    wrong = password_login(client, "alice", "not the password!!")
    unknown = password_login(client, "nobody", "not the password!!")
    assert right.status_code == wrong.status_code == unknown.status_code == 403
    assert right.json() == wrong.json() == unknown.json()


def test_passkey_only_does_not_check_the_password_at_all(client, monkeypatch):
    from app.auth import passwords

    register(client, "alice")
    use_policy("passkey_only")
    called = []
    monkeypatch.setattr(passwords, "verify_password", lambda *a: called.append(a) or True)
    password_login(client, "alice", PASSWORD)
    assert called == []  # refused before the password is looked at, so timing is equal too


def test_fallback_policy_gives_the_same_answer_for_right_and_wrong_password(client):
    register(client, "bob")  # password only, no TOTP
    use_policy("passkey_with_fallback")
    right = password_login(client, "bob", PASSWORD)
    wrong = password_login(client, "bob", "not the password!!")
    assert right.status_code == wrong.status_code == 401
    assert right.json() == wrong.json()


def test_fallback_policy_counts_a_right_password_as_a_failure(client):
    # Otherwise an attacker could see the right password by when the block starts
    register(client, "bob")
    use_policy("passkey_with_fallback")
    password_login(client, "bob", PASSWORD)
    for _ in range(config.RATE_MAX_FAILURES_ACCOUNT - 1):
        password_login(client, "bob", "not the password!!")
    assert password_login(client, "bob", "not the password!!").status_code == 429


def test_fallback_policy_still_lets_totp_users_in(client):
    uid = register(client, "alice")
    totp = enrol_totp(client, uid)
    use_policy("passkey_with_fallback")
    r = password_login(client, "alice", PASSWORD)
    assert r.json()["status"] == "totp_required"
    r = client.post("/auth/login/totp", json={"pending_id": r.json()["pending_id"], "code": totp.at(clock.now())})
    assert r.status_code == 200


# ---------- 2. races ----------

def test_challenge_cannot_be_used_twice_by_two_requests_at_the_same_time(client):
    opts = client.post("/auth/webauthn/login/options", json={}).json()
    first, second = SessionLocal(), SessionLocal()
    try:
        # the second request has already read the challenge (used = False) ...
        stale = second.get(Challenge, opts["challenge_id"])
        assert stale.used is False
        # ... when the first one uses it
        from app.auth import webauthn_service as ws
        assert ws.consume_challenge(first, opts["challenge_id"], "authentication") is not None
        # the second must now lose, although its own copy still says used = False
        assert ws.consume_challenge(second, opts["challenge_id"], "authentication") is None
    finally:
        first.close()
        second.close()


def test_totp_code_cannot_be_used_twice_by_two_requests_at_the_same_time(client):
    from app.auth.models import User

    uid = register(client, "alice")
    totp = enrol_totp(client, uid)
    pending = password_login(client, "alice", PASSWORD).json()["pending_id"]
    code = totp.at(clock.now())
    first, second = SessionLocal(), SessionLocal()
    try:
        # The second request has already loaded the pending login and the TOTP row.
        # Keep references: the session only holds loaded objects while they are in use.
        stale = (second.get(Challenge, pending), second.get(User, uid), second.get(User, uid).totp)
        assert stale[0].used is False
        assert service.login_totp(first, pending, code, "1.1.1.1").user_id == uid
        try:
            service.login_totp(second, pending, code, "2.2.2.2")
            raised = False
        except AuthError as exc:
            raised = exc.status == 401
        assert raised
    finally:
        first.close()
        second.close()


# ---------- 3. rate limits ----------

def test_registration_is_limited_per_address(client):
    for i in range(config.REGISTER_MAX_PER_IP):
        assert client.post("/auth/register", json={"username": f"user{i}", "password": "x"}).status_code == 400
    r = client.post("/auth/register", json={"username": "one-more", "password": PASSWORD})
    assert r.status_code == 429
    clock.advance(config.RATE_WINDOW_SECONDS + 1)
    assert client.post("/auth/register", json={"username": "one-more", "password": PASSWORD}).status_code == 201


def test_passkey_options_are_limited_per_address(client):
    for _ in range(config.PASSKEY_OPTIONS_MAX_PER_IP):
        assert client.post("/auth/webauthn/login/options", json={}).status_code == 200
    assert client.post("/auth/webauthn/login/options", json={}).status_code == 429
    clock.advance(config.RATE_WINDOW_SECONDS + 1)
    assert client.post("/auth/webauthn/login/options", json={}).status_code == 200


def test_request_limits_do_not_count_towards_login_blocks(client):
    register(client, "alice")
    for _ in range(config.PASSKEY_OPTIONS_MAX_PER_IP):
        client.post("/auth/webauthn/login/options", json={})
    assert password_login(client, "alice", PASSWORD).status_code == 200
