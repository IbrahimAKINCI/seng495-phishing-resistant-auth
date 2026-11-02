"""T-A1, T-A2, T-A7: registration, password storage and rate limits."""
from sqlalchemy import select

from app.auth import config
from app.auth.clock import clock
from app.auth.db import SessionLocal
from app.auth.models import User

from .conftest import PASSWORD, register


def login(client, username, password):
    return client.post("/auth/login/password", json={"username": username, "password": password})


# ---------- T-A1 ----------

def test_register_creates_account(client):
    user_id = register(client, "alice")
    assert user_id > 0
    assert login(client, "alice", PASSWORD).json()["status"] == "authenticated"


def test_duplicate_username_gets_same_message_as_other_errors(client):
    register(client, "alice")
    duplicate = client.post("/auth/register", json={"username": "alice", "password": PASSWORD})
    weak = client.post("/auth/register", json={"username": "bob", "password": "short"})
    bad_name = client.post("/auth/register", json={"username": "x", "password": PASSWORD})
    assert duplicate.status_code == weak.status_code == bad_name.status_code == 400
    assert duplicate.json() == weak.json() == bad_name.json()


def test_username_is_case_insensitive(client):
    register(client, "Alice")
    assert client.post("/auth/register", json={"username": "ALICE", "password": PASSWORD}).status_code == 400
    assert login(client, "aLiCe", PASSWORD).status_code == 200


# ---------- T-A2 ----------

def test_hash_uses_argon2id_with_required_settings(client):
    register(client, "alice")
    with SessionLocal() as db:
        stored = db.scalar(select(User.password_hash).where(User.username == "alice"))
    assert stored.startswith("$argon2id$")
    assert f"m={config.ARGON2_MEMORY_KIB},t={config.ARGON2_TIME_COST},p={config.ARGON2_PARALLELISM}" in stored
    assert PASSWORD not in stored


def test_same_password_gives_different_hashes(client):
    register(client, "alice")
    register(client, "bob")
    with SessionLocal() as db:
        hashes = db.scalars(select(User.password_hash)).all()
    assert hashes[0] != hashes[1]


def test_wrong_password_and_unknown_user_look_the_same(client):
    register(client, "alice")
    wrong = login(client, "alice", "wrong password here")
    unknown = login(client, "nobody", "wrong password here")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_login_result_has_server_time(client):
    register(client, "alice")
    body = login(client, "alice", PASSWORD).json()
    assert body["methods"] == ["password"]
    assert body["server_ms"] > 0


# ---------- T-A7 ----------

def test_sixth_failure_on_one_account_returns_429(client):
    register(client, "alice")
    for _ in range(config.RATE_MAX_FAILURES_ACCOUNT):
        assert login(client, "alice", "wrong password here").status_code == 401
    r = login(client, "alice", PASSWORD)  # even the right password is blocked now
    assert r.status_code == 429


def test_account_block_ends_after_15_minutes(client):
    register(client, "alice")
    for _ in range(config.RATE_MAX_FAILURES_ACCOUNT):
        login(client, "alice", "wrong password here")
    assert login(client, "alice", PASSWORD).status_code == 429
    clock.advance(config.RATE_BLOCK_SECONDS + 1)
    assert login(client, "alice", PASSWORD).status_code == 200


def test_429_message_is_the_same_for_unknown_accounts(client):
    register(client, "alice")
    for name in ("alice", "nobody"):
        for _ in range(config.RATE_MAX_FAILURES_ACCOUNT):
            login(client, name, "wrong password here")
    a, b = login(client, "alice", "x" * 12), login(client, "nobody", "x" * 12)
    assert a.status_code == b.status_code == 429
    assert a.json() == b.json()


def test_twenty_first_failure_from_one_address_returns_429(client):
    # 4 failures each on 5 accounts: no account reaches its limit, but the address does
    for i in range(config.RATE_MAX_FAILURES_IP):
        assert login(client, f"user{i // 4}", "wrong password here").status_code == 401
    assert login(client, "someone-new", "wrong password here").status_code == 429
    clock.advance(config.RATE_BLOCK_SECONDS + 1)
    assert login(client, "someone-new", "wrong password here").status_code == 401


def test_failures_spread_over_more_than_15_minutes_do_not_block(client):
    register(client, "alice")
    for _ in range(config.RATE_MAX_FAILURES_ACCOUNT):
        login(client, "alice", "wrong password here")
        clock.advance(4 * 60)  # 5 failures over 20 minutes
    assert login(client, "alice", PASSWORD).status_code == 200
