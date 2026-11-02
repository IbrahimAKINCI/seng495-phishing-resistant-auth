"""T-A3, T-A4 and NFR-2: TOTP enrolment, login and storage."""
import pyotp
from sqlalchemy import select

from app.auth import config
from app.auth.clock import clock
from app.auth.db import SessionLocal
from app.auth.models import TotpSecret

from .conftest import PASSWORD, as_user, enrol_totp, register


def start_login(client, username="alice"):
    r = client.post("/auth/login/password", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "totp_required"
    return r.json()["pending_id"]


def send_code(client, pending_id, code):
    return client.post("/auth/login/totp", json={"pending_id": pending_id, "code": code})


# ---------- T-A3 ----------

def test_wrong_confirmation_code_leaves_totp_inactive(client):
    uid = register(client)
    r = client.post("/auth/totp/enroll/start", headers=as_user(uid))
    assert r.json()["qr_png_base64"]
    secret = pyotp.parse_uri(r.json()["otpauth_uri"]).secret
    assert len(secret) == 32  # 160 bits in base32
    wrong = client.post("/auth/totp/enroll/confirm", json={"code": "000000"}, headers=as_user(uid))
    assert wrong.status_code == 400
    assert client.get("/auth/credentials", headers=as_user(uid)).json()["totp"] is False
    # password login still works without a code
    assert client.post("/auth/login/password", json={"username": "alice", "password": PASSWORD}).json()["status"] == "authenticated"


def test_correct_confirmation_code_activates_totp(client):
    uid = register(client)
    enrol_totp(client, uid)
    assert client.get("/auth/credentials", headers=as_user(uid)).json()["totp"] is True


def test_secret_is_encrypted_in_the_database(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    with SessionLocal() as db:
        blob = db.scalar(select(TotpSecret.secret_encrypted))
    assert totp.secret.encode() not in blob


# ---------- T-A4 ----------

def test_password_then_valid_code_logs_in(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    r = send_code(client, start_login(client), totp.at(clock.now()))
    assert r.status_code == 200
    assert r.json()["methods"] == ["password", "totp"]


def test_same_code_cannot_be_used_twice(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    code = totp.at(clock.now())
    assert send_code(client, start_login(client), code).status_code == 200
    assert send_code(client, start_login(client), code).status_code == 401


def test_code_from_two_windows_ago_is_rejected(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    old = totp.at(clock.now() - 2 * config.TOTP_PERIOD)
    assert send_code(client, start_login(client), old).status_code == 401


def test_code_from_previous_window_is_accepted(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    clock.advance(30)
    previous = totp.at(clock.now() - config.TOTP_PERIOD)
    assert send_code(client, start_login(client), previous).status_code == 200


def test_confirmation_code_cannot_be_used_to_log_in(client):
    uid = register(client)
    r = client.post("/auth/totp/enroll/start", headers=as_user(uid))
    totp = pyotp.TOTP(pyotp.parse_uri(r.json()["otpauth_uri"]).secret)
    code = totp.at(clock.now())
    client.post("/auth/totp/enroll/confirm", json={"code": code}, headers=as_user(uid))
    assert send_code(client, start_login(client), code).status_code == 401


def test_pending_login_expires(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    pending = start_login(client)
    clock.advance(config.PENDING_LOGIN_TTL_SECONDS + 1)
    assert send_code(client, pending, totp.at(clock.now())).status_code == 401


def test_wrong_codes_count_towards_the_rate_limit(client):
    uid = register(client)
    totp = enrol_totp(client, uid)
    pending = start_login(client)
    for _ in range(config.RATE_MAX_FAILURES_ACCOUNT):
        assert send_code(client, pending, "000000").status_code == 401
    assert send_code(client, pending, totp.at(clock.now())).status_code == 429
