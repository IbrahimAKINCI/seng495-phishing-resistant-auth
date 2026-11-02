"""T-B7 and T-B8: recovery codes and the hardened recovery flow."""
from app.auth import config as auth_config
from app.auth.clock import clock
from app.recovery.service import CODE_COUNT, WAITING_PERIOD

from .conftest import PASSWORD, enrol_totp, login, new_browser, register

NEW_PASSWORD = "a brand new password"


def setup_codes(app):
    owner = new_browser(app)
    register(owner)
    login(owner)
    codes = owner.post("/recovery/codes").json()["codes"]
    return owner, codes


def start(app, code, username="alice"):
    return new_browser(app).post("/recovery/start", json={"username": username, "code": code})


# ---------- T-B7 ----------

def test_ten_unique_codes_shown_once(app):
    owner, codes = setup_codes(app)
    assert len(codes) == CODE_COUNT == len(set(codes))
    assert owner.get("/recovery/status").json()["codes_left"] == CODE_COUNT


def test_code_works_once(app):
    _, codes = setup_codes(app)
    assert start(app, codes[0]).status_code == 202
    assert start(app, codes[0]).status_code == 400


def test_codes_accept_lowercase_and_no_dashes(app):
    _, codes = setup_codes(app)
    assert start(app, codes[1].replace("-", "").lower()).status_code == 202


def test_new_codes_replace_old_ones(app):
    owner, old = setup_codes(app)
    owner.post("/recovery/codes")
    assert start(app, old[0]).status_code == 400


def test_wrong_code_and_unknown_user_look_the_same(app):
    setup_codes(app)
    a, b = start(app, "AAAA-BBBB-CCCC"), start(app, "AAAA-BBBB-CCCC", username="nobody")
    assert a.status_code == b.status_code == 400 and a.json() == b.json()


def test_wrong_codes_are_rate_limited(app):
    _, codes = setup_codes(app)
    for _ in range(auth_config.RATE_MAX_FAILURES_ACCOUNT):
        assert start(app, "AAAA-BBBB-CCCC").status_code == 400
    assert start(app, codes[0]).status_code == 429


def test_codes_are_stored_hashed(app):
    from sqlalchemy import select

    from app.auth.db import SessionLocal
    from app.recovery.models import RecoveryCode

    _, codes = setup_codes(app)
    with SessionLocal() as db:
        stored = db.scalars(select(RecoveryCode.code_hash)).all()
    for code in codes:
        assert all(code.replace("-", "") not in h for h in stored)


# ---------- T-B8 ----------

def test_cannot_complete_during_waiting_period(app):
    _, codes = setup_codes(app)
    r = start(app, codes[0]).json()
    clock.advance(WAITING_PERIOD - 60)
    done = new_browser(app).post("/recovery/complete", json={"recovery_id": r["recovery_id"], "token": r["token"], "new_password": NEW_PASSWORD})
    assert done.status_code == 403
    # and the password still works for the owner
    assert new_browser(app).post("/session/login/password", json={"username": "alice", "password": PASSWORD}).status_code == 200


def test_owner_is_notified_and_can_cancel(app):
    owner, codes = setup_codes(app)
    r = start(app, codes[0]).json()
    status = owner.get("/recovery/status").json()
    assert status["pending"][0]["recovery_id"] == r["recovery_id"]
    assert any("recovering your account" in n["message"] for n in owner.get("/recovery/notifications").json())
    assert (auth_config.INSTANCE_DIR / "notifications.log").exists()

    assert owner.post(f"/recovery/cancel/{r['recovery_id']}").status_code == 200
    clock.advance(WAITING_PERIOD + 1)
    done = new_browser(app).post("/recovery/complete", json={"recovery_id": r["recovery_id"], "token": r["token"], "new_password": NEW_PASSWORD})
    assert done.status_code == 400


def test_wrong_token_cannot_complete(app):
    _, codes = setup_codes(app)
    r = start(app, codes[0]).json()
    clock.advance(WAITING_PERIOD + 1)
    done = new_browser(app).post("/recovery/complete", json={"recovery_id": r["recovery_id"], "token": "guess", "new_password": NEW_PASSWORD})
    assert done.status_code == 400


_TOTP = {}


def totp_now(_app):
    return _TOTP["t"].at(clock.now())


def test_completion_ends_all_sessions_removes_totp_and_sets_new_password(app):
    owner, codes = setup_codes(app)
    _TOTP["t"] = enrol_totp(owner)
    phone = new_browser(app)
    r = phone.post("/session/login/password", json={"username": "alice", "password": PASSWORD})
    assert r.json()["status"] == "totp_required"

    rec = start(app, codes[0]).json()
    # Sessions last at most 12 hours and the wait is 24, so log in again 10 minutes
    # before the end: only the recovery itself can end this session.
    clock.advance(WAITING_PERIOD - 600)
    late = new_browser(app)
    r = late.post("/session/login/password", json={"username": "alice", "password": PASSWORD})
    late.post("/session/login/totp", json={"pending_id": r.json()["pending_id"], "code": totp_now(app)})
    assert late.get("/session/me").status_code == 200
    clock.advance(601)
    recovered = new_browser(app)
    done = recovered.post("/recovery/complete", json={"recovery_id": rec["recovery_id"], "token": rec["token"], "new_password": NEW_PASSWORD})
    assert done.status_code == 200 and done.json()["methods"] == ["recovery"]

    assert late.get("/session/me").status_code == 401            # old sessions ended
    assert recovered.get("/session/me").json()["username"] == "alice"
    fresh = new_browser(app)
    assert fresh.post("/session/login/password", json={"username": "alice", "password": PASSWORD}).status_code == 401
    r = fresh.post("/session/login/password", json={"username": "alice", "password": NEW_PASSWORD})
    assert r.json()["status"] == "authenticated"                  # TOTP was removed


def test_recovery_cannot_be_completed_twice(app):
    _, codes = setup_codes(app)
    rec = start(app, codes[0]).json()
    clock.advance(WAITING_PERIOD + 1)
    body = {"recovery_id": rec["recovery_id"], "token": rec["token"], "new_password": NEW_PASSWORD}
    assert new_browser(app).post("/recovery/complete", json=body).status_code == 200
    assert new_browser(app).post("/recovery/complete", json=body).status_code == 400
