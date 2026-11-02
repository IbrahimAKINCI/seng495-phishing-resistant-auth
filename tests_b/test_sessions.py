"""T-B1 to T-B4, and the Week 9 task: a revoked session is rejected on every endpoint."""
from app.auth.clock import clock
from app.sessions import config

from .conftest import PASSWORD, enrol_totp, login, new_browser, register


# ---------- T-B1 ----------

def test_login_sets_secure_httponly_samesite_cookie(browser):
    register(browser)
    r = browser.post("/session/login/password", json={"username": "alice", "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert cookie.startswith(f"{config.COOKIE_NAME}=")
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert "csrf_token" in r.json()
    assert r.cookies.get(config.COOKIE_NAME) not in r.text  # the session ID is never in the body


def test_session_id_has_128_bits(browser):
    register(browser)
    login(browser)
    token = browser.cookies.get(config.COOKIE_NAME)
    assert len(token) >= 22  # 16 random bytes in base64url


def test_post_without_csrf_token_is_rejected(browser):
    register(browser)
    login(browser)
    token = browser.headers.pop("X-CSRF-Token")
    assert browser.post("/session/logout-all").status_code == 403
    assert browser.post("/auth/totp/enroll/start").status_code == 403  # Module A routes too
    browser.headers["X-CSRF-Token"] = "wrong"
    assert browser.post("/session/logout-all").status_code == 403
    browser.headers["X-CSRF-Token"] = token
    assert browser.post("/session/logout-all").status_code == 200


def test_get_requests_do_not_need_csrf(browser):
    register(browser)
    login(browser)
    browser.headers.pop("X-CSRF-Token")
    assert browser.get("/session/me").status_code == 200


# ---------- T-B2 ----------

def test_session_expires_after_30_minutes_idle(browser):
    register(browser)
    login(browser)
    clock.advance(config.IDLE_TIMEOUT + 60)
    assert browser.get("/session/me").status_code == 401


def test_activity_keeps_session_alive_until_12_hours(browser):
    register(browser)
    login(browser)
    for _ in range(int(config.ABSOLUTE_TIMEOUT // 600) - 1):  # every 10 minutes
        clock.advance(600)
        assert browser.get("/session/me").status_code == 200
    clock.advance(600 + 1)
    assert browser.get("/session/me").status_code == 401


# ---------- T-B3 ----------

def test_logout_ends_only_this_session(app):
    laptop, phone = new_browser(app), new_browser(app)
    register(laptop)
    login(laptop)
    login(phone)
    assert laptop.post("/session/logout").status_code == 200
    assert laptop.get("/session/me").status_code == 401
    assert phone.get("/session/me").status_code == 200


def test_logout_all_ends_every_session(app):
    laptop, phone, tablet = new_browser(app), new_browser(app), new_browser(app)
    register(laptop)
    for b in (laptop, phone, tablet):
        login(b)
    phone_cookie = phone.cookies.get(config.COOKIE_NAME)
    r = laptop.post("/session/logout-all")
    assert r.json()["sessions_ended"] == 3
    for b in (laptop, phone, tablet):
        assert b.get("/session/me").status_code == 401
    # even a copy of the old cookie does not work
    thief = new_browser(app)
    thief.cookies.set(config.COOKIE_NAME, phone_cookie, domain="localhost.local")
    assert thief.get("/session/me").status_code == 401


def test_end_another_session_from_the_list(app):
    laptop, phone = new_browser(app), new_browser(app)
    register(laptop)
    login(laptop)
    login(phone)
    sessions = laptop.get("/session/list").json()
    other = next(s for s in sessions if not s["current"])
    assert laptop.delete(f"/session/{other['session_id']}").status_code == 200
    assert phone.get("/session/me").status_code == 401
    assert laptop.get("/session/me").status_code == 200


def test_cannot_end_another_users_session(app):
    alice, bob = new_browser(app), new_browser(app)
    register(alice, "alice")
    register(bob, "bob")
    login(alice, "alice")
    login(bob, "bob")
    bob_id = bob.get("/session/me").json()["session_id"]
    assert alice.delete(f"/session/{bob_id}").status_code == 404
    assert bob.get("/session/me").status_code == 200


# ---------- T-B4 ----------

def test_new_session_id_after_login_and_planted_id_stops_working(app):
    attacker, victim = new_browser(app), new_browser(app)
    register(attacker, "mallory")
    register(victim, "alice")
    login(attacker, "mallory")
    planted = attacker.cookies.get(config.COOKIE_NAME)

    # the attacker gets their session ID into the victim's browser, then the victim logs in
    victim.cookies.set(config.COOKIE_NAME, planted, domain="localhost.local")
    login(victim, "alice")
    assert victim.cookies.get(config.COOKIE_NAME) != planted
    assert victim.get("/session/me").json()["username"] == "alice"

    # the planted ID neither became alice's session nor stays valid
    attacker.cookies.set(config.COOKIE_NAME, planted, domain="localhost.local")
    assert attacker.get("/session/me").status_code == 401


def test_new_session_id_after_totp_and_passkey_login(app, authenticator):
    b = new_browser(app)
    register(b)
    login(b)
    totp = enrol_totp(b)
    first = b.cookies.get(config.COOKIE_NAME)
    r = b.post("/session/login/password", json={"username": "alice", "password": PASSWORD})
    r = b.post("/session/login/totp", json={"pending_id": r.json()["pending_id"], "code": totp.at(clock.now())})
    assert r.status_code == 200 and r.json()["methods"] == ["password", "totp"]
    assert b.cookies.get(config.COOKIE_NAME) != first


def test_passkey_login_creates_session(app, authenticator):
    b = new_browser(app)
    register(b)
    login(b)
    opts = b.post("/auth/webauthn/register/options").json()
    cred = authenticator.create(opts["options"])
    assert b.post("/auth/webauthn/register/verify", json={"challenge_id": opts["challenge_id"], "credential": cred}).status_code == 201

    phone = new_browser(app)
    opts = phone.post("/auth/webauthn/login/options", json={}).json()
    r = phone.post("/session/login/passkey", json={"challenge_id": opts["challenge_id"], "credential": authenticator.get(opts["options"])})
    assert r.status_code == 200 and r.json()["methods"] == ["passkey"]
    assert phone.get("/session/me").json()["username"] == "alice"


def test_failed_login_creates_no_session(browser):
    register(browser)
    r = browser.post("/session/login/password", json={"username": "alice", "password": "wrong password!!"})
    assert r.status_code == 401
    assert "set-cookie" not in r.headers
    assert browser.get("/session/me").status_code == 401


# ---------- Week 9: a revoked session is rejected on every endpoint ----------

PROTECTED = [
    ("GET", "/session/me"), ("GET", "/session/list"), ("POST", "/session/logout"),
    ("POST", "/session/logout-all"), ("DELETE", "/session/some-id"),
    ("GET", "/auth/credentials"), ("POST", "/auth/totp/enroll/start"), ("POST", "/auth/totp/enroll/confirm"),
    ("POST", "/auth/webauthn/register/options"), ("POST", "/auth/webauthn/register/verify"),
    ("PATCH", "/auth/credentials/passkeys/1"), ("DELETE", "/auth/credentials/passkeys/1"),
    ("DELETE", "/auth/credentials/password"), ("DELETE", "/auth/credentials/totp"),
    ("POST", "/recovery/codes"), ("GET", "/recovery/status"), ("POST", "/recovery/cancel/x"),
    ("GET", "/recovery/notifications"),
]


def test_revoked_session_is_rejected_on_every_protected_endpoint(app):
    b = new_browser(app)
    register(b)
    login(b)
    cookie, csrf = b.cookies.get(config.COOKIE_NAME), b.headers["X-CSRF-Token"]
    b.post("/session/logout")

    replay = new_browser(app)
    replay.cookies.set(config.COOKIE_NAME, cookie, domain="localhost.local")
    replay.headers["X-CSRF-Token"] = csrf
    bodies = {"/auth/totp/enroll/confirm": {"code": "123456"},
              "/auth/webauthn/register/verify": {"challenge_id": "x", "credential": {}},
              "/auth/credentials/passkeys/1": {"name": "x"}}
    for method, path in PROTECTED:
        r = replay.request(method, path, json=bodies.get(path))
        assert r.status_code == 401, f"{method} {path} returned {r.status_code}"


def test_every_protected_route_is_in_the_list(app):
    """If someone adds a protected route, this test reminds them to add it above."""
    from fastapi.routing import APIRoute

    from app.sessions.deps import current_session, session_user_id
    from app.auth.deps import get_current_user_id

    def needs_login(route):
        stack = list(route.dependant.dependencies)
        while stack:
            d = stack.pop()
            if d.call in (current_session, session_user_id, get_current_user_id):
                return True
            stack.extend(d.dependencies)
        return False

    listed = {(m, p.split("/some-id")[0].replace("/1", "").replace("/x", "")) for m, p in PROTECTED}
    for route in app.routes:
        if isinstance(route, APIRoute) and needs_login(route):
            base = route.path.split("/{")[0]
            for m in route.methods:
                assert (m, base) in listed, f"{m} {route.path} is protected but not in PROTECTED"
