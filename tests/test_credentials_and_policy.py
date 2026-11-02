"""T-A6 (credential management) and T-A11 (authentication policy for login)."""
from .conftest import PASSWORD, add_passkey, as_user, enrol_totp, passkey_options, passkey_verify, register, use_policy
from app.auth.clock import clock


def password_login(client, username="alice"):
    return client.post("/auth/login/password", json={"username": username, "password": PASSWORD})


# ---------- T-A6 ----------

def test_protected_routes_need_a_logged_in_user(client):
    assert client.get("/auth/credentials").status_code == 401
    assert client.post("/auth/totp/enroll/start").status_code == 401


def test_list_and_rename_passkey(client, authenticator):
    uid = register(client)
    pid, _ = add_passkey(client, authenticator, uid, name="Laptop")
    creds = client.get("/auth/credentials", headers=as_user(uid)).json()
    assert creds["password"] is True and creds["passkeys"][0]["name"] == "Laptop"
    assert client.patch(f"/auth/credentials/passkeys/{pid}", json={"name": "Work laptop"}, headers=as_user(uid)).status_code == 200
    assert client.get("/auth/credentials", headers=as_user(uid)).json()["passkeys"][0]["name"] == "Work laptop"


def test_delete_passkey_when_password_remains(client, authenticator):
    uid = register(client)
    pid, _ = add_passkey(client, authenticator, uid)
    assert client.delete(f"/auth/credentials/passkeys/{pid}", headers=as_user(uid)).status_code == 200
    assert client.get("/auth/credentials", headers=as_user(uid)).json()["passkeys"] == []


def test_last_credential_cannot_be_deleted(client, authenticator):
    uid = register(client)
    pid, _ = add_passkey(client, authenticator, uid)
    assert client.delete("/auth/credentials/password", headers=as_user(uid)).status_code == 200
    r = client.delete(f"/auth/credentials/passkeys/{pid}", headers=as_user(uid))
    assert r.status_code == 400
    # the passkey still logs in
    opts = passkey_options(client, "alice")
    assert passkey_verify(client, opts["challenge_id"], authenticator.get(opts["options"])).status_code == 200


def test_password_is_last_credential_without_passkeys(client):
    uid = register(client)
    assert client.delete("/auth/credentials/password", headers=as_user(uid)).status_code == 400


def test_cannot_touch_another_users_passkey(client, authenticator):
    alice = register(client, "alice")
    bob = register(client, "bob")
    pid, _ = add_passkey(client, authenticator, alice)
    assert client.delete(f"/auth/credentials/passkeys/{pid}", headers=as_user(bob)).status_code == 404
    assert client.patch(f"/auth/credentials/passkeys/{pid}", json={"name": "x"}, headers=as_user(bob)).status_code == 404


def test_removing_totp_returns_to_password_only_login(client):
    uid = register(client)
    enrol_totp(client, uid)
    assert password_login(client).json()["status"] == "totp_required"
    assert client.delete("/auth/credentials/totp", headers=as_user(uid)).status_code == 200
    assert password_login(client).json()["status"] == "authenticated"


# ---------- T-A11 ----------

def test_password_login_allowed_by_permissive_policy(client):
    register(client)
    assert password_login(client).status_code == 200


def test_password_login_refused_by_passkey_only_policy(client, authenticator):
    uid = register(client)
    add_passkey(client, authenticator, uid)
    use_policy("passkey_only")
    assert password_login(client).status_code == 403
    opts = passkey_options(client, "alice")
    assert passkey_verify(client, opts["challenge_id"], authenticator.get(opts["options"])).status_code == 200


def test_fallback_policy_needs_totp_for_password_login(client):
    alice = register(client, "alice")
    register(client, "bob")
    totp = enrol_totp(client, alice)
    use_policy("passkey_with_fallback")
    assert password_login(client, "bob").status_code == 403  # password only: not allowed
    r = password_login(client, "alice")  # password + TOTP: allowed
    assert r.status_code == 200 and r.json()["status"] == "totp_required"
    r = client.post("/auth/login/totp", json={"pending_id": r.json()["pending_id"], "code": totp.at(clock.now())})
    assert r.status_code == 200
