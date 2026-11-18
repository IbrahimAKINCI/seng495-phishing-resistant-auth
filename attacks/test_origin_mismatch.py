"""A3: origin / relying party mismatch (docs/threat_model.md, Week 8 task).

Attacker model: the victim is on the attacker's look-alike page. The victim's passkey signs
a login response there. The attacker sends that response to the real service. The response
is made by the victim's real key, for the real challenge, but it names another site.

Three responses are tried, so each check of FR-A5 (Section 4.2) is tested on its own:
    wrong origin      clientDataJSON.origin is the attacker's site, RP ID hash is correct   -> check 5
    wrong RP ID hash  origin is correct, authenticatorData holds SHA-256 of the attacker's  -> check 6
                      domain
    both wrong        what a real browser produces on the attacker's page: origin and RP ID
                      are both the attacker's

Expected result, written down before the test was run (threat model, row A3):
    passkey         blocked  (the signature covers origin and RP ID; the service checks both)
Passwords and one-time codes carry no origin, so the attack does not apply to them and
they are not tested here.

Controls: the same key, with honest values, is accepted before and after the attacks. Without
them "blocked" could only mean that the test set-up is broken.

The software authenticator is Module C's own (harness/softkey.py).
"""
import httpx

from harness.softkey import SoftKey

from .conftest import new_username, register, session_login

ATTACKER_ORIGIN = "https://login-example-evil.test"
ATTACKER_RP_ID = "login-example-evil.test"


def enrol_passkey(service, http: httpx.Client, username: str) -> SoftKey:
    """Registers a passkey for the victim, like the web client does after a password login."""
    assert session_login(http, username).status_code == 200
    r = http.post("/auth/webauthn/register/options")
    assert r.status_code == 200, r.text
    body = r.json()
    key = SoftKey(rp_id=body["options"]["rp"]["id"], origin=service.base_url)
    r = http.post("/auth/webauthn/register/verify", json={
        "challenge_id": body["challenge_id"], "credential": key.register(body["options"]), "name": "victim key"})
    assert r.status_code == 201, r.text
    return key


def passkey_login(service, username: str, key: SoftKey, **overrides) -> httpx.Response:
    """A passkey login from a fresh machine (no cookies). `overrides` go to SoftKey.assertion."""
    with httpx.Client(base_url=service.base_url, timeout=30) as machine:
        r = machine.post("/auth/webauthn/login/options", json={"username": username})
        assert r.status_code == 200, r.text
        options = r.json()
        return machine.post("/session/login/passkey", json={
            "challenge_id": options["challenge_id"], "credential": key.assertion(options["options"], **overrides)})


def test_passkey_response_for_another_origin_is_rejected(service, http, report):
    username = new_username()
    register(http, username)
    key = enrol_passkey(service, http, username)

    control_before = passkey_login(service, username, key)
    assert control_before.status_code == 200, control_before.text

    attempts = {
        "wrong origin": passkey_login(service, username, key, origin=ATTACKER_ORIGIN),
        "wrong RP ID hash": passkey_login(service, username, key, rp_id=ATTACKER_RP_ID),
        "both wrong": passkey_login(service, username, key, origin=ATTACKER_ORIGIN, rp_id=ATTACKER_RP_ID),
    }

    control_after = passkey_login(service, username, key)
    assert control_after.status_code == 200, control_after.text

    got_session = [name for name, r in attempts.items() if r.status_code == 200 or "set-cookie" in r.headers]
    actual = "succeeded" if got_session else "blocked"
    detail = "; ".join(f"{name}: status {r.status_code}" for name, r in attempts.items())
    detail += f"; controls before/after: {control_before.status_code}/{control_after.status_code}"

    assert report("origin_mismatch", "passkey", "blocked", actual, detail)
    assert actual == "blocked", f"accepted: {got_session}"
    assert all(r.status_code == 401 for r in attempts.values())
