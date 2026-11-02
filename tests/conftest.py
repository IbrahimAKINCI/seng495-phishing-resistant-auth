import base64
import os
import tempfile
from pathlib import Path

# Settings must be in place before the app is imported
_tmp = tempfile.mkdtemp(prefix="auth-tests-")
os.environ["AUTH_INSTANCE_DIR"] = _tmp
os.environ["AUTH_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["TOTP_ENC_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["AUTH_RP_ID"] = "localhost"
os.environ["AUTH_EXPECTED_ORIGIN"] = "http://localhost:8000"
os.environ["AUTH_RESULTS_DIR"] = f"{_tmp}/results"

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth.clock import clock  # noqa: E402
from app.auth.db import Base, engine  # noqa: E402
from app.auth.policy import load_policy, set_policy  # noqa: E402
from app.main import create_app  # noqa: E402

from .soft_authenticator import SoftAuthenticator  # noqa: E402

POLICY_DIR = Path(__file__).resolve().parents[1] / "policy"
PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def fresh_state():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    clock.reset()
    set_policy(load_policy(POLICY_DIR / "default.json"))
    yield
    clock.reset()


@pytest.fixture
def client():
    return TestClient(create_app(dev_user_header=True))


@pytest.fixture
def authenticator():
    return SoftAuthenticator()


def use_policy(name: str) -> None:
    set_policy(load_policy(POLICY_DIR / f"{name}.json"))


def register(client, username="alice", password=PASSWORD) -> int:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201, r.text
    return r.json()["user_id"]


def as_user(user_id: int) -> dict:
    """Stands in for Module B's session until it exists."""
    return {"X-Dev-User": str(user_id)}


def enrol_totp(client, user_id: int) -> pyotp.TOTP:
    r = client.post("/auth/totp/enroll/start", headers=as_user(user_id))
    assert r.status_code == 200, r.text
    totp = pyotp.TOTP(pyotp.parse_uri(r.json()["otpauth_uri"]).secret)
    r = client.post("/auth/totp/enroll/confirm", json={"code": totp.at(clock.now())}, headers=as_user(user_id))
    assert r.status_code == 200, r.text
    # the confirmation code is now used, so tests that log in move to the next window
    clock.advance(30)
    return totp


def add_passkey(client, authenticator, user_id: int, name="Laptop"):
    r = client.post("/auth/webauthn/register/options", headers=as_user(user_id))
    assert r.status_code == 200, r.text
    body = r.json()
    cred = authenticator.create(body["options"])
    r = client.post("/auth/webauthn/register/verify",
                    json={"challenge_id": body["challenge_id"], "credential": cred, "name": name},
                    headers=as_user(user_id))
    assert r.status_code == 201, r.text
    return r.json()["id"], authenticator.credentials[list(authenticator.credentials)[-1]]


def passkey_options(client, username: str | None = None) -> dict:
    r = client.post("/auth/webauthn/login/options", json={"username": username})
    assert r.status_code == 200, r.text
    return r.json()


def passkey_verify(client, challenge_id: str, credential: dict):
    return client.post("/auth/webauthn/login/verify", json={"challenge_id": challenge_id, "credential": credential})
