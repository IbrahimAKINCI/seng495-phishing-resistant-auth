"""Module B tests. They reuse the set-up from tests/conftest.py and run the real app
with sessions (no X-Dev-User header). The base URL is https so the client sends
Secure cookies, as a browser would."""
import pyotp
import pytest
from fastapi.testclient import TestClient

from app.auth.clock import clock
from app.main import create_app
from tests.conftest import PASSWORD, authenticator, fresh_state  # noqa: F401


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def browser(app):
    """One browser (its own cookie jar). Call new_browser() for a second device."""
    return new_browser(app)


def new_browser(app) -> TestClient:
    return TestClient(app, base_url="https://localhost")


def register(c, username="alice", password=PASSWORD) -> int:
    r = c.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201, r.text
    return r.json()["user_id"]


def login(c, username="alice", password=PASSWORD) -> dict:
    r = c.post("/session/login/password", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    body = r.json()
    c.headers["X-CSRF-Token"] = body["csrf_token"]
    return body


def enrol_totp(c) -> pyotp.TOTP:
    r = c.post("/auth/totp/enroll/start")
    assert r.status_code == 200, r.text
    totp = pyotp.TOTP(pyotp.parse_uri(r.json()["otpauth_uri"]).secret)
    assert c.post("/auth/totp/enroll/confirm", json={"code": totp.at(clock.now())}).status_code == 200
    clock.advance(30)
    return totp
