"""Shared set-up for the attack tests. They run only against a service started on this
machine (attacks/server.py), never against any other system."""
import uuid

import httpx
import pyotp
import pytest

from harness import results

from .server import running_service

PASSWORD = "correct horse battery"


@pytest.fixture(scope="session")
def service():
    """One service for all tests that make only a few failed requests. A test that
    triggers the rate limit (many failures from 127.0.0.1) must start its own."""
    with running_service() as svc:
        yield svc


@pytest.fixture
def http(service):
    with httpx.Client(base_url=service.base_url, timeout=30) as client:
        yield client


@pytest.fixture
def report():
    """record(attack, method, expected, actual, detail): saves the outcome to
    results/attack_results.jsonl and returns True when the expectation held."""
    def record(attack: str, method: str, expected: str, actual: str, detail: str = "") -> bool:
        return results.record_attack(attack, method, expected, actual, detail)["confirmed"]
    return record


def new_username() -> str:
    return "victim-" + uuid.uuid4().hex[:12]


def register(client: httpx.Client, username: str, password: str = PASSWORD) -> None:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201, r.text


def session_login(client: httpx.Client, username: str, password: str = PASSWORD) -> httpx.Response:
    """Password login through Module B's route. On success the client holds the cookie
    and sends the CSRF token with later requests."""
    r = client.post("/session/login/password", json={"username": username, "password": password})
    if r.status_code == 200 and "csrf_token" in r.json():
        client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return r


def enrol_totp(client: httpx.Client) -> pyotp.TOTP:
    """Enrols TOTP for the logged-in user, like the web client does, and returns the
    victim's authenticator app (a pyotp object holding the shared secret)."""
    r = client.post("/auth/totp/enroll/start")
    assert r.status_code == 200, r.text
    totp = pyotp.TOTP(pyotp.parse_uri(r.json()["otpauth_uri"]).secret)
    r = client.post("/auth/totp/enroll/confirm", json={"code": totp.now()})
    assert r.status_code == 200, r.text
    return totp
