"""Set-up for the browser tests. One service (started on this machine, reached by name
"localhost" because a browser refuses an IP address as WebAuthn RP ID) and one Chromium for
the whole run. Each test gets its own account and its own browser context (cookies,
virtual authenticator)."""
from dataclasses import dataclass

import secrets

import httpx
import pyotp
import pytest
from playwright.sync_api import sync_playwright

from attacks.conftest import enrol_totp, new_username, register, session_login
from attacks.server import RunningService, running_service


@dataclass
class Env:
    service: RunningService
    page: object                  # Playwright page in a fresh browser context
    cdp: object                   # DevTools session of that page (virtual authenticator)
    username: str
    password: str
    totp: pyotp.TOTP | None = None


@pytest.fixture(scope="session")
def service():
    with running_service(host="localhost") as svc:
        yield svc


@pytest.fixture(scope="session")
def chromium():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def make_env(service, chromium):
    """Returns a function that makes an account and a browser. `with_totp` enrols an
    authenticator app for it first, over the API (not measured)."""
    contexts = []

    def make(with_totp: bool = False) -> Env:
        username = new_username()
        password = secrets.token_urlsafe(12)     # random, like the user name; kept only for this test
        totp = None
        with httpx.Client(base_url=service.base_url, timeout=30) as api:
            register(api, username, password)
            if with_totp:
                assert session_login(api, username, password).status_code == 200
                totp = enrol_totp(api)
        context = chromium.new_context()
        contexts.append(context)
        page = context.new_page()
        return Env(service, page, context.new_cdp_session(page), username, password, totp)

    yield make
    for context in contexts:
        context.close()


@pytest.fixture
def env(make_env) -> Env:
    return make_env()
