# Phishing-Resistant Authentication Service

SENG 495/496 Senior Design Project. A web authentication service supporting passwords,
TOTP and passkeys (WebAuthn), together with session management, account recovery and
an automated adversarial test suite.

**Stack:** Python, FastAPI, SQLite, pytest (served with uvicorn).

| Module | Topic | Owner | Folders |
| --- | --- | --- | --- |
| A | Authentication service core | Abdirahman Ahmed HUSSEIN | `app/auth/`, `policy/`, `tests/` |
| B | Sessions, recovery and client | Abdulaziz ALIOGLU | `app/sessions/`, `app/recovery/`, `app/friction/`, `web/`, `tests_b/` |
| C | Adversarial test suite and evaluation | Ibrahim Said AKINCI | `attacks/`, `tests/test_stats.py` |

Shared: `app/main.py`, `tests_e2e/`, `requirements.txt`, `pytest.ini`, `.github/`.

## Getting started

```
git clone https://github.com/IbrahimAKINCI/seng495-phishing-resistant-auth.git
cd seng495-phishing-resistant-auth

python -m venv .venv
# Windows:   .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

pip install -r requirements.txt
python -m playwright install chromium   # once, for the browser tests
cp .env.example .env        # then put your own SECRET_KEY in .env
```

## Run the service

```
uvicorn app.main:app --reload --port 8001
```

- Service (web client): http://localhost:8001
- Health check: http://localhost:8001/health
- Interactive API documentation: http://localhost:8001/docs

Use `localhost`, not `127.0.0.1`: passkeys are bound to `localhost` and the port must
match `AUTH_EXPECTED_ORIGIN` (default `http://localhost:8001`). On Windows a real
passkey works with Windows Hello.

## Run the tests

```
pytest                     # everything
pytest tests               # Module A
pytest tests_b             # Module B
pytest attacks             # Module C attacks
pytest tests_e2e           # real Chrome, all three methods (Week 9 gate)
python -m attacks.report   # table of attack results
```

## Repository rules

- Never commit `.env` or any `.db` file.
- Every member commits to this repository from the first week; contribution is assessed from the history.
- Results in reports are produced by scripts, never typed by hand.

## How the modules connect (Section 8 of the requirements)

- Module A checks credentials and returns a result. It never sets cookies.
- Module B's `/session/login/*` routes call Module A, then create the session and set the cookie.
- Module A's protected routes get the logged-in user from Module B through
  `app.dependency_overrides[get_current_user_id] = session_user_id` in `app/main.py`.
- Module B writes `results/friction.jsonl` and `results/server_timing.jsonl`. Module C reads them.

## Status (Semester 1)

| Week | Module A | Module B | Module C |
| --- | --- | --- | --- |
| 5 | Registration, Argon2id password login | Session issue and validation | Results recorder, statistics, server timing log |
| 6 | TOTP with time window and reuse prevention | Client screens for registration and login | OTP replay test |
| 7 | Passkey registration, challenge and origin checks | Expiry, revocation, logout across devices | *Session fixation and token reuse tests: to do* |
| 8 | Passkey login, checked with Chrome's virtual authenticator | Recovery flow and its threat | Origin mismatch test |
| 9 | Origin check shown in a real browser | Revoked session rejected on every endpoint | First results table |
| 10 | Rate limiting | *Fatigue scenario: to do* | *Friction measurements: to do* |
| 11 | Credential management | Recovery hardening | *Server time measurements: to do* |

## Settings

Numbers from the requirements: `app/auth/config.py`, `app/sessions/config.py`,
`app/recovery/service.py`. Environment variables: `DATABASE_URL`, `TOTP_ENC_KEY`,
`AUTH_RP_ID`, `AUTH_EXPECTED_ORIGIN`, `AUTH_POLICY_PATH`, `AUTH_RESULTS_DIR`,
`SESSION_COOKIE_SECURE`.
