# Phishing-Resistant Authentication Service

SENG 495/496 Senior Design Project. A web authentication service supporting
passwords, TOTP and passkeys (WebAuthn), together with session management,
account recovery and an automated adversarial test suite.

**Stack:** Python, FastAPI, SQLite, pytest (served with uvicorn).

| Module | Topic | Owner |
|---|---|---|
| A | Authentication service core | Abdu |
| B | Sessions, recovery and client | Aziz |
| C | Adversarial test suite and evaluation | Ibrahim |

## Getting started

```bash
git clone https://github.com/IbrahimAKINCI/seng495-phishing-resistant-auth.git
cd seng495-phishing-resistant-auth

python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env        # then put your own SECRET_KEY in .env
```

## Run the service

```bash
uvicorn app.main:app --reload --port 8001
```

- Service: http://localhost:8001
- Health check: http://localhost:8001/health
- Interactive API documentation: http://localhost:8001/docs

## Run the tests

```bash
pytest
```

## Repository rules

- Never commit `.env` or any `.db` file.
- Every member commits to this repository from the first week; contribution is assessed from the history.
- Results in reports are produced by scripts, never typed by hand.
