"""Module B routes for logging in, out and listing sessions.

Login: the client calls these routes. Each one asks Module A to check the
credentials (app.auth.service) and, on success, creates the session and sets the
cookie. Module A itself never sets cookies (Section 8 of the requirements)."""
import time

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as DbSession

from app.auth import service as auth
from app.auth.db import get_db
from app.auth.router import Credentials, PasskeyLoginVerify, TotpLogin

from . import config, service
from .deps import current_session
from .models import Session

router = APIRouter(prefix="/session", tags=["Module B - sessions"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _start_session(db: DbSession, request: Request, response: Response, result: auth.AuthResult, started: float) -> dict:
    # FR-B4: whatever session cookie came with the request is ended, and a brand new
    # ID is issued, so an ID an attacker planted before login is useless after it.
    old = service.find(db, request.cookies.get(config.COOKIE_NAME))
    if old is not None and not old.revoked:
        service.revoke(db, old)
    token, s = service.create(db, result.user_id, result.methods, _ip(request), request.headers.get("user-agent", ""))
    response.set_cookie(
        config.COOKIE_NAME, token,
        httponly=True, secure=config.COOKIE_SECURE, samesite=config.COOKIE_SAMESITE,
        max_age=config.ABSOLUTE_TIMEOUT, path="/",
    )
    return {
        "status": "authenticated",
        "user_id": result.user_id,
        "username": result.username,
        "methods": result.methods,
        "user_verified": result.user_verified,
        "csrf_token": s.csrf_token,
        "server_ms": round((time.perf_counter() - started) * 1000, 2),
    }


@router.post("/login/password")
def login_password(body: Credentials, request: Request, response: Response, db: DbSession = Depends(get_db)):
    started = time.perf_counter()
    result = auth.login_password(db, body.username, body.password, _ip(request))
    if isinstance(result, auth.TotpRequired):
        return {"status": "totp_required", "pending_id": result.pending_id}
    return _start_session(db, request, response, result, started)


@router.post("/login/totp")
def login_totp(body: TotpLogin, request: Request, response: Response, db: DbSession = Depends(get_db)):
    started = time.perf_counter()
    result = auth.login_totp(db, body.pending_id, body.code, _ip(request))
    return _start_session(db, request, response, result, started)


@router.post("/login/passkey")
def login_passkey(body: PasskeyLoginVerify, request: Request, response: Response, db: DbSession = Depends(get_db)):
    started = time.perf_counter()
    result = auth.passkey_login_verify(db, body.challenge_id, body.credential, _ip(request))
    return _start_session(db, request, response, result, started)


@router.get("/me")
def me(s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    user = auth.get_user(db, s.user_id)
    return {
        "user_id": user.id,
        "username": user.username,
        "methods": s.methods.split(","),
        "csrf_token": s.csrf_token,
        "session_id": s.public_id,
        "idle_timeout_seconds": config.IDLE_TIMEOUT,
        "expires_at": s.created_at + config.ABSOLUTE_TIMEOUT,
    }


@router.get("/list")
def list_sessions(s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    return [
        {
            "session_id": x.public_id, "current": x.id == s.id, "methods": x.methods.split(","),
            "created_at": x.created_at, "last_seen_at": x.last_seen_at, "ip": x.ip, "user_agent": x.user_agent,
        }
        for x in service.active_sessions(db, s.user_id)
    ]


@router.post("/logout")
def logout(response: Response, s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    service.revoke(db, s)
    response.delete_cookie(config.COOKIE_NAME, path="/")
    return {"ok": True}


@router.post("/logout-all")
def logout_all(response: Response, s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    count = service.revoke_all(db, s.user_id)
    response.delete_cookie(config.COOKIE_NAME, path="/")
    return {"ok": True, "sessions_ended": count}


@router.delete("/{public_id}")
def end_session(public_id: str, s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    for x in service.active_sessions(db, s.user_id):
        if x.public_id == public_id:
            service.revoke(db, x)
            return {"ok": True}
    return Response(status_code=404, content='{"detail":"Session not found."}', media_type="application/json")
