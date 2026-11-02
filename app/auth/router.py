"""HTTP routes for Module A. Include in the main app with:

    from app.auth.router import router as auth_router
    app.include_router(auth_router)

Routes under /auth/credentials, /auth/totp/enroll and /auth/webauthn/register need
the logged-in user. That comes from get_current_user_id in deps.py, which Module B
replaces with its session lookup."""
import time
from dataclasses import asdict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from . import service
from .db import get_db
from .deps import get_current_user_id
from .errors import AuthError

router = APIRouter(prefix="/auth", tags=["Module A - authentication"])


class Credentials(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class TotpLogin(BaseModel):
    pending_id: str = Field(max_length=128)
    code: str = Field(max_length=16)


class TotpCode(BaseModel):
    code: str = Field(max_length=16)


class PasskeyRegisterVerify(BaseModel):
    challenge_id: str = Field(max_length=128)
    credential: dict
    name: str = Field(default="Passkey", max_length=64)


class PasskeyLoginOptions(BaseModel):
    username: str | None = Field(default=None, max_length=64)


class PasskeyLoginVerify(BaseModel):
    challenge_id: str = Field(max_length=128)
    credential: dict


class Rename(BaseModel):
    name: str = Field(max_length=64)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _result(result, started: float) -> dict:
    data = asdict(result)
    if isinstance(result, service.AuthResult):
        data["server_ms"] = round((time.perf_counter() - started) * 1000, 2)
        data["status"] = "authenticated"
    else:
        data["status"] = "totp_required"
    return data


def auth_error_handler(_request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content={"detail": exc.message})


# ---------- registration and login ----------

@router.post("/register", status_code=201)
def register(body: Credentials, db: Session = Depends(get_db)):
    user = service.register(db, body.username, body.password)
    return {"user_id": user.id, "username": user.username}


@router.post("/login/password")
def login_password(body: Credentials, request: Request, db: Session = Depends(get_db)):
    started = time.perf_counter()
    return _result(service.login_password(db, body.username, body.password, _ip(request)), started)


@router.post("/login/totp")
def login_totp(body: TotpLogin, request: Request, db: Session = Depends(get_db)):
    started = time.perf_counter()
    return _result(service.login_totp(db, body.pending_id, body.code, _ip(request)), started)


@router.post("/webauthn/login/options")
def passkey_login_options(body: PasskeyLoginOptions, db: Session = Depends(get_db)):
    options, challenge_id = service.passkey_login_options(db, body.username)
    return {"challenge_id": challenge_id, "options": options}


@router.post("/webauthn/login/verify")
def passkey_login_verify(body: PasskeyLoginVerify, request: Request, db: Session = Depends(get_db)):
    started = time.perf_counter()
    return _result(service.passkey_login_verify(db, body.challenge_id, body.credential, _ip(request)), started)


# ---------- routes for a logged-in user ----------

@router.post("/totp/enroll/start")
def totp_enroll_start(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    return service.totp_enroll_start(db, service.get_user(db, user_id))


@router.post("/totp/enroll/confirm")
def totp_enroll_confirm(body: TotpCode, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    service.totp_enroll_confirm(db, service.get_user(db, user_id), body.code)
    return {"totp": "active"}


@router.post("/webauthn/register/options")
def passkey_register_options(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    options, challenge_id = service.passkey_register_options(db, service.get_user(db, user_id))
    return {"challenge_id": challenge_id, "options": options}


@router.post("/webauthn/register/verify", status_code=201)
def passkey_register_verify(body: PasskeyRegisterVerify, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    passkey = service.passkey_register_verify(db, service.get_user(db, user_id), body.challenge_id, body.credential, body.name)
    return {"id": passkey.id, "name": passkey.name}


@router.get("/credentials")
def list_credentials(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    return service.list_credentials(service.get_user(db, user_id))


@router.patch("/credentials/passkeys/{passkey_id}")
def rename_passkey(passkey_id: int, body: Rename, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    service.rename_passkey(db, service.get_user(db, user_id), passkey_id, body.name)
    return {"ok": True}


@router.delete("/credentials/passkeys/{passkey_id}")
def delete_passkey(passkey_id: int, user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    service.delete_passkey(db, service.get_user(db, user_id), passkey_id)
    return {"ok": True}


@router.delete("/credentials/password")
def delete_password(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    service.delete_password(db, service.get_user(db, user_id))
    return {"ok": True}


@router.delete("/credentials/totp")
def delete_totp(user_id: int = Depends(get_current_user_id), db: Session = Depends(get_db)):
    service.delete_totp(db, service.get_user(db, user_id))
    return {"ok": True}
