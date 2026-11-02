import time

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from app.auth.db import get_db
from app.auth.service import AuthResult, get_user
from app.sessions.deps import current_session
from app.sessions.models import Session
from app.sessions.router import _start_session

from . import service

router = APIRouter(prefix="/recovery", tags=["Module B - recovery"])


class StartRecovery(BaseModel):
    username: str = Field(max_length=64)
    code: str = Field(max_length=32)


class CompleteRecovery(BaseModel):
    recovery_id: str = Field(max_length=64)
    token: str = Field(max_length=128)
    new_password: str = Field(max_length=256)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/codes")
def generate_codes(s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    return {"codes": service.generate_codes(db, get_user(db, s.user_id))}


@router.get("/status")
def status(s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    return {
        "codes_left": service.codes_left(db, s.user_id),
        "pending": [{"recovery_id": r.id, "created_at": r.created_at, "ready_at": r.ready_at} for r in service.pending_for(db, s.user_id)],
    }


@router.post("/cancel/{recovery_id}")
def cancel(recovery_id: str, s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    service.cancel(db, s.user_id, recovery_id)
    return {"ok": True}


@router.get("/notifications")
def notifications(s: Session = Depends(current_session), db: DbSession = Depends(get_db)):
    return [{"at": n.at, "message": n.message} for n in service.notifications(db, s.user_id)]


@router.post("/start", status_code=202)
def start(body: StartRecovery, request: Request, db: DbSession = Depends(get_db)):
    recovery_id, token, ready_at = service.start(db, body.username, body.code, _ip(request))
    return {"recovery_id": recovery_id, "token": token, "ready_at": ready_at,
            "message": "Recovery started. Come back after the waiting period to set a new password."}


@router.post("/complete")
def complete(body: CompleteRecovery, request: Request, response: Response, db: DbSession = Depends(get_db)):
    started = time.perf_counter()
    user = service.complete(db, body.recovery_id, body.token, body.new_password)
    return _start_session(db, request, response, AuthResult(user_id=user.id, username=user.username, methods=["recovery"]), started)
