"""Who is logged in. Module A's protected routes use session_user_id through
app.dependency_overrides[get_current_user_id] = session_user_id (see app/main.py)."""
import hmac

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from app.auth.db import get_db

from . import config, service
from .models import Session


def current_session(request: Request, db: DbSession = Depends(get_db)) -> Session:
    s = service.validate(db, request.cookies.get(config.COOKIE_NAME))
    if s is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    # FR-B1: every state-changing request carries the CSRF token of its session.
    # A page on another site cannot read the token, so it cannot send it.
    if request.method not in config.SAFE_METHODS:
        sent = request.headers.get(config.CSRF_HEADER, "")
        if not hmac.compare_digest(sent, s.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token missing or wrong.")
    return s


def session_user_id(s: Session = Depends(current_session)) -> int:
    return s.user_id
