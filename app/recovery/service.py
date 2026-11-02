"""FR-B7 and FR-B8: account recovery with single-use codes and a 24-hour waiting period.

The threat this flow exposes (Week 8 task): recovery exists so that someone who lost
their credentials can get in, so it is also a way in for an attacker who steals a
recovery code. The hardening (Week 11 task) limits the damage:
- the code is useless for 24 hours, and the owner is notified at once and can cancel
  from any logged-in session;
- the person recovering gets no session and can change nothing during the wait;
- completing recovery ends every existing session, removes TOTP (the lost phone) and
  needs a new password;
- wrong codes count towards a rate limit, like failed logins.
"""
import hashlib
import hmac
import json
import secrets
import time

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from app.auth import config as auth_config
from app.auth import passwords, ratelimit
from app.auth.clock import clock
from app.auth.errors import AuthError, too_many
from app.auth.models import User
from app.sessions import service as sessions

from .models import Notification, RecoveryCode, RecoveryRequest

CODE_COUNT = 10
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I, easy to read
CODE_LENGTH = 12  # about 60 bits
WAITING_PERIOD = 24 * 3600
RECOVERY_FAILED = "Recovery failed."


def _normalize(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def _hash_code(user_id: int, code: str) -> str:
    return hashlib.sha256(f"{user_id}:{_normalize(code)}".encode()).hexdigest()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def notify(db: DbSession, user_id: int, message: str) -> None:
    db.add(Notification(user_id=user_id, at=clock.now(), message=message))
    db.commit()
    auth_config.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    with (auth_config.INSTANCE_DIR / "notifications.log").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "user_id": user_id, "message": message}) + "\n")


def generate_codes(db: DbSession, user: User) -> list[str]:
    """New set of 10 codes. Shown once; any old codes stop working."""
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = []
    for _ in range(CODE_COUNT):
        raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
        db.add(RecoveryCode(user_id=user.id, code_hash=_hash_code(user.id, raw), used=False))
    db.commit()
    notify(db, user.id, "New recovery codes were created. Old codes no longer work.")
    return codes


def codes_left(db: DbSession, user_id: int) -> int:
    return len(db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user_id, RecoveryCode.used.is_(False))).all())


def start(db: DbSession, username: str, code: str, ip: str) -> tuple[str, str, float]:
    """Returns (recovery id, secret token, ready_at). Same error for unknown users and wrong codes."""
    username = (username or "").strip().lower()
    key = f"recovery:{username}"
    if ratelimit.is_blocked(db, key, ip):
        raise too_many()
    user = db.scalar(select(User).where(User.username == username))
    row = None
    if user is not None:
        row = db.scalar(select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.code_hash == _hash_code(user.id, code), RecoveryCode.used.is_(False)
        ))
    if row is None:
        ratelimit.record_failure(db, key, ip)
        raise AuthError(400, RECOVERY_FAILED)

    row.used = True
    token = secrets.token_urlsafe(32)
    now = clock.now()
    req = RecoveryRequest(id=secrets.token_urlsafe(12), user_id=user.id, token_hash=_hash_token(token),
                          created_at=now, ready_at=now + WAITING_PERIOD, status="pending")
    db.add(req)
    db.commit()
    notify(db, user.id, "Someone started recovering your account with a recovery code. "
                        "If this was not you, cancel it from your security page within 24 hours.")
    return req.id, token, req.ready_at


def pending_for(db: DbSession, user_id: int) -> list[RecoveryRequest]:
    return db.scalars(select(RecoveryRequest).where(RecoveryRequest.user_id == user_id, RecoveryRequest.status == "pending")).all()


def cancel(db: DbSession, user_id: int, recovery_id: str) -> None:
    req = db.get(RecoveryRequest, recovery_id)
    if req is None or req.user_id != user_id or req.status != "pending":
        raise AuthError(404, "Recovery not found.")
    req.status = "cancelled"
    db.commit()
    notify(db, user_id, "The account recovery was cancelled.")


def complete(db: DbSession, recovery_id: str, token: str, new_password: str) -> User:
    req = db.get(RecoveryRequest, recovery_id or "")
    if req is None or req.status != "pending" or not hmac.compare_digest(req.token_hash, _hash_token(token or "")):
        raise AuthError(400, RECOVERY_FAILED)
    if clock.now() < req.ready_at:
        raise AuthError(403, "The waiting period has not ended yet.")
    if passwords.check_password_rules(new_password or ""):
        raise AuthError(400, passwords.check_password_rules(new_password or ""))

    user = db.get(User, req.user_id)
    sessions.revoke_all(db, user.id)        # every old session ends
    user.password_hash = passwords.hash_password(new_password)
    if user.totp is not None:               # the lost phone's TOTP goes
        db.delete(user.totp)
    req.status = "completed"
    db.commit()
    db.refresh(user)
    notify(db, user.id, "Your account was recovered. All sessions were ended and the password was changed.")
    return user


def notifications(db: DbSession, user_id: int) -> list[Notification]:
    return db.scalars(select(Notification).where(Notification.user_id == user_id).order_by(Notification.at.desc())).all()
