"""FR-B1 to FR-B4: session issue, validation, expiry and revocation."""
import hashlib
import secrets

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from app.auth.clock import clock

from . import config
from .models import Session


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db: DbSession, user_id: int, methods: list[str], ip: str = "", user_agent: str = "") -> tuple[str, Session]:
    """Returns the cookie value and the new session. A new random ID every time,
    which is what stops session fixation (FR-B4)."""
    token = secrets.token_urlsafe(config.SESSION_ID_BYTES)
    now = clock.now()
    s = Session(
        token_hash=_hash(token),
        public_id=secrets.token_urlsafe(8),
        user_id=user_id,
        csrf_token=secrets.token_urlsafe(32),
        methods=",".join(methods),
        created_at=now,
        last_seen_at=now,
        revoked=False,
        ip=ip[:64],
        user_agent=user_agent[:256],
    )
    db.add(s)
    db.commit()
    return token, s


def is_expired(s: Session, now: float) -> bool:
    return now - s.last_seen_at > config.IDLE_TIMEOUT or now - s.created_at > config.ABSOLUTE_TIMEOUT


def find(db: DbSession, token: str | None) -> Session | None:
    if not token:
        return None
    return db.scalar(select(Session).where(Session.token_hash == _hash(token)))


def validate(db: DbSession, token: str | None) -> Session | None:
    """Returns the session if it is still valid and records the activity, otherwise None."""
    s = find(db, token)
    if s is None or s.revoked:
        return None
    now = clock.now()
    if is_expired(s, now):
        s.revoked = True
        db.commit()
        return None
    s.last_seen_at = now
    db.commit()
    return s


def revoke(db: DbSession, s: Session) -> None:
    s.revoked = True
    db.commit()


def revoke_all(db: DbSession, user_id: int) -> int:
    """FR-B3: log out of all devices. Returns how many sessions were ended."""
    result = db.execute(update(Session).where(Session.user_id == user_id, Session.revoked.is_(False)).values(revoked=True))
    db.commit()
    return result.rowcount


def active_sessions(db: DbSession, user_id: int) -> list[Session]:
    now = clock.now()
    rows = db.scalars(select(Session).where(Session.user_id == user_id, Session.revoked.is_(False))).all()
    return [s for s in rows if not is_expired(s, now)]
