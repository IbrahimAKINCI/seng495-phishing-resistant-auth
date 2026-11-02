"""FR-A7: limits on failed logins, per account and per IP address.

Account: 5 failures within 15 minutes blocks that account for 15 minutes.
IP address: 20 failures within 15 minutes blocks that address for 15 minutes.
The block lasts until 15 minutes after the failure that reached the limit."""
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import config
from .clock import clock
from .models import FailedAttempt


def _blocked(db: Session, column, value: str, limit: int, now: float) -> bool:
    since = now - config.RATE_WINDOW_SECONDS - config.RATE_BLOCK_SECONDS
    times = db.scalars(
        select(FailedAttempt.at).where(column == value, FailedAttempt.at >= since).order_by(FailedAttempt.at)
    ).all()
    # Find a run of `limit` failures inside one window whose block is still running
    for i in range(len(times) - limit + 1):
        first, last = times[i], times[i + limit - 1]
        if last - first <= config.RATE_WINDOW_SECONDS and now < last + config.RATE_BLOCK_SECONDS:
            return True
    return False


def is_blocked(db: Session, username: str, ip: str) -> bool:
    now = clock.now()
    username = username.lower()
    return _blocked(db, FailedAttempt.username, username, config.RATE_MAX_FAILURES_ACCOUNT, now) or _blocked(
        db, FailedAttempt.ip, ip, config.RATE_MAX_FAILURES_IP, now
    )


def is_ip_blocked(db: Session, ip: str) -> bool:
    """Only the per-address limit. Used where the account is not known yet, such as a
    passkey login that fails before the credential is matched to a user."""
    return _blocked(db, FailedAttempt.ip, ip, config.RATE_MAX_FAILURES_IP, clock.now())


def record_failure(db: Session, username: str, ip: str) -> None:
    db.add(FailedAttempt(username=username.lower(), ip=ip, at=clock.now()))
    # keep the table small
    db.execute(delete(FailedAttempt).where(FailedAttempt.at < clock.now() - 24 * 3600))
    db.commit()


def failure_count(db: Session, username: str) -> int:
    since = clock.now() - config.RATE_WINDOW_SECONDS
    return db.scalar(
        select(func.count()).select_from(FailedAttempt).where(
            FailedAttempt.username == username.lower(), FailedAttempt.at >= since
        )
    )
