"""Module A business logic. The HTTP routes in router.py call these functions.

Module A never creates sessions or sets cookies (Section 8 of the requirements).
A successful login returns an AuthResult, and Module B turns it into a session."""
import os
import re
import secrets
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, passwords, ratelimit, totp, webauthn_service
from .clock import clock
from .errors import REGISTRATION_FAILED, AuthError, login_failed, too_many
from .models import Challenge, Passkey, TotpSecret, User
from .policy import current_policy

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,64}$")


@dataclass
class AuthResult:
    user_id: int
    username: str
    methods: list[str]          # e.g. ["password"], ["password", "totp"], ["passkey"]
    user_verified: bool = False
    server_ms: float = 0.0      # filled in by the router


@dataclass
class TotpRequired:
    pending_id: str
    next: str = field(default="totp")


# ---------- FR-A1 / FR-A2: registration ----------

def register(db: Session, username: str, password: str) -> User:
    username = (username or "").strip().lower()
    if not USERNAME_RE.match(username) or passwords.check_password_rules(password or ""):
        raise AuthError(400, REGISTRATION_FAILED)
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise AuthError(400, REGISTRATION_FAILED)
    user = User(
        username=username,
        password_hash=passwords.hash_password(password),
        webauthn_user_handle=os.urandom(32),
        created_at=clock.now(),
    )
    db.add(user)
    db.commit()
    return user


def get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise AuthError(401, "Not authenticated.")
    return user


def _find_user(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == (username or "").strip().lower()))


# ---------- FR-A2 / FR-A4 / FR-A7 / FR-A11: password login ----------

def login_password(db: Session, username: str, password: str, ip: str) -> AuthResult | TotpRequired:
    username = (username or "").strip().lower()
    if ratelimit.is_blocked(db, username, ip):
        raise too_many()

    user = _find_user(db, username)
    ok = passwords.verify_password(user.password_hash if user else None, password or "")
    if not ok:
        ratelimit.record_failure(db, username, ip)
        raise login_failed()

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
        db.commit()

    policy = current_policy()
    has_totp = user.totp is not None and user.totp.active
    method = "password+totp" if has_totp else "password"
    if not policy.allows("login", method):
        raise AuthError(403, "This login method is not allowed by the current policy.")

    if has_totp:
        pending = Challenge(
            id=secrets.token_urlsafe(32),
            ceremony="totp_pending",
            user_id=user.id,
            challenge=b"",
            expires_at=clock.now() + config.PENDING_LOGIN_TTL_SECONDS,
        )
        db.add(pending)
        db.commit()
        return TotpRequired(pending_id=pending.id)

    return AuthResult(user_id=user.id, username=user.username, methods=["password"])


def login_totp(db: Session, pending_id: str, code: str, ip: str) -> AuthResult:
    pending = db.get(Challenge, pending_id or "")
    if pending is None or pending.ceremony != "totp_pending" or pending.used or clock.now() > pending.expires_at:
        raise login_failed()
    user = db.get(User, pending.user_id)
    if ratelimit.is_blocked(db, user.username, ip):
        raise too_many()
    secret_row = user.totp
    if secret_row is None or not secret_row.active:
        raise login_failed()

    step = totp.match_step(totp.decrypt_secret(secret_row.secret_encrypted), (code or "").strip(), clock.now(), secret_row.last_used_step)
    if step is None:
        ratelimit.record_failure(db, user.username, ip)
        raise login_failed()

    secret_row.last_used_step = step
    pending.used = True
    db.commit()
    return AuthResult(user_id=user.id, username=user.username, methods=["password", "totp"])


# ---------- FR-A3: TOTP enrolment ----------

def totp_enroll_start(db: Session, user: User) -> dict:
    if user.totp is not None and user.totp.active:
        raise AuthError(400, "TOTP is already active. Remove it first to enrol a new one.")
    secret = totp.new_secret()
    if user.totp is None:
        user.totp = TotpSecret(secret_encrypted=totp.encrypt_secret(secret), active=False, last_used_step=-1)
    else:
        user.totp.secret_encrypted = totp.encrypt_secret(secret)
        user.totp.last_used_step = -1
    db.commit()
    uri = totp.provisioning_uri(secret, user.username)
    return {"otpauth_uri": uri, "qr_png_base64": totp.qr_png_base64(uri)}


def totp_enroll_confirm(db: Session, user: User, code: str) -> None:
    row = user.totp
    if row is None or row.active:
        raise AuthError(400, "No TOTP enrolment in progress.")
    step = totp.match_step(totp.decrypt_secret(row.secret_encrypted), (code or "").strip(), clock.now(), row.last_used_step)
    if step is None:
        raise AuthError(400, "Code is not correct.")
    row.active = True
    row.last_used_step = step  # the confirmation code cannot be used to log in
    db.commit()


# ---------- FR-A5: passkeys ----------

def passkey_register_options(db: Session, user: User) -> tuple[dict, str]:
    return webauthn_service.register_options(db, user, current_policy().rule("add_credential").require_uv)


def passkey_register_verify(db: Session, user: User, challenge_id: str, credential: dict, name: str) -> Passkey:
    return webauthn_service.register_verify(
        db, user, challenge_id, credential, name, current_policy().rule("add_credential").require_uv
    )


def passkey_login_options(db: Session, username: str | None) -> tuple[dict, str]:
    user = _find_user(db, username) if username else None
    # An unknown username gets usernameless options, so the response does not reveal whether it exists
    return webauthn_service.login_options(db, user, current_policy().rule("login").require_uv)


def passkey_login_verify(db: Session, challenge_id: str, credential: dict, ip: str) -> AuthResult:
    policy = current_policy()
    if ratelimit.is_blocked(db, "(passkey)", ip):
        raise too_many()
    if not policy.allows("login", "passkey"):
        raise AuthError(403, "This login method is not allowed by the current policy.")
    try:
        passkey, uv = webauthn_service.login_verify(db, challenge_id, credential, policy.rule("login").require_uv)
    except AuthError:
        ratelimit.record_failure(db, "(passkey)", ip)
        raise
    user = db.get(User, passkey.user_id)
    return AuthResult(user_id=user.id, username=user.username, methods=["passkey"], user_verified=uv)


# ---------- FR-A6: credential management ----------

def list_credentials(user: User) -> dict:
    return {
        "password": user.password_hash is not None,
        "totp": user.totp is not None and user.totp.active,
        "passkeys": [
            {"id": p.id, "name": p.name, "created_at": p.created_at, "last_used_at": p.last_used_at}
            for p in user.passkeys
        ],
    }


def _primary_count(user: User) -> int:
    """Password and passkeys can each log in on their own. TOTP cannot, so it does not count."""
    return (1 if user.password_hash is not None else 0) + len(user.passkeys)


def _get_own_passkey(db: Session, user: User, passkey_id: int) -> Passkey:
    p = db.get(Passkey, passkey_id)
    if p is None or p.user_id != user.id:
        raise AuthError(404, "Credential not found.")
    return p


def rename_passkey(db: Session, user: User, passkey_id: int, name: str) -> None:
    p = _get_own_passkey(db, user, passkey_id)
    name = (name or "").strip()
    if not 1 <= len(name) <= 64:
        raise AuthError(400, "Name must be 1 to 64 characters.")
    p.name = name
    db.commit()


def delete_passkey(db: Session, user: User, passkey_id: int) -> None:
    p = _get_own_passkey(db, user, passkey_id)
    if _primary_count(user) <= 1:
        raise AuthError(400, "You cannot delete your last credential.")
    db.delete(p)
    db.commit()
    db.refresh(user)


def delete_password(db: Session, user: User) -> None:
    if user.password_hash is None:
        raise AuthError(404, "Credential not found.")
    if _primary_count(user) <= 1:
        raise AuthError(400, "You cannot delete your last credential.")
    user.password_hash = None
    if user.totp is not None:  # TOTP is a second factor for the password, so it goes too
        db.delete(user.totp)
    db.commit()
    db.refresh(user)


def delete_totp(db: Session, user: User) -> None:
    if user.totp is None:
        raise AuthError(404, "Credential not found.")
    db.delete(user.totp)
    db.commit()
    db.refresh(user)
