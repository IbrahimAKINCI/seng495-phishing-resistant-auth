from sqlalchemy import Boolean, Float, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # NULL when the user removed the password and logs in with passkeys only
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # random handle sent to authenticators instead of the database id
    webauthn_user_handle: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    created_at: Mapped[float] = mapped_column(Float)

    totp: Mapped["TotpSecret | None"] = relationship(back_populates="user", cascade="all, delete-orphan")
    passkeys: Mapped[list["Passkey"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class TotpSecret(Base):
    __tablename__ = "totp_secrets"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    secret_encrypted: Mapped[bytes] = mapped_column(LargeBinary)  # nonce + AES-GCM ciphertext
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_step: Mapped[int] = mapped_column(Integer, default=-1)  # FR-A4: each code once

    user: Mapped[User] = relationship(back_populates="totp")


class Passkey(Base):
    __tablename__ = "passkeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, index=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(64))
    aaguid: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[float] = mapped_column(Float)
    last_used_at: Mapped[float | None] = mapped_column(Float, nullable=True)

    user: Mapped[User] = relationship(back_populates="passkeys")


class Challenge(Base):
    """Server-side record of every challenge and pending login (Section 4.2 checks 1-3)."""

    __tablename__ = "challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # "registration", "authentication" or "totp_pending"
    ceremony: Mapped[str] = mapped_column(String(32))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    expires_at: Mapped[float] = mapped_column(Float)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class FailedAttempt(Base):
    """FR-A7: one row per failed login, counted per account and per IP address."""

    __tablename__ = "failed_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    at: Mapped[float] = mapped_column(Float, index=True)
