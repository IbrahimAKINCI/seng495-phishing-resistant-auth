from sqlalchemy import Boolean, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.auth.db import Base


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), index=True)  # codes are stored hashed (NFR-2)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class RecoveryRequest(Base):
    __tablename__ = "recovery_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64))  # given only to the person recovering
    created_at: Mapped[float] = mapped_column(Float)
    ready_at: Mapped[float] = mapped_column(Float)  # created_at + 24 hours (FR-B8)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending, cancelled, completed


class Notification(Base):
    """Stands in for the e-mail the owner would get (FR-B8). Shown in the client and
    also written to instance/notifications.log."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    at: Mapped[float] = mapped_column(Float)
    message: Mapped[str] = mapped_column(String(512))
