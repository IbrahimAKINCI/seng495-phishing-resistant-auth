from sqlalchemy import Boolean, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.auth.db import Base


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # SHA-256 of the cookie value. The cookie value itself is never stored, so a
    # copy of the database does not give anyone a working session.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # short id shown in the session list, so a session can be ended by id
    public_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    methods: Mapped[str] = mapped_column(String(64))  # how the user logged in, e.g. "password,totp"
    created_at: Mapped[float] = mapped_column(Float)
    last_seen_at: Mapped[float] = mapped_column(Float)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(256), default="")
