import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.db.base import Base


class AuditEvent(StrEnum):
    REGISTER = "register"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    REFRESH_REUSE = "refresh_reuse"
    LOGOUT = "logout"
    LOGOUT_ALL = "logout_all"
    SESSION_REVOKED = "session_revoked"
    PASSWORD_CHANGED = "password_changed"
    USER_DEACTIVATED = "user_deactivated"
    ROLE_CHANGED = "role_changed"


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    event: Mapped[str] = mapped_column(String(50), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    email: Mapped[str | None] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[str | None] = mapped_column(String(255))
