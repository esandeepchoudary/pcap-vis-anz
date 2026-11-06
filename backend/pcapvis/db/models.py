"""Database models. M0: users and login sessions. Engagement data arrives in M2."""
import enum
from datetime import datetime

from sqlalchemy import Boolean, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pcapvis.db.base import Base, UTCDateTime, utcnow


class Role(enum.StrEnum):
    """Ordered from most to least privileged."""

    admin = "admin"  # manage users and all engagements
    lead = "lead"  # manage engagements and their members
    consultant = "consultant"  # edit engagements they belong to
    viewer = "viewer"  # read-only

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    def at_least(self, other: "Role") -> bool:
        return self.rank >= other.rank


_ROLE_RANK = {Role.viewer: 0, Role.consultant: 1, Role.lead: 2, Role.admin: 3}


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    # NULL for the built-in laptop-mode user, which never logs in with a password.
    password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role", native_enum=False, length=16))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    sessions: Mapped[list["AuthSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class AuthSession(Base):
    """A login session. Only the SHA-256 of the token is stored, never the token itself."""

    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    user_agent: Mapped[str] = mapped_column(String(256), default="")

    user: Mapped[User] = relationship(back_populates="sessions")
