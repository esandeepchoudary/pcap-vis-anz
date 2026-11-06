"""Database models: users and sessions (M0); engagements, captures, audit (M2); assets (M3)."""

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
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

    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class AuthSession(Base):
    """A login session. Only the SHA-256 of the token is stored, never the token itself."""

    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    user_agent: Mapped[str] = mapped_column(String(256), default="")

    user: Mapped[User] = relationship(back_populates="sessions")


class MemberRole(enum.StrEnum):
    """A user's role within one engagement. Ordered from most to least privileged."""

    lead = "lead"  # settings, members, delete
    editor = "editor"  # upload captures, edit assets and findings
    viewer = "viewer"  # read-only

    @property
    def rank(self) -> int:
        return {MemberRole.viewer: 0, MemberRole.editor: 1, MemberRole.lead: 2}[self]

    def at_least(self, other: "MemberRole") -> bool:
        return self.rank >= other.rank


# Highest engagement role each global role may hold.
MAX_MEMBER_ROLE = {
    Role.admin: MemberRole.lead,
    Role.lead: MemberRole.lead,
    Role.consultant: MemberRole.editor,
    Role.viewer: MemberRole.viewer,
}


class EngagementStatus(enum.StrEnum):
    active = "active"
    archived = "archived"


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    client: Mapped[str] = mapped_column(String(200), default="")
    site: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus, name="engagement_status", native_enum=False, length=16),
        default=EngagementStatus.active,
    )
    # Quick look: a personal, throw-away engagement for analysing a capture without setting one up.
    is_quicklook: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # Bumped on every change to the engagement or its captures; clients poll it for live updates.
    revision: Mapped[int] = mapped_column(Integer, default=0)

    members: Mapped[list["EngagementMember"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )
    capture_points: Mapped[list["CapturePoint"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", order_by="CapturePoint.name"
    )
    captures: Mapped[list["Capture"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", order_by="Capture.id"
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan", passive_deletes=True
    )

    def touch(self) -> None:
        self.revision = (self.revision or 0) + 1
        self.updated_at = utcnow()


class EngagementMember(Base):
    __tablename__ = "engagement_members"

    engagement_id: Mapped[int] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    role: Mapped[MemberRole] = mapped_column(
        Enum(MemberRole, name="member_role", native_enum=False, length=16)
    )
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="members")
    user: Mapped[User] = relationship()


class CapturePoint(Base):
    """Where a capture was taken (switch SPAN port, TAP, segment)."""

    __tablename__ = "capture_points"
    __table_args__ = (UniqueConstraint("engagement_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="capture_points")


class CaptureStatus(enum.StrEnum):
    queued = "queued"
    processing = "processing"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"


class Capture(Base):
    __tablename__ = "captures"
    __table_args__ = (UniqueConstraint("engagement_id", "sha256"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    capture_point_id: Mapped[int | None] = mapped_column(
        ForeignKey("capture_points.id", ondelete="SET NULL"), nullable=True
    )
    file_name: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[CaptureStatus] = mapped_column(
        Enum(CaptureStatus, name="capture_status", native_enum=False, length=16),
        default=CaptureStatus.queued,
        index=True,
    )
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    uploaded_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Job lease: which worker holds it and when it last reported in (stale leases are re-queued).
    worker: Mapped[str | None] = mapped_column(String(64), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    engine_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Small summary for lists (packets, hosts, findings by severity…); the full result is a file.
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # When this capture's hosts were merged into the engagement's assets (NULL = not yet).
    assets_merged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    engagement: Mapped[Engagement] = relationship(back_populates="captures")
    capture_point: Mapped[CapturePoint | None] = relationship()


class AuditEvent(Base):
    """Who did what, when, at engagement level. Per-field asset history is in ``AssetChange``."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    engagement_id: Mapped[int | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AssetOrigin(enum.StrEnum):
    observed = "observed"  # created from traffic
    manual = "manual"  # added by a consultant (e.g. a firewall never seen on the wire)


class Asset(Base):
    """One device in an engagement, merged across captures.

    ``auto`` holds the values derived from traffic for editable fields; ``overrides`` holds manual
    values ({field: {value, reason, by, at}}). The effective value is the override when present.
    Edits live here, never on a capture, so new captures merge in without losing work.
    """

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    origin: Mapped[AssetOrigin] = mapped_column(
        Enum(AssetOrigin, name="asset_origin", native_enum=False, length=16), default=AssetOrigin.observed
    )
    macs: Mapped[list] = mapped_column(JSON, default=list)
    ips: Mapped[list] = mapped_column(JSON, default=list)
    # Identifiers a consultant entered by hand (kept even when no capture shows them).
    declared: Mapped[dict] = mapped_column(JSON, default=dict)
    auto: Mapped[dict] = mapped_column(JSON, default=dict)
    observed: Mapped[dict] = mapped_column(JSON, default=dict)
    overrides: Mapped[dict] = mapped_column(JSON, default=dict)
    # Optimistic lock for manual edits; merges from captures don't bump it.
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    engagement: Mapped[Engagement] = relationship(back_populates="assets")
    sightings: Mapped[list["AssetSighting"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", passive_deletes=True
    )


class AssetSighting(Base):
    """A host as one capture saw it, linked to the asset it was merged into (provenance)."""

    __tablename__ = "asset_sightings"
    __table_args__ = (UniqueConstraint("capture_id", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    host: Mapped[dict] = mapped_column(JSON)  # the engine's Host, as serialised

    asset: Mapped[Asset] = relationship(back_populates="sightings")
    capture: Mapped[Capture] = relationship()


class AssetChange(Base):
    """Per-field asset history: who changed what, when, from what, to what, and why."""

    __tablename__ = "asset_changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor: Mapped[str] = mapped_column(String(255), default="")  # username or "capture <name>"
    kind: Mapped[str] = mapped_column(String(16))  # created | override | reset | auto | import
    field: Mapped[str | None] = mapped_column(String(32), nullable=True)
    old: Mapped[object | None] = mapped_column(JSON, nullable=True)
    new: Mapped[object | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")


class AssetLink(Base):
    """Traffic one capture saw from one asset (client) to another (server) over one protocol (M4)."""

    __tablename__ = "asset_links"
    __table_args__ = (UniqueConstraint("capture_id", "src_asset_id", "dst_asset_id", "protocol"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    src_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    dst_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(64))
    ports: Mapped[list] = mapped_column(JSON, default=list)  # server ports, e.g. ["tcp/502"]
    flows: Mapped[int] = mapped_column(Integer, default=0)
    packets: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    ot_reads: Mapped[int] = mapped_column(Integer, default=0)
    ot_writes: Mapped[int] = mapped_column(Integer, default=0)
    ot_errors: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_seen: Mapped[float | None] = mapped_column(Float, nullable=True)


class AssetOtOp(Base):
    """OT commands one capture saw between two assets, grouped by function (M4 command log)."""

    __tablename__ = "asset_ot_ops"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)
    src_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    dst_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(64))
    function: Mapped[str] = mapped_column(String(128))
    function_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(8))  # read | write | error | other
    count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    sample: Mapped[str] = mapped_column(String(300), default="")  # e.g. register range or block name


class Zone(Base):
    """An IEC 62443 zone. Assets join a zone by name (the asset's ``zone`` field) (M6)."""

    __tablename__ = "zones"
    __table_args__ = (UniqueConstraint("engagement_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    purdue_level: Mapped[float | None] = mapped_column(Float, nullable=True)
    security_level: Mapped[int | None] = mapped_column(Integer, nullable=True)  # SL-T 1-4
    description: Mapped[str] = mapped_column(Text, default="")
    x: Mapped[float | None] = mapped_column(Float, nullable=True)  # position on the architecture diagram
    y: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Conduit(Base):
    """An approved path between two zones, with the protocols allowed through it (M6)."""

    __tablename__ = "conduits"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id", ondelete="CASCADE"), index=True)
    zone_a_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"))
    zone_b_id: Mapped[int] = mapped_column(ForeignKey("zones.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(100), default="")
    allowed: Mapped[list] = mapped_column(JSON, default=list)  # protocol names; empty = anything
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
