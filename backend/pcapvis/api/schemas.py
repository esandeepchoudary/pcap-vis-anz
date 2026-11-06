"""Request/response models. These feed OpenAPI, which generates the frontend's TypeScript types."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pcapvis.db.models import Role


class TsharkInfo(BaseModel):
    ok: bool
    path: str | None
    version: str | None
    min_version: str
    message: str


class SystemInfo(BaseModel):
    version: str
    mode: Literal["laptop", "server"]
    auth_required: bool
    tshark: TsharkInfo


class Health(BaseModel):
    status: Literal["ok"] = "ok"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    display_name: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    role: Role = Role.consultant
    display_name: str = Field(default="", max_length=128)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=1, max_length=1024)


class ErrorOut(BaseModel):
    detail: str


# ── Engagements (M2) ──────────────────────────────────────────────────────────

from pcapvis.db.models import CaptureStatus, EngagementStatus, MemberRole  # noqa: E402


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    client: str = Field(default="", max_length=200)
    site: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=10_000)


class EngagementUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    client: str | None = Field(default=None, max_length=200)
    site: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    status: EngagementStatus | None = None
    is_quicklook: Literal[False] | None = None  # promote a Quick look to a real engagement


class EngagementOut(BaseModel):
    id: int
    name: str
    client: str
    site: str
    description: str
    status: EngagementStatus
    is_quicklook: bool
    created_at: datetime
    updated_at: datetime
    revision: int
    my_role: MemberRole
    capture_count: int
    member_count: int


class MemberOut(BaseModel):
    user_id: int
    username: str
    display_name: str
    role: MemberRole
    global_role: Role
    max_role: MemberRole


class MemberSet(BaseModel):
    role: MemberRole


class DirectoryUser(BaseModel):
    id: int
    username: str
    display_name: str
    role: Role


class CapturePointIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=5000)


class CapturePointUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=5000)


class CapturePointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    created_at: datetime


class AuditEventOut(BaseModel):
    id: int
    at: datetime
    user: str | None
    action: str
    target: str
    details: dict | None


class CaptureOut(BaseModel):
    id: int
    engagement_id: int
    capture_point_id: int | None
    capture_point: str | None
    file_name: str
    size: int
    sha256: str
    status: CaptureStatus
    progress: float
    error: str | None
    uploaded_by: str | None
    uploaded_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    summary: dict | None


class CaptureUpdate(BaseModel):
    capture_point_id: int | None = None


class RevisionOut(BaseModel):
    revision: int
