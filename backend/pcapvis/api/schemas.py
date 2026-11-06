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
