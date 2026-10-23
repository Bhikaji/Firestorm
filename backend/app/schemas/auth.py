from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    # Not EmailStr: internal deployments use reserved TLDs such as .local that
    # strict RFC validators reject. Formatting is still length/character bound.
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=1, max_length=200)
    mfa_code: str | None = Field(default=None, max_length=10)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    must_change_password: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=4096)


class UserOut(ORMModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool
    last_login_at: datetime | None = None
    created_at: datetime


class MeOut(BaseModel):
    user: UserOut
    permissions: list[str]


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    role: str = Field(pattern="^(viewer|analyst|responder|admin)$")
    password: str = Field(min_length=12, max_length=72)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=160)
    role: str | None = Field(default=None, pattern="^(viewer|analyst|responder|admin)$")
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=12, max_length=72)


class MfaSetupOut(BaseModel):
    secret: str
    provisioning_uri: str


class MfaEnable(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class MfaDisable(BaseModel):
    password: str = Field(min_length=1, max_length=200)


class LoginAttemptOut(ORMModel):
    id: str
    email: str
    success: bool
    reason: str | None
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
