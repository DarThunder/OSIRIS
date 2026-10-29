# OSIRIS - Personal Auth Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field, StringConstraints, model_validator

def _norm(v):
    return v.strip().lower() if isinstance(v, str) else v

Username = Annotated[str, BeforeValidator(_norm), StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.@-]{2,63}$")]
TenantId = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9_.-]{1,64}$")]
Role = Annotated[str, BeforeValidator(_norm), StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]
NewPassword = Annotated[str, StringConstraints(min_length=10, max_length=128)]

class LoginRequest(BaseModel):
    username: Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=1, max_length=128)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    audience: Annotated[str, StringConstraints(min_length=1, max_length=128)]

class RegisterRequest(BaseModel):
    username: Username
    password: NewPassword
    invite_code: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)] | None = None

    @model_validator(mode="after")
    def _password_not_username(self):
        if self.password.strip().lower() == self.username:
            raise ValueError("la contraseña no puede ser igual al nombre de usuario")
        return self

class CreateInviteRequest(BaseModel):
    tenant_id: TenantId | None = None
    roles: list[Role] = Field(default_factory=list, max_length=16)
    max_uses: int = Field(default=1, ge=1, le=1000)
    expires_in_seconds: int = Field(default=7 * 24 * 3600, ge=60, le=90 * 24 * 3600)

class InviteOut(BaseModel):
    id: str
    tenant_id: str | None
    roles: list[str]
    max_uses: int
    uses: int
    expires_at: int
    revoked_at: int | None
    created_at: int

class InviteCreated(InviteOut):
    code: str

class RefreshRequest(BaseModel):
    refresh_token: Annotated[str, StringConstraints(min_length=1, max_length=512)]

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    audience: str

class CreateUserRequest(BaseModel):
    username: Username
    password: NewPassword
    tenant_id: TenantId
    roles: list[Role] = Field(default_factory=list, max_length=16)

class UpdateUserRequest(BaseModel):
    tenant_id: TenantId | None = None
    roles: list[Role] | None = Field(default=None, max_length=16)
    is_active: bool | None = None

class AdminResetPasswordRequest(BaseModel):
    new_password: NewPassword

class ChangePasswordRequest(BaseModel):
    current_password: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    new_password: NewPassword

class UserOut(BaseModel):
    id: str
    username: str
    tenant_id: str
    roles: list[str]
    is_active: bool
    created_at: int