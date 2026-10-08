"""Authentication schemas."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.common import StrictModel
from app.security.passwords import MAX_PASSWORD_LENGTH, password_problems

_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def normalise_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not _EMAIL.match(value) or ".." in value:
        raise ValueError("not a valid email address")
    return value


class RegisterRequest(StrictModel):
    # Passwords are not trimmed: leading or trailing spaces are significant.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    email: str = Field(max_length=254)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)
    full_name: str = Field(min_length=1, max_length=100)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        return normalise_email(value)

    @field_validator("full_name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value or _CONTROL.search(value):
            raise ValueError("name is required and must not contain control characters")
        return value

    @field_validator("password")
    @classmethod
    def _password(cls, value: str) -> str:
        problems = password_problems(value)
        if problems:
            raise ValueError("password " + "; ".join(problems))
        return value


class LoginRequest(StrictModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        # Login must not explain why an address is unacceptable; just normalise.
        return value.strip().lower()


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut
