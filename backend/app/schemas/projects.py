"""Project schemas."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import StrictModel
from app.security.url_validation import MAX_URL_LENGTH, parse_github_url

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    repository_url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)
    description: str = Field(default="", max_length=1000)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if _CONTROL.search(value):
            raise ValueError("name must not contain control characters")
        return value

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
            raise ValueError("description must not contain control characters")
        return value

    @field_validator("repository_url")
    @classmethod
    def _url(cls, value: str) -> str:
        # Raises InvalidRepositoryURL (a ValueError) with a user-facing reason.
        return parse_github_url(value).url


class RepositoryOut(BaseModel):
    host: str
    owner: str
    name: str
    full_name: str
    url: str
    metadata_status: str
    metadata_error: str | None = None
    metadata_fetched_at: datetime | None = None
    metadata: dict[str, Any] | None = None


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str
    repository_url: str
    status: str
    default_branch: str | None
    languages: list[str]
    created_at: datetime
    updated_at: datetime
    last_analysis: datetime | None
    latest_snapshot_id: str | None = None
    repository: RepositoryOut | None


class ProjectList(BaseModel):
    items: list[ProjectOut]
    total: int
    skip: int
    limit: int
