"""Repository URL validation.

The only accepted form is  https://github.com/<owner>/<repo>  (an optional
trailing slash or ".git" is tolerated and removed). Everything the platform
later fetches is built from the validated owner and repository names, never
from the raw string, which is what prevents SSRF through this input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 200
ALLOWED_HOSTS = {"github.com", "www.github.com"}

_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_FORBIDDEN = re.compile(r"[\s\\@\x00-\x1f\x7f]")


class InvalidRepositoryURL(ValueError):
    """The URL is not an acceptable GitHub repository URL."""


@dataclass(frozen=True)
class RepositoryRef:
    host: str
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def key(self) -> str:
        """Case-insensitive identity (GitHub names are case-insensitive)."""
        return f"{self.host}/{self.owner}/{self.name}".lower()

    @property
    def url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.name}"


def parse_github_url(raw: str) -> RepositoryRef:
    if not isinstance(raw, str):
        raise InvalidRepositoryURL("repository URL must be a string")
    url = raw.strip()
    if not url:
        raise InvalidRepositoryURL("repository URL is required")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidRepositoryURL("repository URL is too long")
    if _FORBIDDEN.search(url):
        raise InvalidRepositoryURL("repository URL contains forbidden characters")

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise InvalidRepositoryURL("repository URL is malformed") from exc

    if parts.scheme.lower() != "https":
        raise InvalidRepositoryURL("repository URL must start with https://")
    if parts.username is not None or parts.password is not None:
        raise InvalidRepositoryURL("repository URL must not contain credentials")
    if port is not None:
        raise InvalidRepositoryURL("repository URL must not specify a port")
    if (parts.hostname or "").lower() not in ALLOWED_HOSTS:
        raise InvalidRepositoryURL("only github.com repositories are supported")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise InvalidRepositoryURL("repository URL must not contain a query or fragment")

    path = parts.path
    if "%" in path:
        raise InvalidRepositoryURL("repository URL must not contain encoded characters")
    segments = path.strip("/").split("/") if path.strip("/") else []
    if len(segments) != 2:
        raise InvalidRepositoryURL("repository URL must look like https://github.com/owner/repository")

    owner, name = segments
    if name.lower().endswith(".git"):
        name = name[:-4]
    if not _OWNER.match(owner):
        raise InvalidRepositoryURL("repository owner is not a valid GitHub name")
    if not _REPO.match(name) or name in {".", ".."}:
        raise InvalidRepositoryURL("repository name is not a valid GitHub name")

    return RepositoryRef(host="github.com", owner=owner, name=name)
