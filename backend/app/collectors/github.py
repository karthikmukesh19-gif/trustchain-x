"""GitHub repository metadata client.

Only one request is made: GET {api}/repos/{owner}/{repo}. The path is built
from names that already passed security.url_validation, the host comes from
configuration, and redirects are not followed, so user input cannot steer the
request anywhere else. Every field of the response is treated as untrusted:
it is type-checked and length-limited before it is stored.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from app.config.settings import Settings
from app.security.url_validation import RepositoryRef

USER_AGENT = "TrustChain-X/0.1"


class GitHubUnavailable(Exception):
    """Metadata could not be obtained. `reason` is safe to show to the user."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _text(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_repository_payload(payload: Any) -> dict[str, Any]:
    """Extract the fields we keep from a GitHub repository response."""
    if not isinstance(payload, dict):
        raise GitHubUnavailable("GitHub returned an unexpected response")
    licence = payload.get("license")
    return {
        "github_id": _count(payload.get("id")),
        "description": _text(payload.get("description"), 1000),
        "default_branch": _text(payload.get("default_branch"), 255),
        "primary_language": _text(payload.get("language"), 50),
        "stars": _count(payload.get("stargazers_count")),
        "forks": _count(payload.get("forks_count")),
        "open_issues": _count(payload.get("open_issues_count")),
        "size_kb": _count(payload.get("size")),
        "archived": _flag(payload.get("archived")),
        "is_fork": _flag(payload.get("fork")),
        "visibility": _text(payload.get("visibility"), 20),
        "license": _text(licence.get("spdx_id"), 60) if isinstance(licence, dict) else None,
        "github_created_at": _time(payload.get("created_at")),
        "pushed_at": _time(payload.get("pushed_at")),
    }


@dataclass
class GitHubClient:
    settings: Settings
    transport: httpx.BaseTransport | None = None

    def fetch_repository(self, ref: RepositoryRef) -> dict[str, Any]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        url = f"{self.settings.github_api_url}/repos/{ref.owner}/{ref.name}"
        try:
            with httpx.Client(
                transport=self.transport,
                timeout=self.settings.github_timeout_seconds,
                follow_redirects=False,
                headers=headers,
            ) as client:
                response = client.get(url)
        except httpx.TimeoutException as exc:
            raise GitHubUnavailable("GitHub did not respond in time") from exc
        except httpx.HTTPError as exc:
            raise GitHubUnavailable("GitHub could not be reached") from exc

        status = response.status_code
        if status == 200:
            try:
                return parse_repository_payload(response.json())
            except ValueError as exc:
                raise GitHubUnavailable("GitHub returned an unexpected response") from exc
        if status == 404:
            raise GitHubUnavailable("Repository not found on GitHub, or it is private")
        if status in (301, 302, 307, 308):
            raise GitHubUnavailable("Repository has been moved or renamed")
        if status == 401:
            raise GitHubUnavailable("GitHub rejected the configured token")
        if status == 429 or (status == 403 and response.headers.get("x-ratelimit-remaining") == "0"):
            raise GitHubUnavailable("GitHub API rate limit reached")
        if status == 403:
            raise GitHubUnavailable("GitHub denied access to this repository")
        raise GitHubUnavailable(f"GitHub returned HTTP {status}")
