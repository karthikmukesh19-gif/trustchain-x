"""GitHub API client: repository metadata, head commit, file listing and file contents.

Safety properties:

* Every URL is built from the configured API host plus names that passed
  security.url_validation, or from commit / blob ids that are checked to be
  hexadecimal. Repository content never contributes to a URL.
* Redirects are not followed.
* Every response is read with a size cap and treated as untrusted: fields are
  type-checked and length-limited before use.
* File contents are verified against the git blob id from the file listing.
* Nothing is written to disk and nothing from the repository is executed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from app.config.settings import Settings
from app.security.url_validation import RepositoryRef

USER_AGENT = "TrustChain-X/0.2"
_HEX = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/@+-]{1,255}$")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_PATH_LENGTH = 1024
RETRY_STATUS = {500, 502, 503, 504}


class GitHubUnavailable(Exception):
    """A GitHub request failed. `reason` is safe to show to the user; `code` is machine-readable."""

    def __init__(self, reason: str, code: str = "GITHUB_ERROR", retry_at: datetime | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code
        self.retry_at = retry_at


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
        raise GitHubUnavailable("GitHub returned an unexpected response", "BAD_RESPONSE")
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


def safe_repository_path(path: Any) -> bool:
    """A path from the file listing is kept only if it is a plain relative path inside the repository."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LENGTH:
        return False
    if path.startswith(("/", "~")) or "\\" in path or "\x00" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return False
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    parts = path.split("/")
    return all(part not in {"", ".", ".."} for part in parts) and not (len(parts[0]) == 2 and parts[0][1] == ":")


def git_blob_id(content: bytes, sha256: bool = False) -> str:
    digest = hashlib.sha256() if sha256 else hashlib.sha1()  # noqa: S324 - git object ids, not a security control
    digest.update(b"blob " + str(len(content)).encode() + b"\x00" + content)
    return digest.hexdigest()


@dataclass
class GitHubSession:
    """One analysis' worth of requests over a single connection pool."""

    client: httpx.Client
    api: str
    sleep: Callable[[float], None] = time.sleep
    requests_made: int = 0
    rate_remaining: int | None = None

    def _get(self, path: str, max_bytes: int = MAX_JSON_BYTES, params: dict[str, str] | None = None) -> Any:
        url = f"{self.api}{path}"
        response_status, body, headers = 0, b"", {}
        for attempt in range(3):
            try:
                self.requests_made += 1
                with self.client.stream("GET", url, params=params) as response:
                    response_status, headers = response.status_code, response.headers
                    chunks, received = [], 0
                    for chunk in response.iter_bytes():
                        received += len(chunk)
                        if received > max_bytes:
                            raise GitHubUnavailable("GitHub returned more data than the configured limit allows", "RESPONSE_TOO_LARGE")
                        chunks.append(chunk)
                    body = b"".join(chunks)
            except httpx.TimeoutException as exc:
                if attempt == 2:
                    raise GitHubUnavailable("GitHub did not respond in time", "TIMEOUT") from exc
                self.sleep(0.5 * (attempt + 1))
                continue
            except httpx.HTTPError as exc:
                if attempt == 2:
                    raise GitHubUnavailable("GitHub could not be reached", "UNREACHABLE") from exc
                self.sleep(0.5 * (attempt + 1))
                continue
            if response_status in RETRY_STATUS and attempt < 2:
                self.sleep(0.5 * (attempt + 1))
                continue
            break

        remaining = headers.get("x-ratelimit-remaining")
        if remaining is not None and remaining.isdigit():
            self.rate_remaining = int(remaining)
        if response_status == 200:
            try:
                return json.loads(body)
            except (ValueError, RecursionError) as exc:
                raise GitHubUnavailable("GitHub returned an unexpected response", "BAD_RESPONSE") from exc
        self._raise_for(response_status, headers, body)

    @staticmethod
    def _raise_for(status: int, headers: Any, body: bytes) -> None:
        if status == 404:
            raise GitHubUnavailable("Repository not found on GitHub, or it is private", "NOT_FOUND")
        if status in (301, 302, 307, 308):
            raise GitHubUnavailable("Repository has been moved or renamed", "MOVED")
        if status == 401:
            raise GitHubUnavailable("GitHub rejected the configured token", "BAD_TOKEN")
        if status == 409:
            raise GitHubUnavailable("The repository is empty: it has no commits to analyse", "EMPTY_REPOSITORY")
        limited = status == 429 or (status == 403 and (headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers
                                                      or b"rate limit" in body[:2000].lower()))
        if limited:
            retry_at = None
            reset = headers.get("x-ratelimit-reset", "")
            if reset.isdigit():
                retry_at = datetime.fromtimestamp(int(reset), tz=timezone.utc)
            elif headers.get("retry-after", "").isdigit():
                retry_at = datetime.fromtimestamp(time.time() + int(headers["retry-after"]), tz=timezone.utc)
            when = f" It resets at {retry_at:%H:%M} UTC." if retry_at else ""
            raise GitHubUnavailable(
                f"GitHub API rate limit reached.{when} Set GITHUB_TOKEN to raise the limit from 60 to 5000 requests per hour.",
                "RATE_LIMITED", retry_at)
        if status == 403:
            raise GitHubUnavailable("GitHub denied access to this repository", "DENIED")
        raise GitHubUnavailable(f"GitHub returned HTTP {status}", "GITHUB_ERROR")

    # -- endpoints ------------------------------------------------------------

    def repository(self, ref: RepositoryRef) -> dict[str, Any]:
        return parse_repository_payload(self._get(f"/repos/{ref.owner}/{ref.name}", 2 * 1024 * 1024))

    def head_commit(self, ref: RepositoryRef, branch: str) -> dict[str, Any]:
        """The commit a branch currently points at."""
        if not _BRANCH.match(branch) or ".." in branch:
            raise GitHubUnavailable("The repository's default branch has an unsupported name", "BAD_RESPONSE")
        payload = self._get(f"/repos/{ref.owner}/{ref.name}/commits/{branch}", 4 * 1024 * 1024)
        commit = payload.get("commit") if isinstance(payload, dict) else None
        sha = payload.get("sha") if isinstance(payload, dict) else None
        tree = commit.get("tree", {}).get("sha") if isinstance(commit, dict) and isinstance(commit.get("tree"), dict) else None
        if not isinstance(sha, str) or not _HEX.match(sha) or not isinstance(tree, str) or not _HEX.match(tree):
            raise GitHubUnavailable("GitHub returned an unexpected commit response", "BAD_RESPONSE")
        committer = commit.get("committer") if isinstance(commit.get("committer"), dict) else {}
        return {
            "commit_sha": sha,
            "tree_sha": tree,
            "committed_at": _time(committer.get("date")),
            "message": _text(str(commit.get("message", "")).splitlines()[0] if commit.get("message") else None, 200),
        }

    def tree(self, ref: RepositoryRef, tree_sha: str) -> dict[str, Any]:
        """The complete file listing of a commit. Entries with unsafe paths are dropped and counted."""
        if not _HEX.match(tree_sha):
            raise GitHubUnavailable("Invalid tree id", "BAD_RESPONSE")
        payload = self._get(f"/repos/{ref.owner}/{ref.name}/git/trees/{tree_sha}", params={"recursive": "1"})
        entries = payload.get("tree") if isinstance(payload, dict) else None
        if not isinstance(entries, list):
            raise GitHubUnavailable("GitHub returned an unexpected file listing", "BAD_RESPONSE")
        files: list[dict[str, Any]] = []
        rejected = symlinks = submodules = 0
        for entry in entries:
            if not isinstance(entry, dict):
                rejected += 1
                continue
            kind, mode, sha, path = entry.get("type"), entry.get("mode"), entry.get("sha"), entry.get("path")
            if kind == "tree":
                continue
            if kind == "commit":
                submodules += 1
                continue
            if kind != "blob" or not isinstance(sha, str) or not _HEX.match(sha) or not safe_repository_path(path):
                rejected += 1
                continue
            if mode == "120000":
                symlinks += 1   # symbolic links are never followed
                continue
            files.append({"path": path, "size": _count(entry.get("size")) or 0, "sha": sha})
        return {
            "files": files, "truncated": payload.get("truncated") is True, "rejected_paths": rejected,
            "symlinks": symlinks, "submodules": submodules, "entries": len(entries),
        }

    def blob(self, ref: RepositoryRef, sha: str, max_bytes: int) -> bytes:
        """One file's content, verified against its git blob id."""
        if not _HEX.match(sha):
            raise GitHubUnavailable("Invalid blob id", "BAD_RESPONSE")
        payload = self._get(f"/repos/{ref.owner}/{ref.name}/git/blobs/{sha}", max_bytes=max_bytes * 2 + 4096)
        if not isinstance(payload, dict) or payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
            raise GitHubUnavailable("GitHub returned an unexpected file response", "BAD_RESPONSE")
        try:
            content = base64.b64decode(payload["content"], validate=False)
        except (binascii.Error, ValueError) as exc:
            raise GitHubUnavailable("GitHub returned an undecodable file", "BAD_RESPONSE") from exc
        if len(content) > max_bytes:
            raise GitHubUnavailable("File is larger than the configured limit", "RESPONSE_TOO_LARGE")
        if git_blob_id(content, sha256=len(sha) == 64) != sha:
            raise GitHubUnavailable("File content does not match its git object id", "INTEGRITY_MISMATCH")
        return content


@dataclass
class GitHubClient:
    settings: Settings
    transport: httpx.BaseTransport | None = None
    sleep: Callable[[float], None] = field(default=time.sleep)

    def _client(self) -> httpx.Client:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        return httpx.Client(
            transport=self.transport, timeout=self.settings.github_timeout_seconds, follow_redirects=False, headers=headers,
        )

    def session(self) -> "_SessionContext":
        return _SessionContext(self)

    def fetch_repository(self, ref: RepositoryRef) -> dict[str, Any]:
        with self.session() as session:
            return session.repository(ref)


class _SessionContext:
    def __init__(self, owner: GitHubClient) -> None:
        self._owner = owner
        self._client: httpx.Client | None = None

    def __enter__(self) -> GitHubSession:
        self._client = self._owner._client()
        return GitHubSession(self._client, self._owner.settings.github_api_url, self._owner.sleep)

    def __exit__(self, *_exc: object) -> None:
        if self._client is not None:
            self._client.close()
