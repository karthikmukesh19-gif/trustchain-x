"""Rules that recognise security-relevant changes in a commit's files and added or removed lines.

Two kinds of evidence are kept apart:

  OBSERVED   a fact about the commit: this file was changed, this many lines were added
  INFERRED   a pattern in the diff text that usually means something (a command is run, a value looks like a secret)

A pattern match is a reason to look, never a verdict. Excerpts are stored
with anything secret-like masked, so the platform does not become a second
place where a leaked credential is kept.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

INDICATOR_TYPES = ("DEPENDENCY_CHANGE", "SECURITY_CONFIG_CHANGE", "AUTH_CHANGE", "NETWORK_BEHAVIOUR_CHANGE", "COMMAND_EXECUTION_PATTERN",
                   "SECRET_LIKE_PATTERN", "LARGE_CHANGESET", "UNUSUAL_CHANGE_PATTERN")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
OBSERVED, INFERRED = "OBSERVED", "INFERRED"
MAX_FINDINGS_PER_RULE = 5        # per file: one rule matching a hundred lines is one observation, not a hundred
MAX_FINDINGS = 200               # per commit
EXCERPT = 160

MANIFESTS = {"requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg", "package.json", "pom.xml", "build.gradle",
             "build.gradle.kts", "go.mod", "cargo.toml", "vcpkg.json", "conanfile.txt", "conanfile.py", "gemfile", "composer.json"}
LOCKFILES = {"pipfile.lock", "poetry.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "gradle.lockfile",
             "go.sum", "cargo.lock", "gemfile.lock", "composer.lock", "uv.lock"}
SOURCE_CONFIG = {".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", ".pypirc", "nuget.config", "settings.xml"}
_REQUIREMENTS = re.compile(r"^requirements[\w.-]*\.(txt|in)$")
_AUTH_PATH = re.compile(r"(auth|login|logout|password|passwd|credential|token|jwt|session|oauth|sso|permission|rbac|acl|2fa|mfa)", re.I)
_LOW_SIGNAL_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|docs?|examples?|fixtures|testdata)(/|$)|\.(md|rst|txt)$|(^|/)test_[^/]+$|[._]test\.", re.I)
_TEXT_ONLY = re.compile(r"\.(md|rst|txt|lock|sum|svg|map|min\.js|min\.css)$", re.I)

_SECRET_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"), "HIGH"),
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "HIGH"),
    ("private_key_block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "HIGH"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "HIGH"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "HIGH"),
    ("stripe_live_key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}"), "HIGH"),
    ("json_web_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "MEDIUM"),
)
_ASSIGNED_SECRET = re.compile(
    r"""(?ix)\b([\w.-]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|token)[\w.-]*)
        \s*[:=]\s*["']([^"'\s]{8,200})["']""")
_PLACEHOLDER = re.compile(r"(example|changeme|change_me|your[_-]|placeholder|dummy|sample|redacted|xxxx|\*\*\*|<[^>]+>|\$\{|\{\{|%\(|test|fake|none|null|todo)", re.I)

_COMMAND_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("decode_and_execute", re.compile(r"(exec|eval|system|popen|subprocess\.\w+|Function)\s*\(.{0,80}(b64decode|atob|fromhex|decompress|unhexlify)", re.I), "HIGH"),
    ("pipe_to_shell", re.compile(r"\b(curl|wget)\b[^|\n]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I), "HIGH"),
    ("encoded_powershell", re.compile(r"powershell(\.exe)?\s[^\n]{0,80}-e(nc|ncodedcommand)?\s", re.I), "HIGH"),
    ("shell_enabled", re.compile(r"\bshell\s*=\s*True\b"), "MEDIUM"),
    ("dynamic_evaluation", re.compile(r"(?<![\w.])(eval|exec)\s*\(|\bnew\s+Function\s*\("), "MEDIUM"),
    ("os_command", re.compile(r"\bos\.(system|popen|exec[lv]p?e?)\s*\(|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bProcessBuilder\s*\("), "MEDIUM"),
    ("unsafe_deserialisation", re.compile(r"\b(pickle|marshal|dill)\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)"), "MEDIUM"),
    ("process_spawn", re.compile(r"\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(|\bchild_process\b|\b(execSync|spawnSync|execFile)\s*\("), "LOW"),
)
_NETWORK_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("url_with_ip_address", re.compile(r"\bhttps?://(?!127\.0\.0\.1|0\.0\.0\.0|localhost)\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?[^\s\"')]*"), "MEDIUM"),
    ("raw_socket", re.compile(r"\bsocket\.(socket|create_connection)\s*\(|\bnet\.(connect|createConnection)\s*\("), "LOW"),
    ("http_client_call", re.compile(r"\b(requests|httpx|urllib\.request|urllib3|aiohttp)\.\w+\s*\(|\bfetch\s*\(|\baxios(\.\w+)?\s*\(|\bXMLHttpRequest\b|\bhttp\.(Get|Post)\s*\("), "INFO"),
)
_URL = re.compile(r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?[^\s\"')>]*")
_SECURITY_CONFIG_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("tls_verification_disabled", re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
                                             r"_create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|--insecure\b|\bcurl\b[^\n]*\s-k\b"), "HIGH"),
    ("permissive_cors", re.compile(r"(allow_origins|Access-Control-Allow-Origin|origin)\s*[:=]\s*\[?\s*[\"']\*[\"']", re.I), "MEDIUM"),
    ("debug_enabled", re.compile(r"\bDEBUG\s*=\s*True\b|\bdebug\s*:\s*true\b"), "LOW"),
)
_AUTH_REMOVED = re.compile(r"@login_required|@requires_auth|@authenticated|@permission_required|Depends\(\s*(get_current_user|require_\w+)|"
                           r"\bCurrentUser\b|verify_token\s*\(|check_permission\s*\(|isAuthenticated|requireAuth|authorize\s*\(", re.I)
_AUTH_WEAKENED = re.compile(r"algorithms?\s*=\s*\[?\s*[\"']none[\"']|verify_signature[\"']?\s*:\s*False|options\s*=\s*\{[^}]*verify[^}]*False", re.I)
_PACKAGE_SOURCE = re.compile(r"--(extra-)?index-url|--trusted-host|--find-links|^\s*registry\s*=|\bgit\+(https?|ssh)://|"
                             r"\[\[tool\.poetry\.source\]\]|\"resolved\"\s*:\s*\"(?!https://registry\.npmjs\.org/)https?://|"
                             r"^\s*replace\s+\S+\s+=>|\[source\.|\[patch\.", re.I)
_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{240,}")


def classify_path(path: str) -> dict[str, bool]:
    """What a changed path is, from its name alone."""
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1]
    manifest = name in MANIFESTS or bool(_REQUIREMENTS.match(name))
    ci = lower.startswith((".github/workflows/", ".circleci/", ".gitlab/")) or name in (".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml",
                                                                                         ".travis.yml", "bitbucket-pipelines.yml")
    container = name.startswith("dockerfile") or name.startswith("docker-compose") or name.endswith((".dockerfile",)) or name == ".dockerignore"
    policy = name in ("codeowners", "security.md", ".env.example", ".env.sample", ".gitattributes") or name.startswith(".env.")
    server = name.startswith("nginx") or name.endswith((".tf", ".tfvars")) or name in ("caddyfile", "haproxy.cfg") \
        or "/k8s/" in f"/{lower}" or "/helm/" in f"/{lower}"
    return {
        "manifest": manifest, "lockfile": name in LOCKFILES, "package_source_config": name in SOURCE_CONFIG,
        "ci": ci, "container": container, "policy": policy, "server": server,
        "auth": bool(_AUTH_PATH.search(lower)) and not name.endswith((".md", ".rst", ".txt")),
        "low_signal": bool(_LOW_SIGNAL_PATH.search(lower)), "text_only": bool(_TEXT_ONLY.search(lower)) or name in LOCKFILES,
    }


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(count / len(value) * math.log2(count / len(value)) for count in counts.values())


def mask(text: str) -> str:
    """The text with every secret-like value replaced by its first characters and its length."""
    def hide(value: str) -> str:
        return f"{value[:4]}***({len(value)} chars)"

    for _name, pattern, _severity in _SECRET_RULES:
        text = pattern.sub(lambda match: hide(match.group(0)), text)
    return _ASSIGNED_SECRET.sub(lambda match: match.group(0).replace(match.group(2), hide(match.group(2))), text)


def excerpt(text: str) -> str:
    return mask(text.strip())[:EXCERPT]


def _finding(kind: str, rule: str, severity: str, basis: str, confidence: float, path: str, detail: str, line: int | None = None,
             text: str | None = None, side: str | None = None) -> dict[str, Any]:
    return {"type": kind, "rule": rule, "severity": severity, "basis": basis, "confidence": round(confidence, 2), "file": path, "line": line,
            "side": side, "detail": detail, "excerpt": excerpt(text) if text else None}


def secret_findings(path: str, lines: list[tuple[int, str, int]], confidence: float) -> list[dict[str, Any]]:
    found = []
    for number, text, _length in lines:
        for name, pattern, severity in _SECRET_RULES:
            if pattern.search(text):
                found.append(_finding("SECRET_LIKE_PATTERN", name, severity, INFERRED, min(0.95, confidence + 0.15), path,
                                      f"An added line contains a value with the format of a {name.replace('_', ' ')}. The value is not stored.",
                                      number, text, "added"))
                break
        else:
            assigned = _ASSIGNED_SECRET.search(text)
            if assigned and not _PLACEHOLDER.search(assigned.group(2)) and entropy(assigned.group(2)) >= 3.0:
                found.append(_finding("SECRET_LIKE_PATTERN", "assigned_secret_like_value", "MEDIUM", INFERRED, confidence * 0.75, path,
                                      f"An added line assigns a literal to '{assigned.group(1)[:60]}'. The value is not stored.", number, text, "added"))
    return found


def _match_rules(kind: str, rules: tuple[tuple[str, re.Pattern[str], str], ...], path: str, lines: list[tuple[int, str, int]],
                 confidence: float, what: str) -> list[dict[str, Any]]:
    found = []
    for number, text, _length in lines:
        for name, pattern, severity in rules:
            if pattern.search(text):
                found.append(_finding(kind, name, severity, INFERRED, confidence, path, f"An added line {what} ({name.replace('_', ' ')}).",
                                      number, text, "added"))
                break                       # the first (most specific) rule that matches a line is the one reported
    return found


def file_findings(changed: dict[str, Any], parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Everything the rules recognise in one changed file. `parsed` is the output of diff.parse_patch for it."""
    path = changed["path"]
    kinds = classify_path(path)
    confidence = 0.4 if kinds["low_signal"] else 0.8
    added, removed = parsed["added"], parsed["removed"]
    found: list[dict[str, Any]] = []
    status = changed.get("status") or "modified"

    if kinds["manifest"] or kinds["lockfile"] or kinds["package_source_config"]:
        what = "lockfile" if kinds["lockfile"] else "package source configuration" if kinds["package_source_config"] else "dependency manifest"
        found.append(_finding("DEPENDENCY_CHANGE", "lockfile_changed" if kinds["lockfile"] else "package_source_config_changed"
                              if kinds["package_source_config"] else "manifest_changed",
                              "MEDIUM" if kinds["package_source_config"] else "LOW", OBSERVED, 1.0, path,
                              f"The {what} {path} was {status} (+{changed.get('additions', 0)} −{changed.get('deletions', 0)} lines)."))
        for number, text, _length in added:
            if _PACKAGE_SOURCE.search(text):
                found.append(_finding("DEPENDENCY_CHANGE", "package_source_changed", "MEDIUM", INFERRED, 0.7, path,
                                      "An added line changes where a package is fetched from (an index, registry, git source or replacement).",
                                      number, text, "added"))
    if kinds["ci"] or kinds["container"] or kinds["policy"] or kinds["server"]:
        what = "CI/CD pipeline definition" if kinds["ci"] else "container build or composition file" if kinds["container"] \
            else "repository policy or environment template" if kinds["policy"] else "server or infrastructure configuration"
        found.append(_finding("SECURITY_CONFIG_CHANGE", "ci_pipeline_changed" if kinds["ci"] else "container_config_changed" if kinds["container"]
                              else "policy_file_changed" if kinds["policy"] else "infrastructure_config_changed",
                              "MEDIUM" if kinds["ci"] else "LOW", OBSERVED, 1.0, path, f"The {what} {path} was {status}."))
    if kinds["auth"]:
        found.append(_finding("AUTH_CHANGE", "auth_related_file_changed", "LOW", OBSERVED, 1.0, path,
                              f"{path} was {status}; its name indicates authentication, authorisation, session or credential handling."))

    # Secret-like values are looked for in every added line, whatever the file type.
    found += secret_findings(path, added, confidence)
    if not kinds["text_only"]:
        found += _match_rules("SECURITY_CONFIG_CHANGE", _SECURITY_CONFIG_RULES, path, added, confidence, "relaxes a security setting")
        found += _match_rules("COMMAND_EXECUTION_PATTERN", _COMMAND_RULES, path, added, confidence, "runs a command or evaluates code")
        found += _match_rules("NETWORK_BEHAVIOUR_CHANGE", _NETWORK_RULES, path, added, confidence, "introduces network use")
        for number, text, _length in added:
            if _AUTH_WEAKENED.search(text):
                found.append(_finding("AUTH_CHANGE", "token_verification_weakened", "HIGH", INFERRED, confidence, path,
                                      "An added line turns off or weakens verification of a token.", number, text, "added"))
        known_hosts = {match.group(1).lower() for _n, text, _l in removed for match in _URL.finditer(text)}
        for number, text, _length in added:
            for match in _URL.finditer(text):
                host = match.group(1).lower()
                if host not in known_hosts:
                    known_hosts.add(host)
                    found.append(_finding("NETWORK_BEHAVIOUR_CHANGE", "new_external_host", "LOW", INFERRED, confidence * 0.75, path,
                                          f"An added line refers to the host {host[:80]}, which the lines it replaces did not.", number, text, "added"))
        for number, text, _length in removed:
            if _AUTH_REMOVED.search(text) and not any(_AUTH_REMOVED.search(line) for _n, line, _l in added):
                found.append(_finding("AUTH_CHANGE", "auth_check_removed", "MEDIUM", INFERRED, confidence * 0.75, path,
                                      "A removed line contained an authentication or authorisation check, and no added line in this file has one.",
                                      number, text, "removed"))
        long_lines = [(number, length) for number, _text, length in added if length >= 1000]
        blobs = [(number, text) for number, text, _length in added if _BLOB.search(text)]
        if blobs and not kinds["lockfile"]:
            found.append(_finding("UNUSUAL_CHANGE_PATTERN", "encoded_blob_added", "LOW", INFERRED, confidence * 0.75, path,
                                  f"{len(blobs)} added line(s) contain a long run of encoded-looking characters (240 or more). "
                                  "Embedded assets and test data also look like this.", blobs[0][0]))
        elif long_lines:
            found.append(_finding("UNUSUAL_CHANGE_PATTERN", "very_long_line_added", "INFO", INFERRED, confidence * 0.6, path,
                                  f"{len(long_lines)} added line(s) are 1,000 characters or longer, as generated or minified code is.", long_lines[0][0]))
    return _limit(found)


def _limit(found: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """At most MAX_FINDINGS_PER_RULE findings of one rule per file; the number left out is noted on the last one kept."""
    kept: list[dict[str, Any]] = []
    seen: Counter[tuple[str, str]] = Counter()
    for item in found:
        key = (item["type"], item["rule"])
        seen[key] += 1
        if seen[key] <= MAX_FINDINGS_PER_RULE:
            kept.append(item)
    for item in kept:
        extra = seen[(item["type"], item["rule"])] - MAX_FINDINGS_PER_RULE
        if extra > 0:
            item["more_in_file"] = extra
    return kept
