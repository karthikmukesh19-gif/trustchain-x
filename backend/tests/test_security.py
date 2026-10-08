import pytest

from app.config.settings import SettingsError, load_settings
from app.security import passwords
from app.security.rate_limit import RateLimiter
from app.security.url_validation import InvalidRepositoryURL, parse_github_url
from tests.conftest import TEST_ENV, VALID_USER, register


# --- password hashing -------------------------------------------------------

def test_hash_is_salted_and_verifiable():
    first = passwords.hash_password("correct-horse-42")
    second = passwords.hash_password("correct-horse-42")
    assert first != second
    assert passwords.verify_password("correct-horse-42", first)
    assert not passwords.verify_password("correct-horse-43", first)
    assert not passwords.needs_rehash(first)


@pytest.mark.parametrize(
    "stored",
    ["", "plain", "scrypt$1$2", "bcrypt$32768$8$1$AAAA$AAAA", "scrypt$x$8$1$AAAA$AAAA",
     "scrypt$32768$8$1$!!!$AAAA", "scrypt$1073741824$8$1$AAAA$AAAA"],
)
def test_malformed_or_hostile_hashes_never_verify(stored):
    assert passwords.verify_password("anything", stored) is False


def test_needs_rehash_when_parameters_change():
    assert passwords.needs_rehash("scrypt$16384$8$1$AAAA$AAAA")


def test_unicode_passwords_round_trip():
    hashed = passwords.hash_password("pässwörd-密码-1")
    assert passwords.verify_password("pässwörd-密码-1", hashed)


# --- repository URL validation ---------------------------------------------

def test_parse_github_url_returns_canonical_reference():
    ref = parse_github_url("https://GitHub.com/Pallets/Flask.git/")
    assert (ref.host, ref.owner, ref.name) == ("github.com", "Pallets", "Flask")
    assert ref.url == "https://github.com/Pallets/Flask"
    assert ref.key == "github.com/pallets/flask"


@pytest.mark.parametrize("value", [None, 42, "", "   ", "https://github.com/" + "a" * 300, "https://[::1/a/b"])
def test_parse_github_url_rejects_non_urls(value):
    with pytest.raises(InvalidRepositoryURL):
        parse_github_url(value)


# --- rate limiting ----------------------------------------------------------

def test_rate_limiter_blocks_then_recovers():
    now = [0.0]
    limiter = RateLimiter(limit=3, window_seconds=60, clock=lambda: now[0])
    assert [limiter.check("a")[0] for _ in range(3)] == [True, True, True]
    allowed, retry_after = limiter.check("a")
    assert allowed is False and retry_after == 60
    assert limiter.check("b")[0] is True  # other clients are unaffected
    now[0] = 61.0
    assert limiter.check("a")[0] is True


def test_rate_limiter_bounds_memory(monkeypatch):
    from app.security import rate_limit

    monkeypatch.setattr(rate_limit, "MAX_TRACKED_KEYS", 10)
    limiter = RateLimiter(limit=1, window_seconds=60, clock=lambda: 0.0)
    for i in range(100):
        limiter.check(f"client-{i}")
    assert len(limiter._hits) <= 10


def test_login_is_rate_limited(mongo, fake_redis):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings = load_settings({**TEST_ENV, "AUTH_RATE_LIMIT": "3"})
    with TestClient(create_app(settings, mongo_client=mongo, redis_client=fake_redis)) as client:
        codes = [
            client.post("/api/auth/login", json={"email": "a@example.com", "password": "guess-number-1"}).status_code
            for _ in range(5)
        ]
        assert codes == [401, 401, 401, 429, 429]
        blocked = client.post("/api/auth/login", json={"email": "a@example.com", "password": "guess-number-1"})
        assert int(blocked.headers["retry-after"]) >= 1
        # Spoofed forwarding headers do not create a fresh allowance.
        spoofed = client.post(
            "/api/auth/login",
            json={"email": "a@example.com", "password": "guess-number-1"},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )
        assert spoofed.status_code == 429


# --- configuration ----------------------------------------------------------

def test_production_requires_a_strong_secret():
    with pytest.raises(SettingsError):
        load_settings({"APP_ENV": "production"})
    with pytest.raises(SettingsError):
        load_settings({"APP_ENV": "production", "JWT_SECRET": "short"})
    assert load_settings({"APP_ENV": "production", "JWT_SECRET": "x" * 32}).is_production


def test_development_generates_an_ephemeral_secret():
    first, second = load_settings({}), load_settings({})
    assert len(first.jwt_secret) >= 32 and first.jwt_secret != second.jwt_secret


@pytest.mark.parametrize(
    "env",
    [
        {"JWT_SECRET": "too-short"},
        {"APP_ENV": "staging"},
        {"CORS_ORIGINS": "*"},
        {"JWT_ALGORITHM": "none"},
        {"GITHUB_API_URL": "http://api.github.com"},
        {"JWT_EXPIRE_MINUTES": "0"},
        {"AUTH_RATE_LIMIT": "many"},
    ],
)
def test_unsafe_configuration_is_rejected(env):
    with pytest.raises(SettingsError):
        load_settings({**TEST_ENV, **env})


def test_secrets_are_not_in_settings_repr(settings):
    assert TEST_ENV["JWT_SECRET"] not in repr(settings)


def test_cors_origins_are_parsed():
    settings = load_settings({**TEST_ENV, "CORS_ORIGINS": "https://a.example/, https://b.example"})
    assert settings.cors_origins == ("https://a.example", "https://b.example")


# --- HTTP hardening ---------------------------------------------------------

def test_security_headers_are_set(client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert "default-src 'none'" in headers["content-security-policy"]


def test_error_responses_also_carry_security_headers(client):
    assert client.get("/api/projects").headers["x-content-type-options"] == "nosniff"


def test_cors_allows_only_configured_origins(client):
    allowed = client.options(
        "/api/projects",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    denied = client.options(
        "/api/projects",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in denied.headers


def test_oversized_declared_body_is_rejected(client):
    response = client.post(
        "/api/auth/register",
        content=b"x" * (1_048_576 + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_oversized_streamed_body_is_rejected(client):
    def chunks():
        for _ in range(300):
            yield b"x" * 4096

    response = client.post("/api/auth/register", content=chunks(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_invalid_content_length_is_rejected(client):
    response = client.post(
        "/api/auth/register", content=b"{}", headers={"Content-Type": "application/json", "Content-Length": "abc"}
    )
    assert response.status_code in (400, 413)


def test_api_docs_are_disabled_in_production(mongo, fake_redis):
    from fastapi.testclient import TestClient

    from app.main import create_app

    settings = load_settings({**TEST_ENV, "APP_ENV": "production"})
    with TestClient(create_app(settings, mongo_client=mongo, redis_client=fake_redis)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_unhandled_errors_do_not_leak_details(app, auth_headers, monkeypatch):
    from fastapi.testclient import TestClient

    from app.services import dashboard

    def boom(*_a, **_k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(dashboard, "build_summary", boom)
    with TestClient(app, raise_server_exceptions=False) as quiet:
        response = quiet.get("/api/dashboard/summary", headers=auth_headers)
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "secret internal detail" not in response.text


def test_indexes_enforce_unique_email(client, db):
    from pymongo.errors import DuplicateKeyError

    register(client)
    with pytest.raises(DuplicateKeyError):
        db.users.insert_one({"email": VALID_USER["email"]})


def test_all_declared_collections_have_indexes(client, db):
    from app.models.collections import ALL_COLLECTIONS, INDEXES

    # 29 from the original data model + vulnerability_syncs and vulnerability_sources (Phase 3)
    # + source_files, source_symbols, code_edges and reachability_analyses (Phase 4)
    assert len(ALL_COLLECTIONS) == 35
    for name in ALL_COLLECTIONS:
        assert len(db[name].index_information()) == len(INDEXES[name]) + 1  # + the _id index


def test_index_migration_tolerates_another_process_dropping_first(db, monkeypatch):
    """The API and the worker migrate at the same time; losing that race must not stop start-up."""
    from pymongo.errors import OperationFailure

    from app.models.database import ensure_indexes

    db.repository_snapshots.create_index([("repository_id", 1), ("commit_sha", 1)], unique=True)
    real_drop = db.repository_snapshots.drop_index

    def drop_after_someone_else(name, *args, **kwargs):
        real_drop(name)
        raise OperationFailure("index not found with name [%s]" % name, 27)

    monkeypatch.setattr(db.repository_snapshots, "drop_index", drop_after_someone_else)
    ensure_indexes(db)
    assert "repository_id_1_commit_sha_1" not in db.repository_snapshots.index_information()
    assert "project_id_1_commit_sha_1_analyzer_version_1" in db.repository_snapshots.index_information()
