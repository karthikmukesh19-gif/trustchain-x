from datetime import datetime, timedelta, timezone

import jwt
import pytest
from bson import ObjectId

from app.auth.tokens import InvalidToken, create_access_token, decode_access_token
from app.config.settings import load_settings
from tests.conftest import TEST_ENV, VALID_USER, register


def test_register_creates_user_and_returns_token(client, db):
    response = register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600
    assert body["user"]["email"] == "alice@example.com"
    assert body["user"]["full_name"] == "Alice Example"
    assert "password" not in str(body).lower()

    stored = db.users.find_one({"email": "alice@example.com"})
    assert stored["password_hash"].startswith("scrypt$")
    assert VALID_USER["password"] not in stored["password_hash"]
    assert stored["is_active"] is True


def test_register_normalises_email_case(client, db):
    assert register(client, email="  Alice@Example.COM ").status_code == 201
    assert db.users.count_documents({"email": "alice@example.com"}) == 1


def test_register_rejects_duplicate_email(client):
    assert register(client).status_code == 201
    again = register(client, email="ALICE@example.com")
    assert again.status_code == 409


@pytest.mark.parametrize(
    "password",
    ["short1", "nodigitsinthispassword", "1234567890123", "x" * 200 + "1"],
)
def test_register_rejects_weak_passwords(client, password):
    response = register(client, password=password)
    assert response.status_code == 422


def test_validation_errors_never_echo_the_password(client):
    secret = "leak-me-9"
    response = register(client, password=secret)
    assert response.status_code == 422
    assert secret not in response.text
    assert "input" not in response.json()["detail"][0]


@pytest.mark.parametrize("email", ["not-an-email", "a@b", "a@@example.com", "a b@example.com", "a..b@example.com", ""])
def test_register_rejects_invalid_email(client, email):
    assert register(client, email=email).status_code == 422


def test_register_rejects_unknown_fields(client):
    response = client.post("/api/auth/register", json={**VALID_USER, "role": "admin"})
    assert response.status_code == 422


def test_registered_users_cannot_choose_their_role(client, db):
    register(client)
    assert db.users.find_one({})["role"] == "user"


def test_login_success(client, db):
    register(client)
    response = client.post("/api/auth/login", json={"email": "Alice@example.com", "password": VALID_USER["password"]})
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "alice@example.com"
    assert db.users.find_one({})["last_login_at"] is not None


def test_login_failure_is_identical_for_unknown_user_and_wrong_password(client):
    register(client)
    wrong_password = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-password-1"})
    unknown_user = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong-password-1"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_login_rejects_inactive_account(client, db):
    register(client)
    db.users.update_one({}, {"$set": {"is_active": False}})
    response = client.post("/api/auth/login", json={"email": "alice@example.com", "password": VALID_USER["password"]})
    assert response.status_code == 401


def test_me_returns_current_user(client, auth_headers):
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"
    assert "password_hash" not in response.json()


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer not.a.token"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}],
)
def test_me_requires_a_valid_token(client, headers):
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_token_signed_with_another_secret_is_rejected(client, settings):
    register(client)
    other = load_settings({**TEST_ENV, "JWT_SECRET": "a-completely-different-secret-of-enough-length"})
    token, _ = create_access_token(other, str(ObjectId()))
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_expired_token_is_rejected(client, settings, db):
    register(client)
    user_id = str(db.users.find_one({})["_id"])
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    token, _ = create_access_token(settings, user_id, now=past)
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_unsigned_token_is_rejected(client, settings, db):
    register(client)
    user_id = str(db.users.find_one({})["_id"])
    now = datetime.now(timezone.utc)
    payload = {"sub": user_id, "type": "access", "iat": now, "exp": now + timedelta(hours=1)}
    token = jwt.encode(payload, key=None, algorithm="none")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_of_wrong_type_is_rejected(settings):
    now = datetime.now(timezone.utc)
    payload = {"sub": str(ObjectId()), "type": "refresh", "iat": now, "exp": now + timedelta(hours=1)}
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    with pytest.raises(InvalidToken):
        decode_access_token(settings, token)


def test_token_for_deleted_user_is_rejected(client, auth_headers, db):
    db.users.delete_many({})
    assert client.get("/api/auth/me", headers=auth_headers).status_code == 401


def test_token_with_non_objectid_subject_is_rejected(client, settings):
    token, _ = create_access_token(settings, "not-an-object-id")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_auth_events_are_audited_without_secrets(client, db):
    register(client)
    client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-password-1"})
    client.post("/api/auth/login", json={"email": "alice@example.com", "password": VALID_USER["password"]})
    entries = list(db.audit_logs.find({}))
    assert [(e["action"], e["outcome"]) for e in entries] == [
        ("auth.register", "success"),
        ("auth.login", "failure"),
        ("auth.login", "success"),
    ]
    assert VALID_USER["password"] not in str(entries)
    assert "wrong-password-1" not in str(entries)
