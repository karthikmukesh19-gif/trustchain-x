"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.dependencies import CurrentUser, DbDep, SettingsDep
from app.auth.tokens import create_access_token
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.security.rate_limit import auth_rate_limit
from app.services import audit, users

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _token_response(settings, user) -> TokenResponse:
    token, expires_in = create_access_token(settings, str(user["_id"]))
    return TokenResponse(access_token=token, expires_in=expires_in, user=UserOut(**users.to_public(user)))


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(auth_rate_limit)],
)
def register(body: RegisterRequest, request: Request, db: DbDep, settings: SettingsDep) -> TokenResponse:
    try:
        user = users.create_user(db, body.email, body.password, body.full_name)
    except users.EmailAlreadyRegistered:
        audit.record(db, "auth.register", request=request, outcome="failure", details={"reason": "email_taken"})
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists") from None
    audit.record(db, "auth.register", request=request, actor_id=user["_id"], resource_type="user", resource_id=user["_id"])
    return _token_response(settings, user)


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(auth_rate_limit)])
def login(body: LoginRequest, request: Request, db: DbDep, settings: SettingsDep) -> TokenResponse:
    user = users.authenticate(db, body.email, body.password)
    if user is None:
        audit.record(db, "auth.login", request=request, outcome="failure")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    audit.record(db, "auth.login", request=request, actor_id=user["_id"], resource_type="user", resource_id=user["_id"])
    return _token_response(settings, user)


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut(**users.to_public(user))
