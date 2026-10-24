import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from auth_service.api.deps import (
    CurrentUserDep,
    PasswordFilterDep,
    RedisDep,
    SessionDep,
    TokenPayloadDep,
    client_info,
)
from auth_service.core.security import create_access_token, verify_password_async
from auth_service.db.models import User
from auth_service.schemas.token import RefreshRequest, Token
from auth_service.schemas.user import PasswordChange, UserCreate, UserRead
from auth_service.services import audit_service, throttle_service, token_service, user_service

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    data: UserCreate,
    session: SessionDep,
    redis: RedisDep,
    password_filter: PasswordFilterDep,
) -> User:
    ip, user_agent = client_info(request)
    try:
        await throttle_service.check_registration_allowed(redis, ip)
    except throttle_service.TooManyAttemptsError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Try again later.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    if password_filter is not None and data.password in password_filter:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password has appeared in known data breaches. Choose a different one.",
        )
    try:
        user = await user_service.create_user(session, data.email, data.password)
    except user_service.EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        ) from exc

    await audit_service.record(
        session, "register", user_id=user.id, email=user.email, ip=ip, user_agent=user_agent
    )
    return user


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    redis: RedisDep,
    password_filter: PasswordFilterDep,
) -> Token:
    email = form.username.strip().lower()
    ip, user_agent = client_info(request)

    if len(email) > MAX_EMAIL_LENGTH or len(form.password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        await throttle_service.check_login_allowed(redis, email, ip)
    except throttle_service.TooManyAttemptsError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    user = await user_service.authenticate(session, email, form.password)
    if user is None:
        await throttle_service.register_failure(redis, email, ip)
        await audit_service.record(
            session, "login_failed", email=email, ip=ip, user_agent=user_agent
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _no_store(response)
    compromised = password_filter is not None and form.password in password_filter
    await throttle_service.register_success(redis, email, ip)
    session_id, refresh_token = await token_service.create_session(
        redis, user.id, user_agent=user_agent, ip=ip
    )
    await audit_service.record(
        session,
        "login_success",
        user_id=user.id,
        email=email,
        ip=ip,
        user_agent=user_agent,
        details="password found in breach list" if compromised else None,
    )
    return Token(
        access_token=create_access_token(user.id, session_id),
        refresh_token=refresh_token,
        password_compromised=compromised,
    )


def _invalid_refresh_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/refresh", response_model=Token)
async def refresh(
    request: Request,
    response: Response,
    data: RefreshRequest,
    session: SessionDep,
    redis: RedisDep,
) -> Token:
    try:
        user_id, session_id, new_refresh_token = await token_service.rotate_refresh_token(
            redis, data.refresh_token
        )
    except token_service.RefreshTokenReuseError as exc:
        ip, user_agent = client_info(request)
        await audit_service.record(
            session, "refresh_reuse", user_id=exc.user_id, ip=ip, user_agent=user_agent
        )
        raise _invalid_refresh_error() from exc
    except token_service.InvalidRefreshTokenError as exc:
        raise _invalid_refresh_error() from exc

    user = await user_service.get_user_by_id(session, user_id)
    if user is None or not user.is_active:
        await token_service.revoke_session(redis, session_id)
        raise _invalid_refresh_error()

    _no_store(response)
    return Token(
        access_token=create_access_token(user.id, session_id),
        refresh_token=new_refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    payload: TokenPayloadDep,
    session: SessionDep,
    redis: RedisDep,
) -> None:
    await token_service.revoke_session(redis, payload["sid"])
    ip, user_agent = client_info(request)
    await audit_service.record(
        session, "logout", user_id=uuid.UUID(payload["sub"]), ip=ip, user_agent=user_agent
    )


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    request: Request,
    user: CurrentUserDep,
    session: SessionDep,
    redis: RedisDep,
) -> None:
    await token_service.revoke_all_sessions(redis, user.id)
    ip, user_agent = client_info(request)
    await audit_service.record(
        session, "logout_all", user_id=user.id, email=user.email, ip=ip, user_agent=user_agent
    )


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    request: Request,
    data: PasswordChange,
    user: CurrentUserDep,
    payload: TokenPayloadDep,
    session: SessionDep,
    redis: RedisDep,
    password_filter: PasswordFilterDep,
) -> None:
    ip, user_agent = client_info(request)

    try:
        await throttle_service.check_login_allowed(redis, user.email, ip)
    except throttle_service.TooManyAttemptsError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Try again later.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    if not await verify_password_async(data.current_password, user.password_hash):
        await throttle_service.register_failure(redis, user.email, ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    if data.new_password == data.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must differ from the current one",
        )
    if password_filter is not None and data.new_password in password_filter:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password has appeared in known data breaches. Choose a different one.",
        )

    await user_service.change_password(session, user, data.new_password)
    await token_service.revoke_other_sessions(redis, user.id, payload["sid"])
    await audit_service.record(
        session,
        "password_changed",
        user_id=user.id,
        email=user.email,
        ip=ip,
        user_agent=user_agent,
    )
