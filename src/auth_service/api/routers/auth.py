from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from auth_service.api.deps import CurrentUserDep, RedisDep, SessionDep, TokenPayloadDep
from auth_service.core.security import create_access_token
from auth_service.db.models import User
from auth_service.schemas.token import RefreshRequest, Token
from auth_service.schemas.user import UserCreate, UserRead
from auth_service.services import token_service, user_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(data: UserCreate, session: SessionDep) -> User:
    try:
        return await user_service.create_user(session, data.email, data.password)
    except user_service.EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        ) from exc


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    redis: RedisDep,
) -> Token:
    user = await user_service.authenticate(session, form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    session_id, refresh_token = await token_service.create_session(
        redis,
        user.id,
        user_agent=request.headers.get("user-agent", ""),
        ip=request.client.host if request.client else "",
    )
    return Token(
        access_token=create_access_token(user.id, session_id),
        refresh_token=refresh_token,
    )


def _invalid_refresh_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/refresh", response_model=Token)
async def refresh(data: RefreshRequest, session: SessionDep, redis: RedisDep) -> Token:
    try:
        user_id, session_id, new_refresh_token = await token_service.rotate_refresh_token(
            redis, data.refresh_token
        )
    except token_service.InvalidRefreshTokenError as exc:
        raise _invalid_refresh_error() from exc

    user = await user_service.get_user_by_id(session, user_id)
    if user is None or not user.is_active:
        await token_service.revoke_session(redis, session_id)
        raise _invalid_refresh_error()

    return Token(
        access_token=create_access_token(user.id, session_id),
        refresh_token=new_refresh_token,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: TokenPayloadDep, redis: RedisDep) -> None:
    await token_service.revoke_session(redis, payload["sid"])


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(user: CurrentUserDep, redis: RedisDep) -> None:
    await token_service.revoke_all_sessions(redis, user.id)
