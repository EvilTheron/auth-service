import uuid
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.core.redis import get_redis
from auth_service.core.security import decode_access_token
from auth_service.db.models import User
from auth_service.db.session import get_session
from auth_service.services import user_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

SessionDep = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]


def _credentials_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_token_payload(
    token: Annotated[str, Depends(oauth2_scheme)],
    redis: RedisDep,
) -> dict[str, Any]:
    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError as exc:
        raise _credentials_error() from exc

    if not await redis.exists(f"session:{payload['sid']}"):
        raise _credentials_error()
    return payload


TokenPayloadDep = Annotated[dict[str, Any], Depends(get_token_payload)]


async def get_current_user(payload: TokenPayloadDep, session: SessionDep) -> User:
    try:
        user_id = uuid.UUID(payload["sub"])
    except ValueError as exc:
        raise _credentials_error() from exc

    user = await user_service.get_user_by_id(session, user_id)
    if user is None or not user.is_active:
        raise _credentials_error()
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]
