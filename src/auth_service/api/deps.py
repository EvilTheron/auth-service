import logging
import uuid
from collections.abc import Awaitable, Callable
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.bloom.filter import BloomFilter
from auth_service.core.config import get_settings
from auth_service.core.redis import get_redis
from auth_service.core.security import decode_access_token
from auth_service.db.models import User
from auth_service.db.session import get_session
from auth_service.services import user_service

logger = logging.getLogger(__name__)

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


@lru_cache
def _load_filter(path: str) -> BloomFilter | None:
    file = Path(path)
    if not file.exists():
        logger.warning("leaked password filter not found at %s: check is disabled", path)
        return None
    try:
        return BloomFilter.load(file)
    except OSError, ValueError:
        logger.exception("leaked password filter at %s is unreadable: check is disabled", path)
        return None


def get_password_filter() -> BloomFilter | None:
    return _load_filter(get_settings().leaked_passwords_filter_path)


PasswordFilterDep = Annotated[BloomFilter | None, Depends(get_password_filter)]


def require_role(*roles: str) -> Callable[..., Awaitable[User]]:
    async def checker(user: CurrentUserDep) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return checker


AdminDep = Annotated[User, Depends(require_role("admin"))]


def client_info(request: Request) -> tuple[str, str]:
    ip = request.client.host if request.client else "unknown"
    return ip, request.headers.get("user-agent", "")
