import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from auth_service.core.config import get_settings

_hasher = PasswordHasher()
_hash_limiter = anyio.CapacityLimiter(4)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


async def hash_password_async(password: str) -> str:
    return await anyio.to_thread.run_sync(hash_password, password, limiter=_hash_limiter)


async def verify_password_async(password: str, password_hash: str) -> bool:
    return await anyio.to_thread.run_sync(
        verify_password, password, password_hash, limiter=_hash_limiter
    )


def create_access_token(user_id: uuid.UUID, session_id: str) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "sid": session_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    return jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        options={"require": ["exp", "iat", "sub", "sid", "jti"]},
    )
