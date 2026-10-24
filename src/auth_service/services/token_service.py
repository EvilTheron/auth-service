import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis

from auth_service.core.config import get_settings


class InvalidRefreshTokenError(Exception):
    pass


class RefreshTokenReuseError(InvalidRefreshTokenError):
    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__("Refresh token reuse detected")
        self.user_id = user_id


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(
    redis: Redis,
    user_id: uuid.UUID,
    user_agent: str,
    ip: str,
) -> tuple[str, str]:
    """Создаёт сессию, возвращает (session_id, refresh_token)."""
    ttl = get_settings().refresh_token_expire_days * 24 * 60 * 60
    session_id = uuid.uuid4().hex
    refresh_token = secrets.token_urlsafe(48)
    now = datetime.now(UTC).isoformat()

    async with redis.pipeline(transaction=True) as pipe:
        pipe.hset(
            f"session:{session_id}",
            mapping={
                "user_id": str(user_id),
                "user_agent": user_agent,
                "ip": ip,
                "created_at": now,
                "last_used_at": now,
            },
        )
        pipe.expire(f"session:{session_id}", ttl)
        pipe.set(f"refresh:{hash_token(refresh_token)}", session_id, ex=ttl)
        pipe.sadd(f"user_sessions:{user_id}", session_id)
        pipe.expire(f"user_sessions:{user_id}", ttl)
        await pipe.execute()

    return session_id, refresh_token


async def revoke_session(redis: Redis, session_id: str) -> None:
    user_id = await redis.hget(f"session:{session_id}", "user_id")
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(f"session:{session_id}")
        if user_id:
            pipe.srem(f"user_sessions:{user_id}", session_id)
        await pipe.execute()


async def rotate_refresh_token(
    redis: Redis,
    refresh_token: str,
) -> tuple[uuid.UUID, str, str]:
    """Проверяет refresh-токен и выдаёт новый.

    Возвращает (user_id, session_id, новый refresh-токен).
    """
    ttl = get_settings().refresh_token_expire_days * 24 * 60 * 60
    token_hash = hash_token(refresh_token)

    session_id = await redis.get(f"refresh:{token_hash}")
    if session_id is None:
        raise InvalidRefreshTokenError

    session = await redis.hgetall(f"session:{session_id}")
    if not session:
        raise InvalidRefreshTokenError

    first_use = await redis.set(f"used:{token_hash}", "1", nx=True, ex=ttl)
    if not first_use:
        await revoke_session(redis, session_id)
        raise RefreshTokenReuseError(uuid.UUID(session["user_id"]))

    new_token = secrets.token_urlsafe(48)
    user_id = session["user_id"]
    async with redis.pipeline(transaction=True) as pipe:
        pipe.set(f"refresh:{hash_token(new_token)}", session_id, ex=ttl)
        pipe.hset(f"session:{session_id}", "last_used_at", datetime.now(UTC).isoformat())
        pipe.expire(f"session:{session_id}", ttl)
        pipe.expire(f"user_sessions:{user_id}", ttl)
        await pipe.execute()

    return uuid.UUID(user_id), session_id, new_token


async def revoke_all_sessions(redis: Redis, user_id: uuid.UUID) -> None:
    key = f"user_sessions:{user_id}"
    session_ids = await redis.smembers(key)
    async with redis.pipeline(transaction=True) as pipe:
        for session_id in session_ids:
            pipe.delete(f"session:{session_id}")
        pipe.delete(key)
        await pipe.execute()


async def revoke_user_session(redis: Redis, user_id: uuid.UUID, session_id: str) -> bool:
    owner = await redis.hget(f"session:{session_id}", "user_id")
    if owner != str(user_id):
        return False
    await revoke_session(redis, session_id)
    return True


async def list_sessions(redis: Redis, user_id: uuid.UUID) -> list[dict[str, str]]:
    key = f"user_sessions:{user_id}"
    sessions = []
    for session_id in await redis.smembers(key):
        data = await redis.hgetall(f"session:{session_id}")
        if not data:
            await redis.srem(key, session_id)
            continue
        sessions.append({"id": session_id, **data})
    return sorted(sessions, key=lambda s: s["created_at"], reverse=True)


async def revoke_other_sessions(redis: Redis, user_id: uuid.UUID, keep_session_id: str) -> None:
    key = f"user_sessions:{user_id}"
    session_ids = await redis.smembers(key)
    async with redis.pipeline(transaction=True) as pipe:
        for session_id in session_ids:
            if session_id != keep_session_id:
                pipe.delete(f"session:{session_id}")
                pipe.srem(key, session_id)
        await pipe.execute()
