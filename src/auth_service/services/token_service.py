import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis

from auth_service.core.config import get_settings

logger = logging.getLogger(__name__)


class InvalidRefreshTokenError(Exception):
    pass


class RefreshTokenReuseError(InvalidRefreshTokenError):
    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__("Refresh token reuse detected")
        self.user_id = user_id


def _session_key(session_id: str) -> str:
    return f"session:{session_id}"


def _user_sessions_key(user_id: uuid.UUID | str) -> str:
    return f"user_sessions:{user_id}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _text(value: bytes | str) -> str:
    return value.decode() if isinstance(value, bytes) else value


def _refresh_ttl() -> int:
    return get_settings().refresh_token_expire_days * 24 * 60 * 60


async def create_session(
    redis: Redis,
    user_id: uuid.UUID,
    user_agent: str,
    ip: str,
) -> tuple[str, str]:
    """Create a session and return (session_id, refresh_token)."""
    ttl = _refresh_ttl()
    session_id = uuid.uuid4().hex
    refresh_token = secrets.token_urlsafe(48)
    now = datetime.now(UTC).isoformat()

    async with redis.pipeline(transaction=True) as pipe:
        pipe.hset(
            _session_key(session_id),
            mapping={
                "user_id": str(user_id),
                "user_agent": user_agent,
                "ip": ip,
                "created_at": now,
                "last_used_at": now,
            },
        )
        pipe.expire(_session_key(session_id), ttl)
        pipe.set(f"refresh:{hash_token(refresh_token)}", session_id, ex=ttl)
        pipe.sadd(_user_sessions_key(user_id), session_id)
        pipe.expire(_user_sessions_key(user_id), ttl)
        await pipe.execute()

    return session_id, refresh_token


async def is_session_active(redis: Redis, session_id: str) -> bool:
    return bool(await redis.exists(_session_key(session_id)))


async def revoke_session(redis: Redis, session_id: str) -> None:
    raw_user_id = await redis.hget(_session_key(session_id), "user_id")
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(_session_key(session_id))
        if raw_user_id:
            pipe.srem(_user_sessions_key(_text(raw_user_id)), session_id)
        await pipe.execute()


# Runs atomically inside Redis, so a concurrent logout cannot interleave.
# KEYS: session, "used" marker of the old token, new refresh token, user's session set.
# ARGV: ttl, session_id, timestamp.
# Returns 1 on success, 0 if the old token was already used (theft), -1 if the session is gone.
_ROTATE_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
    return -1
end
if not redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[1]) then
    return 0
end
redis.call('SET', KEYS[3], ARGV[2], 'EX', ARGV[1])
redis.call('HSET', KEYS[1], 'last_used_at', ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[4], ARGV[1])
return 1
"""


async def rotate_refresh_token(
    redis: Redis,
    refresh_token: str,
) -> tuple[uuid.UUID, str, str]:
    """Validate a refresh token and replace it with a new one.

    Returns (user_id, session_id, new_refresh_token).
    """
    ttl = _refresh_ttl()
    token_hash = hash_token(refresh_token)

    raw_session_id = await redis.get(f"refresh:{token_hash}")
    if raw_session_id is None:
        raise InvalidRefreshTokenError
    session_id = _text(raw_session_id)

    raw_user_id = await redis.hget(_session_key(session_id), "user_id")
    if raw_user_id is None:
        raise InvalidRefreshTokenError
    user_id = _text(raw_user_id)

    new_token = secrets.token_urlsafe(48)
    result = await redis.eval(
        _ROTATE_SCRIPT,
        4,
        _session_key(session_id),
        f"used:{token_hash}",
        f"refresh:{hash_token(new_token)}",
        _user_sessions_key(user_id),
        ttl,
        session_id,
        datetime.now(UTC).isoformat(),
    )

    if int(result) == -1:
        raise InvalidRefreshTokenError
    if int(result) == 0:
        await revoke_session(redis, session_id)
        logger.warning(
            "refresh token reuse detected: user_id=%s session_id=%s", user_id, session_id
        )
        raise RefreshTokenReuseError(uuid.UUID(user_id))

    return uuid.UUID(user_id), session_id, new_token


async def revoke_all_sessions(redis: Redis, user_id: uuid.UUID) -> None:
    key = _user_sessions_key(user_id)
    session_ids = await redis.smembers(key)
    async with redis.pipeline(transaction=True) as pipe:
        for raw_id in session_ids:
            pipe.delete(f"session:{_text(raw_id)}")
        pipe.delete(key)
        await pipe.execute()


async def revoke_other_sessions(redis: Redis, user_id: uuid.UUID, keep_session_id: str) -> None:
    key = _user_sessions_key(user_id)
    session_ids = await redis.smembers(key)
    async with redis.pipeline(transaction=True) as pipe:
        for raw_id in session_ids:
            session_id = _text(raw_id)
            if session_id != keep_session_id:
                pipe.delete(_session_key(session_id))
                pipe.srem(key, session_id)
        await pipe.execute()


async def revoke_user_session(redis: Redis, user_id: uuid.UUID, session_id: str) -> bool:
    owner = await redis.hget(_session_key(session_id), "user_id")
    if owner is None or _text(owner) != str(user_id):
        return False
    await revoke_session(redis, session_id)
    return True


async def list_sessions(redis: Redis, user_id: uuid.UUID) -> list[dict[str, str]]:
    key = _user_sessions_key(user_id)
    sessions: list[dict[str, str]] = []
    for raw_id in await redis.smembers(key):
        session_id = _text(raw_id)
        data = await redis.hgetall(_session_key(session_id))
        if not data:
            await redis.srem(key, session_id)
            continue
        fields = {_text(name): _text(value) for name, value in data.items()}
        sessions.append({"id": session_id, **fields})
    return sorted(sessions, key=lambda s: s["created_at"], reverse=True)
