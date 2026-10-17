import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis

from auth_service.core.config import get_settings


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
