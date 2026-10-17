from functools import lru_cache

from redis.asyncio import Redis

from auth_service.core.config import get_settings


@lru_cache
def get_redis() -> Redis:
    settings = get_settings()
    return Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)
