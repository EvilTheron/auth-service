from httpx import AsyncClient
from redis.asyncio import Redis

from auth_service.services.token_service import hash_token
from tests.helpers import login, register


async def test_login_creates_session_in_redis(client: AsyncClient, redis_client: Redis):
    await register(client)
    refresh_token = (await login(client)).json()["refresh_token"]
    session_id = await redis_client.get(f"refresh:{hash_token(refresh_token)}")
    assert session_id is not None
    assert await redis_client.exists(f"session:{session_id}") == 1


async def test_refresh_token_is_not_stored_in_plain_text(client: AsyncClient, redis_client: Redis):
    await register(client)
    refresh_token = (await login(client)).json()["refresh_token"]
    assert await redis_client.exists(f"refresh:{refresh_token}") == 0
