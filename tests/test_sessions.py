from httpx import AsyncClient
from redis.asyncio import Redis

from auth_service.services.token_service import hash_token
from tests.helpers import bearer, login, refresh, register


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


async def test_refresh_rotates_tokens(client: AsyncClient):
    await register(client)
    first = (await login(client)).json()

    response = await refresh(client, first["refresh_token"])
    assert response.status_code == 200
    second = response.json()
    assert second["refresh_token"] != first["refresh_token"]

    me = await client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {second['access_token']}"},
    )
    assert me.status_code == 200


async def test_refresh_unknown_token(client: AsyncClient):
    response = await refresh(client, "not-a-real-token")
    assert response.status_code == 401


async def test_refresh_reuse_revokes_whole_session(client: AsyncClient):
    await register(client)
    first = (await login(client)).json()
    second = (await refresh(client, first["refresh_token"])).json()

    reuse = await refresh(client, first["refresh_token"])
    assert reuse.status_code == 401

    after = await refresh(client, second["refresh_token"])
    assert after.status_code == 401


async def test_refresh_does_not_resurrect_session_revoked_during_rotation(
    client: AsyncClient, redis_client: Redis
):
    await register(client)
    tokens = (await login(client)).json()
    sessions = (await client.get("/sessions", headers=bearer(tokens["access_token"]))).json()
    session_key = f"session:{sessions[0]['id']}"

    original_hget = redis_client.hget

    async def hget_then_logout(name: str, key: str) -> str | None:
        value = await original_hget(name, key)
        if name == session_key:
            await redis_client.delete(session_key)  # logout lands between rotation steps
        return value

    redis_client.hget = hget_then_logout  # type: ignore[assignment, method-assign]
    response = await refresh(client, tokens["refresh_token"])
    redis_client.hget = original_hget  # type: ignore[method-assign]

    assert response.status_code == 401
    assert await redis_client.exists(session_key) == 0
    me = await client.get("/users/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 401
