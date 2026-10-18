from httpx import AsyncClient
from redis.asyncio import Redis

from tests.helpers import EMAIL, login, register


async def test_account_locked_after_repeated_failures(client: AsyncClient):
    await register(client)
    for _ in range(5):
        response = await login(client, password="wrong-password")
        assert response.status_code == 401

    response = await login(client)
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


async def test_lock_applies_to_unknown_email_too(client: AsyncClient):
    for _ in range(5):
        await login(client, email="ghost@example.com", password="whatever-password")
    response = await login(client, email="ghost@example.com", password="whatever-password")
    assert response.status_code == 429


async def test_successful_login_resets_failure_counter(client: AsyncClient):
    await register(client)
    for _ in range(4):
        await login(client, password="wrong-password")
    assert (await login(client)).status_code == 200
    for _ in range(4):
        assert (await login(client, password="wrong-password")).status_code == 401
    assert (await login(client)).status_code == 200


async def test_lock_duration_grows(client: AsyncClient, redis_client: Redis):
    await register(client)
    for _ in range(5):
        await login(client, password="wrong-password")
    first_lock = await redis_client.ttl(f"login:lock:{EMAIL}")

    await redis_client.delete(f"login:lock:{EMAIL}")
    await login(client, password="wrong-password")
    second_lock = await redis_client.ttl(f"login:lock:{EMAIL}")

    assert second_lock > first_lock


async def test_ip_blocked_after_too_many_failures(client: AsyncClient):
    for i in range(20):
        await login(client, email=f"user{i}@example.com", password="whatever-password")
    response = await login(client, email="another@example.com", password="whatever-password")
    assert response.status_code == 429
