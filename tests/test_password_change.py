from httpx import AsyncClient

from auth_service.api.deps import get_password_filter
from auth_service.main import app
from tests.helpers import (
    PASSWORD,
    auth_headers,
    bearer,
    change_password,
    login,
    make_filter,
    refresh,
    register,
)

NEW_PASSWORD = "another-strong-password"


async def test_change_password_success(client: AsyncClient):
    headers = await auth_headers(client)
    response = await change_password(client, headers, PASSWORD, NEW_PASSWORD)
    assert response.status_code == 204
    assert (await login(client, password=PASSWORD)).status_code == 401
    assert (await login(client, password=NEW_PASSWORD)).status_code == 200


async def test_change_password_wrong_current(client: AsyncClient):
    headers = await auth_headers(client)
    response = await change_password(client, headers, "wrong-password", NEW_PASSWORD)
    assert response.status_code == 400


async def test_change_password_same_password(client: AsyncClient):
    headers = await auth_headers(client)
    response = await change_password(client, headers, PASSWORD, PASSWORD)
    assert response.status_code == 400


async def test_change_password_rejects_leaked_password(client: AsyncClient):
    headers = await auth_headers(client)
    app.dependency_overrides[get_password_filter] = lambda: make_filter(NEW_PASSWORD)
    response = await change_password(client, headers, PASSWORD, NEW_PASSWORD)
    assert response.status_code == 400


async def test_change_password_keeps_current_session_and_revokes_others(client: AsyncClient):
    await register(client)
    first = (await login(client)).json()
    second = (await login(client)).json()

    response = await change_password(client, bearer(first["access_token"]), PASSWORD, NEW_PASSWORD)
    assert response.status_code == 204

    assert (await client.get("/users/me", headers=bearer(first["access_token"]))).status_code == 200
    assert (await refresh(client, second["refresh_token"])).status_code == 401
    assert (
        await client.get("/users/me", headers=bearer(second["access_token"]))
    ).status_code == 401


async def test_login_flags_compromised_password(client: AsyncClient):
    await register(client)
    app.dependency_overrides[get_password_filter] = lambda: make_filter(PASSWORD)
    response = await login(client)
    assert response.status_code == 200
    assert response.json()["password_compromised"] is True


async def test_login_does_not_flag_normal_password(client: AsyncClient):
    await register(client)
    response = await login(client)
    assert response.json()["password_compromised"] is False


async def test_change_password_is_throttled(client: AsyncClient):
    headers = await auth_headers(client)
    for _ in range(20):
        await change_password(client, headers, "wrong-password", NEW_PASSWORD)
    response = await change_password(client, headers, PASSWORD, NEW_PASSWORD)
    assert response.status_code == 429
