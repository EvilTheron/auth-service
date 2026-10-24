import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from auth_service.core.config import get_settings
from tests.helpers import EMAIL, auth_headers, bearer, login, refresh, register, set_inactive

pytestmark = pytest.mark.asyncio


async def test_me_success(client: AsyncClient):
    headers = await auth_headers(client)
    response = await client.get("/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL


async def test_me_without_token(client: AsyncClient):
    response = await client.get("/users/me")
    assert response.status_code == 401


async def test_me_forged_token(client: AsyncClient):
    headers = await auth_headers(client)
    forged = {"Authorization": headers["Authorization"][:-3] + "abc"}
    response = await client.get("/users/me", headers=forged)
    assert response.status_code == 401


async def test_me_expired_token(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    await register(client)
    monkeypatch.setattr(get_settings(), "access_token_expire_minutes", -1)
    token = (await login(client)).json()["access_token"]
    response = await client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


async def test_inactive_user_is_rejected_even_with_live_session(
    client: AsyncClient, engine: AsyncEngine
):
    await register(client)
    tokens = (await login(client)).json()
    await set_inactive(engine, EMAIL)  # sessions are left alive on purpose

    me = await client.get("/users/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 401
    assert (await refresh(client, tokens["refresh_token"])).status_code == 401
