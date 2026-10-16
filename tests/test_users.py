import pytest
from httpx import AsyncClient

from auth_service.core.config import get_settings
from tests.helpers import EMAIL, auth_headers, login, register


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
