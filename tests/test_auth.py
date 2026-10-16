from httpx import AsyncClient

from tests.helpers import EMAIL, login, register


async def test_register_success(client: AsyncClient):
    response = await register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == EMAIL
    assert "password" not in body
    assert "password_hash" not in body


async def test_register_duplicate_email(client: AsyncClient):
    await register(client)
    response = await register(client, email=EMAIL.upper())
    assert response.status_code == 409


async def test_register_short_password(client: AsyncClient):
    response = await register(client, password="short")
    assert response.status_code == 422


async def test_login_success(client: AsyncClient):
    await register(client)
    response = await login(client)
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["access_token"]


async def test_login_wrong_password(client: AsyncClient):
    await register(client)
    response = await login(client, password="wrong-password")
    assert response.status_code == 401


async def test_login_unknown_email_looks_like_wrong_password(client: AsyncClient):
    await register(client)
    wrong_password = await login(client, password="wrong-password")
    unknown_email = await login(client, email="nobody@example.com")
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()
