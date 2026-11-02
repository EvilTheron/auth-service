import pytest
from httpx import AsyncClient

from auth_service.core.config import get_settings
from tests.helpers import EMAIL, PASSWORD, bearer, refresh, register


@pytest.fixture
def plain_http_cookies(monkeypatch: pytest.MonkeyPatch) -> None:
    # The test client talks plain HTTP, so it would never send back a Secure cookie.
    monkeypatch.setattr(get_settings(), "cookie_secure", False)


async def cookie_login(client: AsyncClient) -> dict[str, str]:
    await register(client)
    response = await client.post(
        "/auth/login",
        params={"delivery": "cookie"},
        data={"username": EMAIL, "password": PASSWORD},
    )
    assert response.status_code == 200
    return response.json()


async def test_cookie_login_keeps_refresh_token_out_of_body(client: AsyncClient):
    await register(client)
    response = await client.post(
        "/auth/login",
        params={"delivery": "cookie"},
        data={"username": EMAIL, "password": PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["refresh_token"] is None

    set_cookie = response.headers["set-cookie"]
    assert set_cookie.startswith("refresh_token=")
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/auth", "Max-Age="):
        assert attribute in set_cookie


async def test_body_login_sets_no_cookie(client: AsyncClient):
    await register(client)
    response = await client.post("/auth/login", data={"username": EMAIL, "password": PASSWORD})
    assert "set-cookie" not in response.headers
    assert response.json()["refresh_token"]


@pytest.mark.usefixtures("plain_http_cookies")
async def test_refresh_from_cookie_rotates_cookie(client: AsyncClient):
    await cookie_login(client)
    old_cookie = client.cookies["refresh_token"]

    response = await client.post("/auth/refresh")
    assert response.status_code == 200
    assert response.json()["refresh_token"] is None
    assert client.cookies["refresh_token"] != old_cookie

    me = await client.get("/users/me", headers=bearer(response.json()["access_token"]))
    assert me.status_code == 200


@pytest.mark.usefixtures("plain_http_cookies")
async def test_reused_cookie_token_revokes_session(client: AsyncClient):
    await cookie_login(client)
    old_cookie = client.cookies["refresh_token"]
    assert (await client.post("/auth/refresh")).status_code == 200

    assert (await refresh(client, old_cookie)).status_code == 401
    assert (await client.post("/auth/refresh")).status_code == 401


@pytest.mark.usefixtures("plain_http_cookies")
async def test_logout_clears_refresh_cookie(client: AsyncClient):
    tokens = await cookie_login(client)

    response = await client.post("/auth/logout", headers=bearer(tokens["access_token"]))
    assert response.status_code == 204
    assert "refresh_token" not in client.cookies
    assert (await client.post("/auth/refresh")).status_code == 401


@pytest.mark.usefixtures("plain_http_cookies")
async def test_logout_all_clears_refresh_cookie(client: AsyncClient):
    tokens = await cookie_login(client)

    response = await client.post("/auth/logout-all", headers=bearer(tokens["access_token"]))
    assert response.status_code == 204
    assert "refresh_token" not in client.cookies


async def test_refresh_without_any_token_is_rejected(client: AsyncClient):
    response = await client.post("/auth/refresh")
    assert response.status_code == 401
