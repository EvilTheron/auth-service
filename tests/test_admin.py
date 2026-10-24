import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from auth_service.services import user_service
from tests.helpers import EMAIL, auth_headers, bearer, login, make_admin, refresh, register


async def test_admin_endpoint_requires_token(client: AsyncClient):
    response = await client.get("/admin/users")
    assert response.status_code == 401


async def test_regular_user_gets_403(client: AsyncClient):
    headers = await auth_headers(client)
    response = await client.get("/admin/users", headers=headers)
    assert response.status_code == 403


async def test_admin_can_list_users(client: AsyncClient, engine: AsyncEngine):
    headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    response = await client.get("/admin/users", headers=headers)
    assert response.status_code == 200
    assert response.json()[0]["email"] == EMAIL


async def test_deactivate_user_revokes_access(client: AsyncClient, engine: AsyncEngine):
    admin_headers = await auth_headers(client)
    await make_admin(engine, EMAIL)

    await register(client, email="bob@example.com")
    bob = (await login(client, email="bob@example.com")).json()
    users = (await client.get("/admin/users", headers=admin_headers)).json()
    bob_id = next(u["id"] for u in users if u["email"] == "bob@example.com")

    response = await client.post(f"/admin/users/{bob_id}/deactivate", headers=admin_headers)
    assert response.status_code == 204
    assert (await client.get("/users/me", headers=bearer(bob["access_token"]))).status_code == 401
    assert (await refresh(client, bob["refresh_token"])).status_code == 401


async def test_admin_cannot_deactivate_self(client: AsyncClient, engine: AsyncEngine):
    headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    me = (await client.get("/users/me", headers=headers)).json()
    response = await client.post(f"/admin/users/{me['id']}/deactivate", headers=headers)
    assert response.status_code == 400


async def test_deactivate_unknown_user(client: AsyncClient, engine: AsyncEngine):
    headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    response = await client.post(f"/admin/users/{uuid.uuid4()}/deactivate", headers=headers)
    assert response.status_code == 404


async def test_set_role_promotes_existing_user(client: AsyncClient, engine: AsyncEngine):
    await register(client)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        user = await user_service.set_role(session, EMAIL.upper(), "admin")
        missing = await user_service.set_role(session, "nobody@example.com", "admin")
    assert user is not None and user.role == "admin"
    assert missing is None
