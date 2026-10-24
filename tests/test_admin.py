from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from auth_service.db.models import User
from tests.helpers import EMAIL, auth_headers, bearer, login, refresh, register


async def make_admin(engine: AsyncEngine, email: str) -> None:
    async with AsyncSession(engine) as session:
        await session.execute(update(User).where(User.email == email).values(role="admin"))
        await session.commit()


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
