from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.helpers import EMAIL, auth_headers, login, make_admin, refresh, register


async def get_events(client: AsyncClient, headers: dict[str, str], event: str) -> list[dict]:
    response = await client.get("/admin/audit", params={"event": event}, headers=headers)
    assert response.status_code == 200
    return response.json()


async def test_login_events_are_audited(client: AsyncClient, engine: AsyncEngine):
    headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    await login(client, password="wrong-password")

    failed = await get_events(client, headers, "login_failed")
    success = await get_events(client, headers, "login_success")
    assert [e["email"] for e in failed] == [EMAIL]
    assert len(success) == 1


async def test_refresh_reuse_is_audited(client: AsyncClient, engine: AsyncEngine):
    headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    tokens = (await login(client)).json()
    await refresh(client, tokens["refresh_token"])
    await refresh(client, tokens["refresh_token"])

    events = await get_events(client, headers, "refresh_reuse")
    assert len(events) == 1


async def test_audit_requires_admin(client: AsyncClient):
    headers = await auth_headers(client)
    response = await client.get("/admin/audit", headers=headers)
    assert response.status_code == 403


async def test_deactivation_is_audited(client: AsyncClient, engine: AsyncEngine):
    admin_headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    await register(client, email="bob@example.com")
    users = (await client.get("/admin/users", headers=admin_headers)).json()
    bob_id = next(u["id"] for u in users if u["email"] == "bob@example.com")
    await client.post(f"/admin/users/{bob_id}/deactivate", headers=admin_headers)

    events = await get_events(client, admin_headers, "user_deactivated")
    assert len(events) == 1
    assert events[0]["email"] == "bob@example.com"
    assert events[0]["details"].startswith("by admin")


async def test_blocked_attempts_do_not_flood_the_audit_log(
    client: AsyncClient, engine: AsyncEngine
):
    headers = await auth_headers(client)
    await make_admin(engine, EMAIL)
    await register(client, email="bob@example.com")
    for _ in range(5):
        await login(client, email="bob@example.com", password="wrong-password")
    for _ in range(3):
        response = await login(client, email="bob@example.com", password="wrong-password")
        assert response.status_code == 429

    events = await get_events(client, headers, "login_failed")
    assert len(events) == 5
