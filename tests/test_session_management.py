from httpx import AsyncClient

from tests.helpers import bearer, login, refresh, register


async def test_logout_kills_refresh_token(client: AsyncClient):
    await register(client)
    tokens = (await login(client)).json()
    response = await client.post("/auth/logout", headers=bearer(tokens["access_token"]))
    assert response.status_code == 204
    assert (await refresh(client, tokens["refresh_token"])).status_code == 401


async def test_list_sessions_marks_current(client: AsyncClient):
    await register(client)
    first = (await login(client)).json()
    await login(client)
    response = await client.get("/sessions", headers=bearer(first["access_token"]))
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 2
    assert sum(s["current"] for s in sessions) == 1


async def test_delete_other_session(client: AsyncClient):
    await register(client)
    first = (await login(client)).json()
    second = (await login(client)).json()
    headers = bearer(first["access_token"])
    sessions = (await client.get("/sessions", headers=headers)).json()
    other = next(s for s in sessions if not s["current"])

    response = await client.delete(f"/sessions/{other['id']}", headers=headers)
    assert response.status_code == 204
    assert (await refresh(client, second["refresh_token"])).status_code == 401
    assert (await refresh(client, first["refresh_token"])).status_code == 200


async def test_logout_all_revokes_every_session(client: AsyncClient):
    await register(client)
    first = (await login(client)).json()
    second = (await login(client)).json()
    response = await client.post("/auth/logout-all", headers=bearer(first["access_token"]))
    assert response.status_code == 204
    for tokens in (first, second):
        assert (await refresh(client, tokens["refresh_token"])).status_code == 401


async def test_cannot_delete_foreign_session(client: AsyncClient):
    await register(client)
    alice = (await login(client)).json()
    alice_sessions = (await client.get("/sessions", headers=bearer(alice["access_token"]))).json()

    await register(client, email="bob@example.com")
    bob = (await login(client, email="bob@example.com")).json()
    response = await client.delete(
        f"/sessions/{alice_sessions[0]['id']}",
        headers=bearer(bob["access_token"]),
    )
    assert response.status_code == 404
    assert (await refresh(client, alice["refresh_token"])).status_code == 200
