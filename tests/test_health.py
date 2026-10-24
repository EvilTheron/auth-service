from collections.abc import AsyncIterator

from httpx import AsyncClient

from auth_service.db.session import get_session
from auth_service.main import app


async def test_health_ok(client: AsyncClient):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_health_reports_database_failure(client: AsyncClient):
    class BrokenSession:
        async def execute(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("database is down")

    async def broken_session() -> AsyncIterator[BrokenSession]:
        yield BrokenSession()

    app.dependency_overrides[get_session] = broken_session
    response = await client.get("/health")
    assert response.status_code == 503
