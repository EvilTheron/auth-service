from collections.abc import AsyncIterator

from httpx import AsyncClient

from auth_service.core.redis import get_redis
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


async def test_health_reports_redis_failure(client: AsyncClient):
    class BrokenRedis:
        async def ping(self) -> bool:
            raise ConnectionError("redis is down")

    app.dependency_overrides[get_redis] = lambda: BrokenRedis()
    response = await client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Redis unavailable"
