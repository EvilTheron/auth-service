import logging
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from auth_service.core.config import get_settings
from auth_service.core.redis import get_redis
from auth_service.db.session import get_session
from auth_service.main import app, create_app


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


async def test_successful_health_checks_are_not_logged_at_info(
    client: AsyncClient, caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.INFO, logger="auth_service.access")
    await client.get("/health")
    await client.get("/users/me")
    assert "GET /health" not in caplog.text
    assert "GET /users/me -> 401" in caplog.text


async def test_docs_can_be_disabled():
    settings = get_settings().model_copy(update={"docs_enabled": False})
    transport = ASGITransport(app=create_app(settings))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/docs")).status_code == 404
        assert (await client.get("/openapi.json")).status_code == 404
