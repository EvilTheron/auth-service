from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from auth_service.api.deps import get_password_filter
from auth_service.core.config import get_settings
from auth_service.core.redis import get_redis
from auth_service.db import models  # noqa: F401
from auth_service.db.base import Base
from auth_service.db.session import get_session
from auth_service.main import app

TEST_DB_NAME = "auth_service_test"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    url = get_settings().database_url.set(database=TEST_DB_NAME)
    test_engine = create_async_engine(url, poolclass=NullPool)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield test_engine
    await test_engine.dispose()


@pytest.fixture
async def redis_client() -> AsyncIterator[Redis]:
    settings = get_settings()
    test_redis = Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=1,
        decode_responses=True,
    )
    await test_redis.flushdb()
    yield test_redis
    await test_redis.aclose()


@pytest.fixture
async def client(engine: AsyncEngine, redis_client: Redis) -> AsyncIterator[AsyncClient]:
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    def override_get_redis() -> Redis:
        return redis_client

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_redis] = override_get_redis
    app.dependency_overrides[get_password_filter] = lambda: None
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()
