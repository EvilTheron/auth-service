import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from sqlalchemy import text

from auth_service.api.deps import RedisDep, SessionDep
from auth_service.api.routers import admin, auth, sessions, users
from auth_service.core.config import Settings, get_settings
from auth_service.core.logging import configure_logging, request_id_var
from auth_service.core.redis import get_redis
from auth_service.db.session import engine

logger = logging.getLogger("auth_service.access")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    await get_redis().aclose()
    await engine.dispose()


async def log_requests(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    request_id = uuid.uuid4().hex[:12]
    token = request_id_var.set(request_id)
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("%s %s failed", request.method, request.url.path)
        raise
    else:
        duration_ms = (time.perf_counter() - start) * 1000
        level = logging.INFO
        if request.url.path == "/health" and response.status_code == 200:
            level = logging.DEBUG
        logger.log(
            level,
            "%s %s -> %d (%.0f ms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        request_id_var.reset(token)


async def health(session: SessionDep, redis: RedisDep) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.exception("database health check failed")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    try:
        await redis.ping()
    except Exception as exc:
        logger.exception("redis health check failed")
        raise HTTPException(status_code=503, detail="Redis unavailable") from exc
    return {"status": "ok"}


def create_app(settings: Settings) -> FastAPI:
    configure_logging(settings.log_level)
    application = FastAPI(
        title="Auth Service",
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    application.middleware("http")(log_requests)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(sessions.router)
    application.include_router(admin.router)
    application.get("/health")(health)
    return application


app = create_app(get_settings())
