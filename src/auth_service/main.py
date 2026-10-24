import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from sqlalchemy import text

from auth_service.api.deps import SessionDep
from auth_service.api.routers import admin, auth, sessions, users
from auth_service.core.config import get_settings
from auth_service.core.logging import configure_logging, request_id_var

configure_logging(get_settings().log_level)
logger = logging.getLogger("auth_service.access")

app = FastAPI(title="Auth Service")
app.include_router(admin.router)
app.include_router(auth.router)
app.include_router(sessions.router)
app.include_router(users.router)


@app.middleware("http")
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
        logger.info(
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


@app.get("/health")
async def health(session: SessionDep) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.exception("database health check failed")
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok"}
