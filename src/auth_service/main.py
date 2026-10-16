from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from auth_service.api.deps import SessionDep
from auth_service.api.routers import auth, users

app = FastAPI(title="Auth Service")
app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health")
async def health(session: SessionDep) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok"}
