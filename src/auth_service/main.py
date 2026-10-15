from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.db.session import get_session

app = FastAPI(title="Auth Service")

SessionDep = Annotated[AsyncSession, Depends(get_session)]


@app.get("/health")
async def health(session: SessionDep) -> dict[str, str]:
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok"}
