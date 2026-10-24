from httpx import AsyncClient, Response
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from auth_service.db.models import User

EMAIL = "user@example.com"
PASSWORD = "correct-horse-battery"


async def register(client: AsyncClient, email: str = EMAIL, password: str = PASSWORD) -> Response:
    return await client.post("/auth/register", json={"email": email, "password": password})


async def login(client: AsyncClient, email: str = EMAIL, password: str = PASSWORD) -> Response:
    return await client.post("/auth/login", data={"username": email, "password": password})


async def auth_headers(client: AsyncClient) -> dict[str, str]:
    await register(client)
    token = (await login(client)).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def refresh(client: AsyncClient, refresh_token: str) -> Response:
    return await client.post("/auth/refresh", json={"refresh_token": refresh_token})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def make_admin(engine: AsyncEngine, email: str) -> None:
    async with AsyncSession(engine) as session:
        await session.execute(update(User).where(User.email == email).values(role="admin"))
        await session.commit()
