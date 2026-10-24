import asyncio
import sys

from sqlalchemy import update

from auth_service.db.models import User
from auth_service.db.session import SessionLocal, engine


async def main(email: str) -> None:
    async with SessionLocal() as session:
        result = await session.execute(
            update(User).where(User.email == email.lower()).values(role="admin")
        )
        await session.commit()
        print("Done" if result.rowcount else "User not found")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
