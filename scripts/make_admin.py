import asyncio
import sys

from auth_service.db.session import SessionLocal, engine
from auth_service.services import audit_service, user_service


async def main(email: str) -> None:
    async with SessionLocal() as session:
        user = await user_service.set_role(session, email, "admin")
        if user is None:
            print("User not found")
        else:
            await audit_service.record(
                session,
                "role_changed",
                user_id=user.id,
                email=user.email,
                details="role set to admin by make_admin script",
            )
            print("Done")
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
