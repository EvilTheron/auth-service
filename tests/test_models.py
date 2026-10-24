import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine


async def test_user_columns_have_database_defaults(engine: AsyncEngine):
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "insert into users (id, email, password_hash) "
                "values (gen_random_uuid(), 'raw@example.com', 'x')"
            )
        )
        row = (
            await conn.execute(
                text("select is_active, role from users where email = 'raw@example.com'")
            )
        ).one()
    assert row.is_active is True
    assert row.role == "user"


async def test_unknown_role_is_rejected_by_database(engine: AsyncEngine):
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "insert into users (id, email, password_hash, role) "
                    "values (gen_random_uuid(), 'bad@example.com', 'x', 'superuser')"
                )
            )
