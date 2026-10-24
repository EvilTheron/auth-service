import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.core.security import hash_password, hash_password_async, verify_password_async
from auth_service.db.models import User

_DUMMY_HASH = hash_password("dummy-password")


class EmailAlreadyRegisteredError(Exception):
    pass


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()


async def create_user(session: AsyncSession, email: str, password: str) -> User:
    user = User(email=email.lower(), password_hash=await hash_password_async(password))
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise EmailAlreadyRegisteredError from exc
    await session.refresh(user)
    return user


async def authenticate(session: AsyncSession, email: str, password: str) -> User | None:
    user = await get_user_by_email(session, email)
    # Завершаем читающую транзакцию, чтобы вернуть соединение в пул до медленной
    # проверки пароля: иначе параллельные входы занимают все соединения с базой.
    await session.commit()
    if user is None:
        await verify_password_async(password, _DUMMY_HASH)
        return None
    if not await verify_password_async(password, user.password_hash) or not user.is_active:
        return None
    return user


async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return await session.get(User, user_id)


async def list_users(session: AsyncSession, *, limit: int, offset: int) -> list[User]:
    result = await session.execute(
        select(User).order_by(User.created_at).limit(limit).offset(offset)
    )
    return list(result.scalars())


async def change_password(session: AsyncSession, user: User, new_password: str) -> None:
    user.password_hash = await hash_password_async(new_password)
    await session.commit()


async def set_role(session: AsyncSession, email: str, role: str) -> User | None:
    user = await get_user_by_email(session, email)
    if user is None:
        return None
    user.role = role
    await session.commit()
    return user
