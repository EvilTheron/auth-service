import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.db.models import AuditEvent, AuditLog


async def record(
    session: AsyncSession,
    event: AuditEvent,
    *,
    user_id: uuid.UUID | None = None,
    email: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    details: str | None = None,
) -> None:
    session.add(
        AuditLog(
            event=event,
            user_id=user_id,
            email=email[:255] if email else None,
            ip=ip[:45] if ip else None,
            user_agent=user_agent[:255] if user_agent else None,
            details=details[:255] if details else None,
        )
    )
    await session.commit()


async def list_events(
    session: AsyncSession,
    *,
    event: AuditEvent | None,
    user_id: uuid.UUID | None,
    limit: int,
    offset: int,
) -> list[AuditLog]:
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    if event is not None:
        query = query.where(AuditLog.event == event)
    if user_id is not None:
        query = query.where(AuditLog.user_id == user_id)
    result = await session.execute(query)
    return list(result.scalars())
