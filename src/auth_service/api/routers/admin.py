import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from auth_service.api.deps import AdminDep, RedisDep, SessionDep, client_info
from auth_service.db.models import AuditLog, User
from auth_service.schemas.audit import AuditRead
from auth_service.schemas.user import AdminUserRead
from auth_service.services import audit_service, token_service, user_service

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[AdminUserRead])
async def list_users(
    admin: AdminDep,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[User]:
    return await user_service.list_users(session, limit=limit, offset=offset)


@router.post("/users/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    admin: AdminDep,
    session: SessionDep,
    redis: RedisDep,
) -> None:
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate yourself",
        )
    user = await user_service.get_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = False
    await session.commit()
    await token_service.revoke_all_sessions(redis, user.id)

    ip, user_agent = client_info(request)
    await audit_service.record(
        session,
        "user_deactivated",
        user_id=user.id,
        email=user.email,
        ip=ip,
        user_agent=user_agent,
        details=f"by admin {admin.id}",
    )


@router.get("/audit", response_model=list[AuditRead])
async def read_audit(
    admin: AdminDep,
    session: SessionDep,
    event: str | None = None,
    user_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditLog]:
    return await audit_service.list_events(
        session, event=event, user_id=user_id, limit=limit, offset=offset
    )
