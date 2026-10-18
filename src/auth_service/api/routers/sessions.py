from fastapi import APIRouter, HTTPException, status

from auth_service.api.deps import CurrentUserDep, RedisDep, TokenPayloadDep
from auth_service.schemas.session import SessionRead
from auth_service.services import token_service

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("", response_model=list[SessionRead])
async def list_my_sessions(
    user: CurrentUserDep,
    payload: TokenPayloadDep,
    redis: RedisDep,
) -> list[SessionRead]:
    sessions = await token_service.list_sessions(redis, user.id)
    return [SessionRead(**s, current=s["id"] == payload["sid"]) for s in sessions]


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(session_id: str, user: CurrentUserDep, redis: RedisDep) -> None:
    revoked = await token_service.revoke_user_session(redis, user.id, session_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
