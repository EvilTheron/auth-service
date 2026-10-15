from fastapi import APIRouter, HTTPException, status

from auth_service.api.deps import SessionDep
from auth_service.db.models import User
from auth_service.schemas.user import UserCreate, UserRead
from auth_service.services import user_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(data: UserCreate, session: SessionDep) -> User:
    try:
        return await user_service.create_user(session, data.email, data.password)
    except user_service.EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        ) from exc
