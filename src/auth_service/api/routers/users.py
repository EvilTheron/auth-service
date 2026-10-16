from fastapi import APIRouter

from auth_service.api.deps import CurrentUserDep
from auth_service.db.models import User
from auth_service.schemas.user import UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserRead)
async def read_me(current_user: CurrentUserDep) -> User:
    return current_user
