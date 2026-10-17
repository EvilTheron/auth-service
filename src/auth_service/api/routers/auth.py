from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from auth_service.api.deps import RedisDep, SessionDep
from auth_service.core.security import create_access_token
from auth_service.db.models import User
from auth_service.schemas.token import Token
from auth_service.schemas.user import UserCreate, UserRead
from auth_service.services import token_service, user_service

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


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
    redis: RedisDep,
) -> Token:
    user = await user_service.authenticate(session, form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    session_id, refresh_token = await token_service.create_session(
        redis,
        user.id,
        user_agent=request.headers.get("user-agent", ""),
        ip=request.client.host if request.client else "",
    )
    return Token(
        access_token=create_access_token(user.id, session_id),
        refresh_token=refresh_token,
    )
