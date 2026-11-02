from enum import StrEnum

from pydantic import BaseModel


class TokenDelivery(StrEnum):
    BODY = "body"
    COOKIE = "cookie"


class Token(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    password_compromised: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str
