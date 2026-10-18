from datetime import datetime

from pydantic import BaseModel


class SessionRead(BaseModel):
    id: str
    user_agent: str
    ip: str
    created_at: datetime
    last_used_at: datetime
    current: bool
