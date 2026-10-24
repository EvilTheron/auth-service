import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    event: str
    user_id: uuid.UUID | None
    email: str | None
    ip: str | None
    user_agent: str | None
    details: str | None
