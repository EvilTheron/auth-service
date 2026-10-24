"""add user defaults and role check

Revision ID: c41f8a2d6e93
Revises: ea408716f5fd
Create Date: 2026-10-24 20:50:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c41f8a2d6e93"
down_revision: str | Sequence[str] | None = "ea408716f5fd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("users", "is_active", server_default=sa.true())
    op.alter_column("users", "role", server_default="user")
    op.create_check_constraint("ck_users_role", "users", "role IN ('user', 'admin')")


def downgrade() -> None:
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.alter_column("users", "role", server_default=None)
    op.alter_column("users", "is_active", server_default=None)