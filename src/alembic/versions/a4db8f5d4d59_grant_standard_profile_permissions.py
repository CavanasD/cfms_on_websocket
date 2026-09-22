"""grant standard profile permissions

Revision ID: a4db8f5d4d59
Revises: 0460356a5ba6
Create Date: 2026-09-15 23:38:27.057869

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a4db8f5d4d59"
down_revision: str | Sequence[str] | None = "0460356a5ba6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROFILE_PERMISSIONS = ("rename_user", "set_user_avatar")


def _permissions_table() -> sa.Table:
    return sa.table(
        "group_permissions",
        sa.column("group_name", sa.String()),
        sa.column("permission", sa.String()),
        sa.column("granted", sa.Boolean()),
        sa.column("start_time", sa.Float()),
        sa.column("end_time", sa.Float()),
    )


def upgrade() -> None:
    """Allow standard users to maintain their own profile."""
    permissions = _permissions_table()
    connection = op.get_bind()
    existing = set(
        connection.execute(
            sa.select(permissions.c.permission).where(
                permissions.c.group_name == "user",
                permissions.c.permission.in_(_PROFILE_PERMISSIONS),
                permissions.c.granted.is_(True),
                permissions.c.end_time.is_(None),
            )
        ).scalars()
    )
    rows = [
        {
            "group_name": "user",
            "permission": permission,
            "granted": True,
            "start_time": 0.0,
            "end_time": None,
        }
        for permission in _PROFILE_PERMISSIONS
        if permission not in existing
    ]
    if rows:
        op.bulk_insert(permissions, rows)


def downgrade() -> None:
    """Remove the standard profile grants added by this revision."""
    permissions = _permissions_table()
    op.execute(
        permissions.delete().where(
            permissions.c.group_name == "user",
            permissions.c.permission.in_(_PROFILE_PERMISSIONS),
            permissions.c.granted.is_(True),
            permissions.c.start_time == 0.0,
            permissions.c.end_time.is_(None),
        )
    )
