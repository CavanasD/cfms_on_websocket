"""add home_directory_id to users

Revision ID: f1a2b3c4d5e6
Revises: 5b4437a79292
Create Date: 2026-05-07 20:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "5b4437a79292"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("home_directory_id", sa.VARCHAR(length=255), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_users_home_directory_id_folders",
            "folders",
            ["home_directory_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_constraint("fk_users_home_directory_id_folders", type_="foreignkey")
        batch_op.drop_column("home_directory_id")
