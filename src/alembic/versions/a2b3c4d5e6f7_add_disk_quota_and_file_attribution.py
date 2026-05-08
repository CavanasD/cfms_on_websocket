"""add disk_quota to users and uploaded_by/stored_size to files

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-05-07 20:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "a2b3c4d5e6f7"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("disk_quota", sa.Integer(), nullable=True))

    with op.batch_alter_table("files", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("uploaded_by", sa.VARCHAR(length=64), nullable=True)
        )
        batch_op.add_column(sa.Column("stored_size", sa.Integer(), nullable=True))
        batch_op.create_index(
            "ix_files_uploaded_by", ["uploaded_by"], unique=False
        )
        batch_op.create_foreign_key(
            "fk_files_uploaded_by_users",
            "users",
            ["uploaded_by"],
            ["username"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("files", schema=None) as batch_op:
        batch_op.drop_constraint("fk_files_uploaded_by_users", type_="foreignkey")
        batch_op.drop_index("ix_files_uploaded_by")
        batch_op.drop_column("stored_size")
        batch_op.drop_column("uploaded_by")

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("disk_quota")
