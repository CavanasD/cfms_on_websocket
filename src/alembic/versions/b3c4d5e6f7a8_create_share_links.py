"""create share_links table

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-05-07 21:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, Sequence[str], None] = "a2b3c4d5e6f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "share_links",
        sa.Column("token", sa.VARCHAR(length=64), nullable=False),
        sa.Column("document_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("created_by", sa.VARCHAR(length=64), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=True),
        sa.Column("max_downloads", sa.Integer(), nullable=True),
        sa.Column("download_count", sa.Integer(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["document_id"], ["documents.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.username"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("token"),
    )
    op.create_index(
        "ix_share_links_document_id", "share_links", ["document_id"], unique=False
    )
    op.create_index(
        "ix_share_links_created_by", "share_links", ["created_by"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_share_links_created_by", table_name="share_links")
    op.drop_index("ix_share_links_document_id", table_name="share_links")
    op.drop_table("share_links")
