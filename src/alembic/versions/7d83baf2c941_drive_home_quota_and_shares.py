"""add cloud-drive homes, quotas, and share links

Revision ID: 7d83baf2c941
Revises: 6cc4a094da7a
Create Date: 2026-07-15 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7d83baf2c941"
down_revision: str | Sequence[str] | None = "6cc4a094da7a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_DISK_QUOTA_BYTES = 10 * 1024**3


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("home_directory_id", sa.VARCHAR(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "disk_quota",
                sa.BigInteger(),
                nullable=False,
                server_default=str(DEFAULT_DISK_QUOTA_BYTES),
            )
        )
        batch_op.create_unique_constraint(
            "uq_users_home_directory_id", ["home_directory_id"]
        )
        batch_op.create_foreign_key(
            "fk_users_home_directory_id_folders",
            "folders",
            ["home_directory_id"],
            ["id"],
            ondelete="SET NULL",
            use_alter=True,
        )

    op.create_table(
        "share_links",
        sa.Column("token", sa.VARCHAR(length=64), nullable=False),
        sa.Column("document_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("created_by", sa.VARCHAR(length=64), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=True),
        sa.Column("max_downloads", sa.Integer(), nullable=True),
        sa.Column("download_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("revoked", sa.Boolean(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.username"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["document_id"], ["documents.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("token"),
    )
    op.create_index(
        op.f("ix_share_links_created_by"), "share_links", ["created_by"], unique=False
    )
    op.create_index(
        op.f("ix_share_links_document_id"),
        "share_links",
        ["document_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_share_links_document_id"), table_name="share_links")
    op.drop_index(op.f("ix_share_links_created_by"), table_name="share_links")
    op.drop_table("share_links")

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_constraint(
            "fk_users_home_directory_id_folders", type_="foreignkey"
        )
        batch_op.drop_constraint("uq_users_home_directory_id", type_="unique")
        batch_op.drop_column("disk_quota")
        batch_op.drop_column("home_directory_id")
