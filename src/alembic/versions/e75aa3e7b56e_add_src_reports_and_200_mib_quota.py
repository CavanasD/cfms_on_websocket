"""add src reports and 200 mib quota

Revision ID: e75aa3e7b56e
Revises: 7d83baf2c941
Create Date: 2026-08-29 22:39:21.694653

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e75aa3e7b56e"
down_revision: str | Sequence[str] | None = "7d83baf2c941"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_DISK_QUOTA_BYTES = 10 * 1024**3
DISK_QUOTA_BYTES = 200 * 1024**2


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "disk_quota",
            existing_type=sa.BigInteger(),
            existing_nullable=False,
            server_default=str(DISK_QUOTA_BYTES),
        )
    users = sa.table("users", sa.column("disk_quota", sa.BigInteger()))
    op.execute(users.update().values(disk_quota=DISK_QUOTA_BYTES))

    op.create_table(
        "src_reports",
        sa.Column("id", sa.VARCHAR(length=64), nullable=False),
        sa.Column("reporter_username", sa.VARCHAR(length=64), nullable=False),
        sa.Column("title", sa.VARCHAR(length=160), nullable=False),
        sa.Column("category", sa.VARCHAR(length=64), nullable=False),
        sa.Column("severity", sa.VARCHAR(length=16), nullable=False),
        sa.Column("affected_url", sa.Text(), nullable=True),
        sa.Column("description_md", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.VARCHAR(length=16),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["reporter_username"],
            ["users.username"],
            name=op.f("fk_src_reports_reporter_username_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_src_reports")),
    )
    with op.batch_alter_table("src_reports", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_src_reports_created_at"), ["created_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_src_reports_reporter_username"),
            ["reporter_username"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_src_reports_updated_at"), ["updated_at"], unique=False
        )

    op.create_table(
        "src_report_attachments",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("report_id", sa.VARCHAR(length=64), nullable=False),
        sa.Column("document_id", sa.VARCHAR(length=255), nullable=True),
        sa.Column("filename", sa.VARCHAR(length=255), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.VARCHAR(length=255), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name=op.f("fk_src_report_attachments_document_id_documents"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["src_reports.id"],
            name=op.f("fk_src_report_attachments_report_id_src_reports"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_src_report_attachments")),
        sa.UniqueConstraint(
            "document_id", name=op.f("uq_src_report_attachments_document_id")
        ),
    )
    with op.batch_alter_table("src_report_attachments", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_src_report_attachments_report_id"),
            ["report_id"],
            unique=False,
        )

    op.create_table(
        "src_report_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("report_id", sa.VARCHAR(length=64), nullable=False),
        sa.Column("actor_username", sa.VARCHAR(length=64), nullable=True),
        sa.Column("from_status", sa.VARCHAR(length=16), nullable=True),
        sa.Column("to_status", sa.VARCHAR(length=16), nullable=False),
        sa.Column("note_md", sa.Text(), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["actor_username"],
            ["users.username"],
            name=op.f("fk_src_report_events_actor_username_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["src_reports.id"],
            name=op.f("fk_src_report_events_report_id_src_reports"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_src_report_events")),
    )
    with op.batch_alter_table("src_report_events", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_src_report_events_created_at"),
            ["created_at"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_src_report_events_report_id"),
            ["report_id"],
            unique=False,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("src_report_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_src_report_events_report_id"))
        batch_op.drop_index(batch_op.f("ix_src_report_events_created_at"))

    op.drop_table("src_report_events")
    with op.batch_alter_table("src_report_attachments", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_src_report_attachments_report_id"))

    op.drop_table("src_report_attachments")
    with op.batch_alter_table("src_reports", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_src_reports_updated_at"))
        batch_op.drop_index(batch_op.f("ix_src_reports_reporter_username"))
        batch_op.drop_index(batch_op.f("ix_src_reports_created_at"))

    op.drop_table("src_reports")

    users = sa.table("users", sa.column("disk_quota", sa.BigInteger()))
    op.execute(
        users.update()
        .where(users.c.disk_quota == DISK_QUOTA_BYTES)
        .values(disk_quota=OLD_DISK_QUOTA_BYTES)
    )
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column(
            "disk_quota",
            existing_type=sa.BigInteger(),
            existing_nullable=False,
            server_default=str(OLD_DISK_QUOTA_BYTES),
        )
