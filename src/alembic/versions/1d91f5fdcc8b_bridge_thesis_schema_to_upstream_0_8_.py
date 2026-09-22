"""bridge thesis schema to upstream 0.8 baseline

Revision ID: 1d91f5fdcc8b
Revises: e75aa3e7b56e
Create Date: 2026-09-08 21:10:32.334059

"""
import hashlib
import json
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1d91f5fdcc8b'
down_revision: str | Sequence[str] | None = 'e75aa3e7b56e'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    _widen_user_keys()
    for table, columns in (("banned_subnets", ("created_at",)), ("login_throttles", ("last_attempt", "locked_until")), ("traffic_throttles", ("last_attempt", "locked_until"))):
        for column in columns:
            _convert_epoch(table, column)
    op.create_table('account_throttles',
    sa.Column('username', sa.String(length=256), nullable=False),
    sa.Column('factor', sa.String(length=16), nullable=False),
    sa.Column('failed_attempts', sa.Integer(), nullable=False),
    sa.Column('last_attempt', sa.Double(), nullable=False),
    sa.Column('locked_until', sa.Double(), nullable=True),
    sa.PrimaryKeyConstraint('username', 'factor', name=op.f('pk_account_throttles'))
    )
    with op.batch_alter_table('account_throttles', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_account_throttles_last_attempt'), ['last_attempt'], unique=False)

    op.create_table('comments',
    sa.Column('comment_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('digest_version', sa.SmallInteger(), nullable=False),
    sa.Column('content_digest', sa.LargeBinary(length=32).with_variant(sa.BINARY(length=32), 'mysql'), nullable=False),
    sa.Column('comment_text', sa.Text(), nullable=False),
    sa.Column('comment_data', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('comment_id', name=op.f('pk_comments')),
    sa.UniqueConstraint('digest_version', 'content_digest', name='uq_comments_content_digest')
    )
    op.create_table('rate_limit_buckets',
    sa.Column('namespace', sa.VARCHAR(length=64), nullable=False),
    sa.Column('scope', sa.VARCHAR(length=16), nullable=False),
    sa.Column('identity', sa.VARCHAR(length=256), nullable=False),
    sa.Column('tokens', sa.Double(), nullable=False),
    sa.Column('last_refill_at', sa.Double(), nullable=False),
    sa.Column('denial_count', sa.Integer(), nullable=False),
    sa.Column('last_denied_at', sa.Double(), nullable=True),
    sa.Column('last_attempt', sa.Double(), nullable=False),
    sa.PrimaryKeyConstraint('namespace', 'scope', 'identity', name=op.f('pk_rate_limit_buckets'))
    )
    with op.batch_alter_table('rate_limit_buckets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_rate_limit_buckets_last_attempt'), ['last_attempt'], unique=False)

    op.create_table('risk_ip_accounts',
    sa.Column('namespace', sa.VARCHAR(length=64), nullable=False),
    sa.Column('ip_address', sa.VARCHAR(length=45), nullable=False),
    sa.Column('username', sa.VARCHAR(length=256), nullable=False),
    sa.Column('last_attempt', sa.Double(), nullable=False),
    sa.PrimaryKeyConstraint('namespace', 'ip_address', 'username', name=op.f('pk_risk_ip_accounts'))
    )
    with op.batch_alter_table('risk_ip_accounts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_risk_ip_accounts_last_attempt'), ['last_attempt'], unique=False)

    op.create_table('system_states',
    sa.Column('owner', sa.VARCHAR(length=255), nullable=False),
    sa.Column('state_key', sa.VARCHAR(length=128), nullable=False),
    sa.Column('schema_version', sa.Integer(), nullable=False),
    sa.Column('revision', sa.BigInteger(), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('updated_at', sa.Double(), nullable=False),
    sa.CheckConstraint('revision > 0', name='ck_system_states_revision_positive'),
    sa.CheckConstraint('schema_version > 0', name='ck_system_states_schema_version_positive'),
    sa.PrimaryKeyConstraint('owner', 'state_key', name=op.f('pk_system_states'))
    )
    op.create_table('file_deduplication_tasks',
    sa.Column('file_id', sa.VARCHAR(length=255), nullable=False),
    sa.Column('phase', sa.Integer(), nullable=False),
    sa.Column('available_at', sa.Double(), nullable=False),
    sa.Column('lease_owner', sa.VARCHAR(length=64), nullable=True),
    sa.Column('lease_expires_at', sa.Double(), nullable=True),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_time', sa.Double(), nullable=False),
    sa.CheckConstraint('phase IN (0, 1)', name='ck_file_deduplication_tasks_phase_value'),
    sa.ForeignKeyConstraint(['file_id'], ['files.id'], name=op.f('fk_file_deduplication_tasks_file_id_files'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('file_id', name=op.f('pk_file_deduplication_tasks'))
    )
    with op.batch_alter_table('file_deduplication_tasks', schema=None) as batch_op:
        batch_op.create_index('ix_file_deduplication_tasks_available_lease', ['available_at', 'lease_expires_at'], unique=False)

    with op.batch_alter_table('banned_subnets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reason_comment_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=True))
        batch_op.add_column(sa.Column('starts_at', sa.Double(), nullable=True))
        batch_op.add_column(sa.Column('expires_at', sa.Double(), nullable=True))
        batch_op.create_foreign_key(batch_op.f('fk_banned_subnets_reason_comment_id_comments'), 'comments', ['reason_comment_id'], ['comment_id'], ondelete='SET NULL')

    with op.batch_alter_table('file_tasks', schema=None) as batch_op:
        batch_op.add_column(sa.Column('issued_by_username', sa.VARCHAR(length=256), nullable=True))
        batch_op.add_column(sa.Column('chunk_size', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('upload_file_size', sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column('upload_sha256', sa.VARCHAR(length=64), nullable=True))
        batch_op.add_column(sa.Column('upload_session_id', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('upload_checkpoint_size', sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column('upload_checkpoint_data', sa.Text(), nullable=True))
        batch_op.create_index('ix_file_tasks_file_id_mode_status', ['file_id', 'mode', 'status'], unique=False)
        batch_op.create_index('ix_file_tasks_mode_status_end_time', ['mode', 'status', 'end_time'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_file_tasks_issued_by_username_users'), 'users', ['issued_by_username'], ['username'], ondelete='SET NULL')
        batch_op.create_check_constraint('ck_file_tasks_status_value', 'status IN (0, 1, 2, 3, 4)')

    with op.batch_alter_table('files', schema=None) as batch_op:
        batch_op.create_index('ix_files_sha256_active_created_time_id', ['sha256', 'active', 'created_time', 'id'], unique=False)

    with op.batch_alter_table('login_throttles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('window_started_at', sa.Double(), nullable=True))
        batch_op.create_index(batch_op.f('ix_login_throttles_last_attempt'), ['last_attempt'], unique=False)

    with op.batch_alter_table('traffic_throttles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('window_started_at', sa.Double(), nullable=True))
        batch_op.create_index(batch_op.f('ix_traffic_throttles_last_attempt'), ['last_attempt'], unique=False)

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status_comment_id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=True))
        batch_op.create_index(batch_op.f('ix_users_avatar_id'), ['avatar_id'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_users_status_comment_id_comments'), 'comments', ['status_comment_id'], ['comment_id'], ondelete='SET NULL')

    op.execute("UPDATE banned_subnets SET starts_at = created_at")
    for table in ("login_throttles", "traffic_throttles"):
        op.execute(sa.text(f"UPDATE {table} SET window_started_at = last_attempt"))
        with op.batch_alter_table(table) as batch:
            batch.alter_column("window_started_at", existing_type=sa.Double(), nullable=False)
    with op.batch_alter_table("banned_subnets") as batch:
        batch.alter_column("starts_at", existing_type=sa.Double(), nullable=False)
    _preserve_subnet_reasons()
    permissions = sa.table("group_permissions", sa.column("group_name"), sa.column("permission"), sa.column("granted"), sa.column("start_time"), sa.column("end_time"))
    for group in ("user", "sysop"):
        exists = op.get_bind().scalar(sa.select(sa.func.count()).select_from(permissions).where(permissions.c.group_name == group, permissions.c.permission == "search"))
        if not exists:
            op.bulk_insert(permissions, [{"group_name": group, "permission": "search", "granted": True, "start_time": 0, "end_time": None}])



def downgrade() -> None:
    raise RuntimeError("Restore the pre-upgrade database checkpoint to return to CFMS 0.4")


def _convert_epoch(table, column):
    connection = op.get_bind()
    column_info = next(item for item in sa.inspect(connection).get_columns(table) if item["name"] == column)
    temporary = column + "_unix"
    with op.batch_alter_table(table) as batch:
        batch.add_column(sa.Column(temporary, sa.Double(), nullable=True))
    expression = (f"UNIX_TIMESTAMP({column})" if connection.dialect.name == "mysql" else f"(julianday({column}) - 2440587.5) * 86400.0")
    op.execute(sa.text(f"UPDATE {table} SET {temporary} = {expression}"))
    with op.batch_alter_table(table) as batch:
        batch.drop_column(column)
        batch.alter_column(temporary, new_column_name=column, existing_type=sa.Double(), nullable=column_info["nullable"])


def _widen_user_keys():
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    references = [(table, fk) for table in inspector.get_table_names() for fk in inspector.get_foreign_keys(table) if fk["referred_table"] == "users" and fk["referred_columns"] == ["username"]]
    if connection.dialect.name == "mysql":
        for table, fk in references:
            op.drop_constraint(fk["name"], table, type_="foreignkey")
    targets = {(table, fk["constrained_columns"][0]) for table, fk in references} | {("users", "username")}
    for table, column in sorted(targets):
        info = next(item for item in inspector.get_columns(table) if item["name"] == column)
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=info["type"], type_=sa.VARCHAR(256), existing_nullable=info["nullable"])
    if connection.dialect.name == "mysql":
        for table, fk in references:
            op.create_foreign_key(fk["name"], table, "users", fk["constrained_columns"], ["username"], **fk["options"])


def _preserve_subnet_reasons():
    connection = op.get_bind()
    metadata = sa.MetaData()
    subnets = sa.Table("banned_subnets", metadata, autoload_with=connection)
    comments = sa.Table("comments", metadata, autoload_with=connection)
    for subnet, reason in connection.execute(sa.select(subnets.c.subnet, subnets.c.reason)):
        if not reason:
            continue
        serialized = json.dumps({"data": None, "text": reason}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(b"cfms-comment:v1\0" + serialized).digest()
        identifier = connection.scalar(sa.select(comments.c.comment_id).where(comments.c.content_digest == digest, comments.c.digest_version == 1))
        if identifier is None:
            result = connection.execute(comments.insert().values(digest_version=1, content_digest=digest, comment_text=reason))
            identifier = result.inserted_primary_key[0]
        connection.execute(subnets.update().where(subnets.c.subnet == subnet).values(reason_comment_id=identifier))
    with op.batch_alter_table("banned_subnets") as batch:
        batch.drop_column("reason")
