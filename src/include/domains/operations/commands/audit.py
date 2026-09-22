from loguru import logger

from include.database.models.operations import AuditEntry
from include.database.session import Session


def log_audit(
    action: str,
    result: int,
    username: str | None = None,
    target: str | None = None,
    data: dict | None = None,
    remote_address: str | None = None,
) -> None:
    """Create an audit log entry."""
    if result == 400:
        return

    # username 列 nullable=True 且外键指向 users.username。匿名请求（未登录 /
    # 教学关卡的探测动作）会传空串，而空串并不是一个真实用户 —— 外键校验会直接
    # 抛 1452，导致这条审计记录整体丢失。这里把空串归一化成 NULL：既保留审计
    # 记录，又不违反外键约束。
    if not username:
        username = None

    with Session() as session:
        new_entry = AuditEntry(
            action=action,
            username=username,
            target=target,
            result=result,
            data=data,
            remote_address=remote_address,
        )
        try:
            session.add(new_entry)
            session.commit()
        except Exception:
            # 审计失败绝不能影响主业务（这是"谁在攻击我"的记录，不是业务链路）。
            session.rollback()
            logger.debug(f"[AUDIT] failed to persist entry for action={action}")
