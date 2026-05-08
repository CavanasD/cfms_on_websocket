from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from include.database.models.classic import User
from include.database.models.file import File


def get_user_disk_usage(session: Session, username: str) -> int:
    """
    Sum of File.stored_size for active files attributed to ``username``.

    NULL stored_size rows (legacy / system-seeded files) contribute zero so
    quota math never breaks on partially-migrated data.
    """
    total = (
        session.query(func.coalesce(func.sum(File.stored_size), 0))
        .filter(
            File.uploaded_by == username,
            File.active.is_(True),
        )
        .scalar()
    )
    return int(total or 0)


def get_user_disk_quota(session: Session, username: str) -> Optional[int]:
    """
    Return the user's quota in bytes, or None for "no limit" / user not found.
    """
    user = session.get(User, username)
    if user is None:
        return None
    return user.disk_quota


def check_quota_for_upload(
    session: Session, username: str, additional_bytes: int
) -> bool:
    """
    Return True if uploading ``additional_bytes`` would still fit within the
    user's quota. NULL quota means unlimited (always True).

    Sysop or other quota-exempt accounts simply have ``disk_quota=None``.
    """
    if additional_bytes <= 0:
        return True

    quota = get_user_disk_quota(session, username)
    if quota is None:
        return True

    used = get_user_disk_usage(session, username)
    return (used + additional_bytes) <= quota
