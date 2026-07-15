from __future__ import annotations

import threading

from sqlalchemy import event, func
from sqlalchemy.orm import Session

from include.database.models.documents import DocumentMetadata, DocumentRevision
from include.database.models.files import File
from include.database.models.identity import User

_QUOTA_LOCKS = tuple(threading.RLock() for _ in range(64))


def _lock_user_quota(session: Session, username: str) -> User | None:
    lock_index = hash(username) % len(_QUOTA_LOCKS)
    held_indexes: set[int] = session.info.setdefault("quota_locks", set())
    if lock_index not in held_indexes:
        _QUOTA_LOCKS[lock_index].acquire()
        held_indexes.add(lock_index)

        if not session.info.get("quota_release_listener"):
            session.info["quota_release_listener"] = True

            @event.listens_for(session, "after_transaction_end")
            def _release_quota_locks(_session, transaction):
                if transaction.parent is not None:
                    return
                indexes = _session.info.pop("quota_locks", set())
                for index in indexes:
                    _QUOTA_LOCKS[index].release()

    return (
        session.query(User).with_for_update().filter(User.username == username).first()
    )


def _owned_file_ids(session: Session, username: str):
    return (
        session.query(DocumentRevision.file_id.label("file_id"))
        .join(
            DocumentMetadata,
            DocumentMetadata.document_id == DocumentRevision.document_id,
        )
        .filter(DocumentMetadata.creator_username == username)
        .distinct()
        .subquery()
    )


def get_user_disk_usage(session: Session, username: str) -> int:
    """Sum active ``File.size`` values once per file owned through document metadata."""
    owned_file_ids = _owned_file_ids(session, username)
    total = (
        session.query(func.coalesce(func.sum(File._size), 0))
        .join(owned_file_ids, owned_file_ids.c.file_id == File.id)
        .filter(File.active.is_(True))
        .scalar()
    )
    return int(total or 0)


def get_file_owner_usernames(session: Session, file_id: str) -> list[str]:
    rows = (
        session.query(DocumentMetadata.creator_username)
        .join(
            DocumentRevision,
            DocumentRevision.document_id == DocumentMetadata.document_id,
        )
        .filter(
            DocumentRevision.file_id == file_id,
            DocumentMetadata.creator_username.is_not(None),
        )
        .distinct()
        .all()
    )
    return sorted(row[0] for row in rows if row[0])


def file_owners_fit_quota(session: Session, file: File, new_size: int) -> bool:
    """Lock every owning user and validate the file's committed projected size."""
    owners = get_file_owner_usernames(session, file.id)
    users = [_lock_user_quota(session, username) for username in owners]
    current_size = file._size or 0
    additional_bytes = max(0, new_size - current_size) if file.active else new_size

    for user in users:
        if user is None:
            continue
        if (
            get_user_disk_usage(session, user.username) + additional_bytes
            > user.disk_quota
        ):
            return False
    return True
