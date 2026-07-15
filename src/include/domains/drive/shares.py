from __future__ import annotations

import mimetypes
import time
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from include.config.constants import FILE_TASK_DEFAULT_DURATION_SECONDS
from include.database.models.documents import Document
from include.database.models.files import FileTask, TransferMode
from include.database.models.shares import ShareLink
from include.domains.transfers.settings import TransferSettings
from include.domains.transfers.store import RedisTransferSessionStore
from include.domains.transfers.tickets import issue_transfer_ticket

_password_hasher = PasswordHasher()


class ShareUnavailableError(ValueError):
    pass


class SharePasswordError(ValueError):
    pass


def hash_share_password(password: str) -> str:
    return _password_hasher.hash(password)


def _password_matches(encoded: str, candidate: str | None) -> bool:
    if candidate is None:
        return False
    try:
        return _password_hasher.verify(encoded, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def share_is_active(link: ShareLink, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return not (
        link.revoked
        or (link.expires_at is not None and link.expires_at <= now)
        or (
            link.max_downloads is not None and link.download_count >= link.max_downloads
        )
    )


def share_to_dict(link: ShareLink) -> dict:
    return {
        "token": link.token,
        "document_id": link.document_id,
        "created_by": link.created_by,
        "created_at": link.created_at,
        "expires_at": link.expires_at,
        "max_downloads": link.max_downloads,
        "download_count": link.download_count,
        "revoked": link.revoked,
        "password_required": link.password_hash is not None,
        "active": share_is_active(link),
    }


def prepare_share_download(
    session: Session,
    *,
    token: str,
    password: str | None,
    settings: TransferSettings,
    store: RedisTransferSessionStore,
) -> dict:
    """Atomically reserve a share use and create its HTTP download session."""
    link = session.get(ShareLink, token)
    if link is None or not share_is_active(link):
        raise ShareUnavailableError("Share link is unavailable")
    if link.password_hash and not _password_matches(link.password_hash, password):
        raise SharePasswordError("Share password is invalid")

    document = session.get(Document, link.document_id)
    if document is None:
        raise ShareUnavailableError("Shared document no longer exists")
    try:
        revision = document.get_latest_revision()
    except (RuntimeError, ValueError) as exc:
        raise ShareUnavailableError("Shared document has no active content") from exc

    file = revision.file
    size = file.size
    if not file.active or size is None:
        raise ShareUnavailableError("Shared document has no active content")

    now = time.time()
    reservation = session.execute(
        update(ShareLink)
        .where(
            ShareLink.token == token,
            ShareLink.revoked.is_(False),
            or_(ShareLink.expires_at.is_(None), ShareLink.expires_at > now),
            or_(
                ShareLink.max_downloads.is_(None),
                ShareLink.download_count < ShareLink.max_downloads,
            ),
        )
        .values(download_count=ShareLink.download_count + 1)
    )
    if reservation.rowcount != 1:
        session.rollback()
        raise ShareUnavailableError("Share link is unavailable")

    task = FileTask(
        file=file,
        status=0,
        mode=TransferMode.DOWNLOAD,
        start_time=now,
        end_time=now + FILE_TASK_DEFAULT_DURATION_SECONDS,
    )
    session.add(task)
    session.flush()

    identity = f"share:{token}"
    filename = document.title
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    expires_at = int(now) + settings.session_ttl_seconds
    values = {
        "task_id": task.id,
        "username": identity,
        "operation": "download",
        "object_key": file.path,
        "max_size": size,
        "expected_sha256": file.sha256,
        "filename": filename,
        "content_type": content_type,
        "offset": 0,
        "status": "ready",
        "expires_at": expires_at,
    }
    ticket, ticket_expires_at = issue_transfer_ticket(
        settings,
        task_id=task.id,
        username=identity,
        operation="download",
        object_key=file.path,
        max_size=size,
        expected_sha256=file.sha256,
    )
    store.create(values, settings.session_ttl_seconds)
    session.commit()

    return {
        "task_id": task.id,
        "download_url": (
            f"{settings.base_url}/api/v1/transfers/{quote(task.id, safe='')}/content"
        ),
        "size": size,
        "sha256": file.sha256,
        "accept_ranges": "bytes",
        "filename": filename,
        "content_type": content_type,
        "ticket": ticket,
        "expires_at": ticket_expires_at,
    }
