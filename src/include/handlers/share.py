__all__ = [
    "RequestCreateShareLinkHandler",
    "RequestRevokeShareLinkHandler",
    "RequestListMyShareLinksHandler",
    "RequestGetShareLinkInfoHandler",
    "RequestDownloadShareLinkHandler",
]

import time
from typing import Optional

from include.classes.connection_handler import ConnectionHandler
from include.classes.enum.permissions import Permissions
from include.classes.request_handler import RequestHandler
from include.constants import FILE_TASK_DEFAULT_DURATION_SECONDS
from include.database.handler import Session
from include.database.models.classic import User
from include.database.models.entity import Document
from include.database.models.file import FileTask
from include.database.models.share import ShareLink
from include.system.messages import Messages as smsg


def _share_active(link: ShareLink, now: Optional[float] = None) -> bool:
    """Pure check: is this link still good to use right now?"""
    now = now if now is not None else time.time()
    if link.revoked:
        return False
    if link.expires_at is not None and link.expires_at <= now:
        return False
    if link.max_downloads is not None and link.download_count >= link.max_downloads:
        return False
    return True


def _share_to_dict(link: ShareLink) -> dict:
    return {
        "token": link.token,
        "document_id": link.document_id,
        "created_by": link.created_by,
        "created_at": link.created_at,
        "expires_at": link.expires_at,
        "max_downloads": link.max_downloads,
        "download_count": link.download_count,
        "revoked": link.revoked,
        "active": _share_active(link),
    }


class RequestCreateShareLinkHandler(RequestHandler):
    """Create a share link for a document the caller has read access to."""

    data_schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1},
            "expires_at": {
                "anyOf": [{"type": "number"}, {"type": "null"}]
            },
            "max_downloads": {
                "anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]
            },
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        document_id: str = handler.data["document_id"]
        expires_at = handler.data.get("expires_at")
        max_downloads = handler.data.get("max_downloads")

        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)
            if document is None:
                handler.conclude_request(404, {}, smsg.DOCUMENT_NOT_FOUND)
                return 404, document_id, handler.username

            if not document.check_access_requirements(user, "read"):
                handler.conclude_access_denial()
                return 403, document_id, handler.username

            link = ShareLink(
                document_id=document_id,
                created_by=handler.username,
                expires_at=expires_at,
                max_downloads=max_downloads,
            )
            session.add(link)
            session.commit()

            handler.conclude_request(
                200,
                {"share": _share_to_dict(link)},
                "Share link created",
            )
            return 0, document_id, handler.username


class RequestRevokeShareLinkHandler(RequestHandler):
    """Revoke a share link. Creator or sysop only."""

    data_schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "minLength": 1},
        },
        "required": ["token"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        token: str = handler.data["token"]

        with Session() as session:
            link = session.get(ShareLink, token)
            if link is None:
                handler.conclude_request(404, {}, "Share link not found")
                return 404, token, handler.username

            user = User.get_existing(session, handler.username)
            is_owner = link.created_by == handler.username
            is_sysop = "sysop" in user.all_groups
            if not (is_owner or is_sysop):
                handler.conclude_permission_denial()
                return 403, token, handler.username

            link.revoked = True
            session.commit()

            handler.conclude_request(200, {"token": token}, "Share link revoked")
            return 0, token, handler.username


class RequestListMyShareLinksHandler(RequestHandler):
    """List share links created by the caller (most recent first)."""

    data_schema = {
        "type": "object",
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            links = (
                session.query(ShareLink)
                .filter(ShareLink.created_by == handler.username)
                .order_by(ShareLink.created_at.desc())
                .all()
            )
            handler.conclude_request(
                200,
                {"shares": [_share_to_dict(l) for l in links]},
                "ok",
            )
            return 0, None, handler.username


class RequestGetShareLinkInfoHandler(RequestHandler):
    """
    Read-only metadata lookup by token. Anonymous-friendly: returns just
    enough for the share-link landing page (document title, expiry, validity)
    without exposing creator identity to the public.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "minLength": 1},
        },
        "required": ["token"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        token: str = handler.data["token"]

        with Session() as session:
            link = session.get(ShareLink, token)
            if link is None:
                handler.conclude_request(404, {}, "Share link not found")
                return

            doc = session.get(Document, link.document_id)
            if doc is None:
                handler.conclude_request(410, {}, "Linked document is gone")
                return

            handler.conclude_request(
                200,
                {
                    "document_title": doc.title,
                    "expires_at": link.expires_at,
                    "max_downloads": link.max_downloads,
                    "download_count": link.download_count,
                    "active": _share_active(link),
                },
                "ok",
            )


class RequestDownloadShareLinkHandler(RequestHandler):
    """
    Anonymous download via a share-link token. Validates the link, creates
    a one-shot FileTask scoped to the document's current revision, then
    streams the file. Increments download_count on a successful start.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "minLength": 1},
        },
        "required": ["token"],
        "additionalProperties": False,
    }
    # No require_auth — share-link holders are by definition anonymous.

    def handle(self, handler: ConnectionHandler):
        token: str = handler.data["token"]

        with Session() as session:
            link = session.get(ShareLink, token)
            if link is None:
                handler.conclude_request(404, {}, "Share link not found")
                return

            if not _share_active(link):
                handler.conclude_request(410, {}, "Share link is no longer valid")
                return

            document = session.get(Document, link.document_id)
            if document is None:
                handler.conclude_request(410, {}, "Linked document is gone")
                return

            try:
                revision = document.get_latest_revision()
            except Exception:
                handler.conclude_request(410, {}, "Linked document has no content")
                return

            file = revision.file
            if file is None:
                handler.conclude_request(410, {}, "Linked document has no content")
                return

            now = time.time()
            task = FileTask(
                file_id=file.id,
                status=0,
                mode=0,
                start_time=now,
                end_time=now + FILE_TASK_DEFAULT_DURATION_SECONDS,
            )
            session.add(task)

            link.download_count += 1
            session.commit()

            task_id = task.id

        # send_file opens its own session lookup of the FileTask by id.
        handler.send_file(task_id)
