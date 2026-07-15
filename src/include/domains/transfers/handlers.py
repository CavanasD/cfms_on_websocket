from __future__ import annotations

import mimetypes
import time
from dataclasses import dataclass
from urllib.parse import quote

import redis

from include.database.models.documents import DocumentRevision
from include.database.models.files import FileTask, TransferMode
from include.database.models.identity import User
from include.database.session import Session
from include.domains.drive.quota import file_owners_fit_quota
from include.domains.transfers.settings import get_transfer_settings
from include.domains.transfers.store import (
    RedisTransferSessionStore,
    TransferSessionConflictError,
    TransferSessionReservation,
)
from include.domains.transfers.tickets import (
    TransferOperation,
    issue_transfer_ticket,
)
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


@dataclass(frozen=True)
class TransferAuthorization:
    object_key: str
    file_size: int | None
    sha256: str | None
    filename: str | None
    content_type: str | None


def _authorize_task(
    task_id: str,
    username: str,
    operation: TransferOperation,
    expected_size: int | None = None,
) -> tuple[TransferAuthorization | None, int, str]:
    expected_mode = (
        TransferMode.UPLOAD if operation == "upload" else TransferMode.DOWNLOAD
    )
    now = time.time()

    with Session() as session:
        task = session.get(FileTask, task_id)
        if task is None:
            return None, 404, "Task not found"
        if task.status != 0 or task.mode != expected_mode:
            return None, 409, "Task is not pending for this operation"
        if task.start_time > now or (task.end_time is not None and task.end_time < now):
            return None, 410, "Task has expired"

        user = User.get_existing(session, username)
        revisions = (
            session.query(DocumentRevision)
            .filter(DocumentRevision.file_id == task.file_id)
            .all()
        )
        access_type = "write" if operation == "upload" else "read"
        authorized_revision = next(
            (
                revision
                for revision in revisions
                if revision.document
                and revision.document.check_access_requirements(user, access_type)
            ),
            None,
        )
        if authorized_revision is None:
            return None, 403, "Access denied"

        if (
            operation == "upload"
            and expected_size is not None
            and not file_owners_fit_quota(session, task.file, expected_size)
        ):
            return None, 413, "Upload would exceed the document owner's quota"

        filename = authorized_revision.document.title
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return (
            TransferAuthorization(
                object_key=task.file.path,
                file_size=task.file.size,
                sha256=task.file.sha256,
                filename=filename,
                content_type=content_type,
            ),
            200,
            "",
        )


class _TransferHandler(RequestHandler):
    require_auth = True

    @staticmethod
    def _disabled(handler: ConnectionHandler) -> Result | None:
        if get_transfer_settings().enabled:
            return None
        handler.conclude_request(503, {}, "HTTP transfer data plane is disabled")
        return Result(code=503, target=None, username=handler.username)

    @staticmethod
    def _store_session(
        handler: ConnectionHandler, values: dict, ttl_seconds: int
    ) -> Result | None:
        try:
            RedisTransferSessionStore().create(values, ttl_seconds)
            return None
        except redis.RedisError:
            handler.conclude_request(503, {}, "Transfer session store is unavailable")
            return Result(
                code=503,
                target=str(values.get("task_id")),
                username=handler.username,
            )

    @staticmethod
    def _reserve_upload_session(
        handler: ConnectionHandler, values: dict, ttl_seconds: int
    ) -> tuple[TransferSessionReservation | None, Result | None]:
        try:
            reservation = RedisTransferSessionStore().create_or_reuse(
                values,
                ttl_seconds,
                immutable_fields=(
                    "task_id",
                    "username",
                    "operation",
                    "object_key",
                    "max_size",
                    "expected_sha256",
                    "filename",
                    "content_type",
                ),
            )
            return reservation, None
        except TransferSessionConflictError as exc:
            handler.conclude_request(409, {}, str(exc))
            return None, Result(
                code=409,
                target=str(values.get("task_id")),
                username=handler.username,
            )
        except redis.RedisError:
            handler.conclude_request(503, {}, "Transfer session store is unavailable")
            return None, Result(
                code=503,
                target=str(values.get("task_id")),
                username=handler.username,
            )


class RequestPrepareUploadHandler(_TransferHandler):
    schema = {
        "type": "object",
        "properties": {
            "task_id": {"type": "string", "minLength": 1, "maxLength": 255},
            "size": {"type": "integer", "minimum": 0},
            "filename": {"type": "string", "minLength": 1, "maxLength": 255},
            "content_type": {"type": "string", "minLength": 1, "maxLength": 255},
            "sha256": {
                "anyOf": [
                    {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                    {"type": "null"},
                ]
            },
        },
        "required": ["task_id", "size"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        if result := self._disabled(handler):
            return result

        settings = get_transfer_settings()
        task_id = handler.data["task_id"]
        expected_size = handler.data["size"]
        expected_sha256 = handler.data.get("sha256")
        if expected_sha256 is not None:
            expected_sha256 = expected_sha256.lower()
        if expected_size > settings.max_upload_size:
            handler.conclude_request(
                413, {}, "File exceeds the configured upload limit"
            )
            return Result(code=413, target=task_id, username=handler.username)

        authorized, code, message = _authorize_task(
            task_id, handler.username, "upload", expected_size=expected_size
        )
        if authorized is None:
            handler.conclude_request(code, {}, message)
            return Result(code=code, target=task_id, username=handler.username)

        expires_at = int(time.time()) + settings.session_ttl_seconds
        values = {
            "task_id": task_id,
            "username": handler.username,
            "operation": "upload",
            "object_key": authorized.object_key,
            "max_size": expected_size,
            "expected_sha256": expected_sha256,
            # Transfer policy must use metadata derived from the authorized
            # document. Client-declared values are untrusted hints and cannot
            # be allowed to disguise a blocked extension or content type.
            "filename": authorized.filename,
            "content_type": authorized.content_type,
            "offset": 0,
            "status": "pending",
            "expires_at": expires_at,
        }
        reservation, error = self._reserve_upload_session(
            handler, values, settings.session_ttl_seconds
        )
        if error is not None:
            return error
        assert reservation is not None
        session_values = reservation.values

        ticket, ticket_expires_at = issue_transfer_ticket(
            settings,
            task_id=task_id,
            username=handler.username,
            operation="upload",
            object_key=authorized.object_key,
            max_size=expected_size,
            expected_sha256=expected_sha256,
        )
        url = f"{settings.base_url}/api/v1/transfers/{quote(task_id, safe='')}"
        handler.conclude_request(
            200,
            {
                "task_id": task_id,
                "upload_url": url,
                "chunk_size": settings.chunk_size,
                "ticket": ticket,
                "expires_at": ticket_expires_at,
                "session_expires_at": int(session_values["expires_at"]),
                "offset": int(session_values.get("offset", 0)),
                "status": session_values.get("status", "pending"),
            },
            "Upload transfer prepared",
        )
        return Result(code=0, target=task_id, username=handler.username)


class RequestPrepareDownloadHandler(_TransferHandler):
    schema = {
        "type": "object",
        "properties": {"task_id": {"type": "string", "minLength": 1, "maxLength": 255}},
        "required": ["task_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        if result := self._disabled(handler):
            return result

        settings = get_transfer_settings()
        task_id = handler.data["task_id"]
        authorized, code, message = _authorize_task(
            task_id, handler.username, "download"
        )
        if authorized is None:
            handler.conclude_request(code, {}, message)
            return Result(code=code, target=task_id, username=handler.username)

        size = authorized.file_size
        if size is None:
            handler.conclude_request(409, {}, "File size is not available")
            return Result(code=409, target=task_id, username=handler.username)

        expires_at = int(time.time()) + settings.session_ttl_seconds
        values = {
            "task_id": task_id,
            "username": handler.username,
            "operation": "download",
            "object_key": authorized.object_key,
            "max_size": size,
            "expected_sha256": authorized.sha256,
            "filename": authorized.filename,
            "content_type": authorized.content_type,
            "offset": 0,
            "status": "ready",
            "expires_at": expires_at,
        }
        if result := self._store_session(handler, values, settings.session_ttl_seconds):
            return result

        ticket, ticket_expires_at = issue_transfer_ticket(
            settings,
            task_id=task_id,
            username=handler.username,
            operation="download",
            object_key=authorized.object_key,
            max_size=size,
            expected_sha256=authorized.sha256,
        )
        url = f"{settings.base_url}/api/v1/transfers/{quote(task_id, safe='')}/content"
        handler.conclude_request(
            200,
            {
                "task_id": task_id,
                "download_url": url,
                "size": size,
                "sha256": authorized.sha256,
                "accept_ranges": "bytes",
                "filename": authorized.filename,
                "content_type": authorized.content_type,
                "ticket": ticket,
                "expires_at": ticket_expires_at,
            },
            "Download transfer prepared",
        )
        return Result(code=0, target=task_id, username=handler.username)


class RequestGetTransferStatusHandler(_TransferHandler):
    schema = {
        "type": "object",
        "properties": {"task_id": {"type": "string", "minLength": 1, "maxLength": 255}},
        "required": ["task_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        if result := self._disabled(handler):
            return result

        task_id = handler.data["task_id"]
        try:
            values = RedisTransferSessionStore().get(task_id)
        except redis.RedisError:
            handler.conclude_request(503, {}, "Transfer session store is unavailable")
            return Result(code=503, target=task_id, username=handler.username)

        if values is None:
            handler.conclude_request(404, {}, "Transfer session not found")
            return Result(code=404, target=task_id, username=handler.username)
        if values.get("username") != handler.username:
            handler.conclude_request(403, {}, "Access denied")
            return Result(code=403, target=task_id, username=handler.username)

        values = dict(values)
        raw_status = values.get("status", "pending").lower()
        values["status"] = {
            "pending": "pending",
            "ready": "pending",
            "receiving": "running",
            "running": "running",
            "finalizing": "running",
            "completed": "completed",
            "failed": "failed",
        }.get(raw_status, "failed")
        if raw_status not in {
            "pending",
            "ready",
            "receiving",
            "running",
            "finalizing",
            "completed",
            "failed",
        }:
            values.setdefault("error", "invalid_transfer_state")

        if values.get("operation") == "upload":
            with Session() as session:
                task = session.get(FileTask, task_id)
                if task is not None and task.mode == TransferMode.UPLOAD:
                    if task.status == 1:
                        values["status"] = "completed"
                        values.pop("error", None)
                    elif task.status == 2:
                        values["status"] = "failed"
                        values.setdefault("error", "upload_rejected")
                    elif values["status"] == "completed":
                        # MinIO persistence precedes Core's transactional metadata
                        # commit. Until the consumer commits, completion is not a
                        # business-level success and clients must keep polling.
                        values["status"] = "running"

        public_fields = {
            key: values.get(key)
            for key in (
                "task_id",
                "operation",
                "offset",
                "max_size",
                "status",
                "size",
                "sha256",
                "error",
                "expires_at",
            )
            if values.get(key) is not None
        }
        for integer_field in ("offset", "max_size", "size", "expires_at"):
            if integer_field in public_fields:
                public_fields[integer_field] = int(public_fields[integer_field])

        handler.conclude_request(200, public_fields, "Transfer status retrieved")
        return Result(code=0, target=task_id, username=handler.username)
