from __future__ import annotations

import mimetypes
import time
from typing import Any

from sqlalchemy import case, func

from include.database.models.documents import Document, EntityStatus
from include.database.models.files import TransferMode
from include.database.models.identity import User
from include.database.models.src_reports import (
    SrcReport,
    SrcReportAttachment,
    SrcReportEvent,
)
from include.database.session import Session
from include.domains.access.authorization.evaluation import check_access_requirements
from include.domains.documents.handlers.documents import create_file_task
from include.extensions.manager import hookimpl
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import Result
from include.extensions.thesis_request import ThesisRequestHandler as RequestHandler

REPORT_STATUSES = {
    "pending": "审核中",
    "rejected": "已拒绝",
    "duplicate": "重复",
    "fixing": "修复中",
    "passed": "已通过",
}
SEVERITIES = {"low", "medium", "high", "critical"}
SEVERITY_SCORES = {"low": 10, "medium": 30, "high": 60, "critical": 100}


def _finish(
    handler: ConnectionHandler,
    code: int,
    data: dict[str, Any],
    message: str,
    *,
    target: str | None = None,
) -> Result:
    handler.conclude_request(code, data, message)
    return Result(code=code, target=target, data=data, username=handler.username)


def _is_sysop(user: User | None) -> bool:
    return user is not None and "sysop" in user.all_groups


def _status_payload(status: str) -> dict[str, str]:
    return {"status_code": status, "status": REPORT_STATUSES[status]}


def _serialize_report(report: SrcReport, *, detailed: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": report.id,
        "reporter_username": report.reporter_username,
        "title": report.title,
        "category": report.category,
        "severity": report.severity,
        "affected_url": report.affected_url,
        "created_at": report.created_at,
        "updated_at": report.updated_at,
        "attachment_count": len(report.attachments),
        "score": SEVERITY_SCORES.get(report.severity, 0)
        if report.status == "passed"
        else 0,
        **_status_payload(report.status),
    }
    if detailed:
        data["description_md"] = report.description_md
        data["attachments"] = [
            {
                "id": attachment.id,
                "document_id": attachment.document_id,
                "filename": attachment.filename,
                "size": attachment.size,
                "content_type": attachment.content_type,
                "created_at": attachment.created_at,
                "available": attachment.document_id is not None,
            }
            for attachment in report.attachments
        ]
        data["events"] = [
            {
                "id": event.id,
                "actor_username": event.actor_username,
                "from_status_code": event.from_status,
                "from_status": (
                    REPORT_STATUSES.get(event.from_status) if event.from_status else None
                ),
                "to_status_code": event.to_status,
                "to_status": REPORT_STATUSES[event.to_status],
                "note_md": event.note_md,
                "created_at": event.created_at,
            }
            for event in report.events
        ]
    return data


def _load_authorized_report(session, report_id: str, username: str) -> SrcReport | None:
    report = session.get(SrcReport, report_id)
    if report is None:
        return None
    user = User.get_existing(session, username)
    if report.reporter_username != username and not _is_sysop(user):
        return None
    return report


class RequestSrcCreateReportHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": 160},
            "category": {"type": "string", "minLength": 1, "maxLength": 64},
            "severity": {"type": "string", "enum": sorted(SEVERITIES)},
            "affected_url": {
                "anyOf": [
                    {"type": "string", "maxLength": 2048},
                    {"type": "null"},
                ]
            },
            "description_md": {
                "type": "string",
                "minLength": 1,
                "maxLength": 50000,
            },
            "attachments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "document_id": {"type": "string", "minLength": 1},
                        "filename": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 255,
                        },
                    },
                    "required": ["document_id", "filename"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["title", "category", "severity", "description_md"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        username = handler.username
        now = time.time()
        attachment_inputs = handler.data.get("attachments") or []
        document_ids = [item["document_id"] for item in attachment_inputs]
        if len(document_ids) != len(set(document_ids)):
            return _finish(handler, 400, {}, "Duplicate attachments are not allowed")

        with Session() as session:
            user = User.get_existing(session, username)
            attachments: list[SrcReportAttachment] = []
            for item in attachment_inputs:
                document = session.get(Document, item["document_id"])
                metadata = document.metadata_record if document is not None else None
                if (
                    document is None
                    or document.status != EntityStatus.OK
                    or metadata is None
                    or metadata.creator_username != username
                    or not check_access_requirements(session, user, document, "read")
                ):
                    return _finish(
                        handler,
                        403,
                        {},
                        "An attachment does not belong to the current user",
                    )
                try:
                    file_record = document.get_latest_revision().file
                except (RuntimeError, LookupError):
                    return _finish(handler, 409, {}, "An attachment is not available")
                if not file_record.active or file_record.size is None:
                    return _finish(handler, 409, {}, "An attachment upload is incomplete")

                filename = item["filename"].strip()
                attachments.append(
                    SrcReportAttachment(
                        document_id=document.id,
                        filename=filename,
                        size=file_record.size,
                        content_type=(
                            mimetypes.guess_type(filename)[0]
                            or "application/octet-stream"
                        ),
                        created_at=now,
                    )
                )

            report = SrcReport(
                reporter_username=username,
                title=handler.data["title"].strip(),
                category=handler.data["category"].strip(),
                severity=handler.data["severity"],
                affected_url=(handler.data.get("affected_url") or "").strip() or None,
                description_md=handler.data["description_md"].strip(),
                status="pending",
                created_at=now,
                updated_at=now,
            )
            report.attachments.extend(attachments)
            report.events.append(
                SrcReportEvent(
                    actor_username=username,
                    from_status=None,
                    to_status="pending",
                    note_md="报告已提交",
                    created_at=now,
                )
            )
            session.add(report)
            session.commit()
            data = {"report": _serialize_report(report, detailed=True)}
            return _finish(
                handler,
                200,
                data,
                "SRC report created",
                target=report.id,
            )


class RequestSrcListMyReportsHandler(RequestHandler):
    require_auth = True
    schema = {"type": "object", "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            reports = (
                session.query(SrcReport)
                .filter(SrcReport.reporter_username == handler.username)
                .order_by(SrcReport.updated_at.desc())
                .all()
            )
            data = {"reports": [_serialize_report(report) for report in reports]}
        return _finish(handler, 200, data, "SRC reports listed")


class RequestSrcGetLeaderboardHandler(RequestHandler):
    require_auth = True
    schema = {"type": "object", "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):
        severity_score = case(
            *(
                (SrcReport.severity == severity, score)
                for severity, score in SEVERITY_SCORES.items()
            ),
            else_=0,
        )
        accepted_score = case(
            (SrcReport.status == "passed", severity_score), else_=0
        )
        accepted_count = case((SrcReport.status == "passed", 1), else_=0)

        with Session() as session:
            rows = (
                session.query(
                    SrcReport.reporter_username,
                    User.nickname,
                    func.sum(accepted_score).label("score"),
                    func.sum(accepted_count).label("accepted_count"),
                    func.count(SrcReport.id).label("report_count"),
                )
                .join(User, User.username == SrcReport.reporter_username)
                .group_by(SrcReport.reporter_username, User.nickname)
                .order_by(
                    func.sum(accepted_score).desc(),
                    func.sum(accepted_count).desc(),
                    SrcReport.reporter_username.asc(),
                )
                .all()
            )

            leaderboard = []
            previous_score: int | None = None
            previous_rank = 0
            for position, row in enumerate(rows, start=1):
                score = int(row.score or 0)
                rank = previous_rank if score == previous_score else position
                previous_score = score
                previous_rank = rank
                leaderboard.append(
                    {
                        "rank": rank,
                        "username": row.reporter_username,
                        "nickname": row.nickname or row.reporter_username,
                        "score": score,
                        "accepted_count": int(row.accepted_count or 0),
                        "report_count": int(row.report_count or 0),
                    }
                )

            personal = next(
                (
                    item
                    for item in leaderboard
                    if item["username"] == handler.username
                ),
                {
                    "rank": None,
                    "username": handler.username,
                    "nickname": User.get_existing(
                        session, handler.username
                    ).nickname
                    or handler.username,
                    "score": 0,
                    "accepted_count": 0,
                    "report_count": 0,
                },
            )
            data = {
                "leaderboard": leaderboard,
                "me": personal,
                "score_rules": SEVERITY_SCORES,
            }
        return _finish(handler, 200, data, "SRC leaderboard returned")


class RequestSrcGetReportHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {"report_id": {"type": "string", "minLength": 1}},
        "required": ["report_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        report_id = handler.data["report_id"]
        with Session() as session:
            report = _load_authorized_report(session, report_id, handler.username)
            if report is None:
                return _finish(handler, 404, {}, "SRC report not found")
            data = {"report": _serialize_report(report, detailed=True)}
        return _finish(handler, 200, data, "SRC report returned", target=report_id)


class RequestSrcListReportsHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {
            "status": {
                "anyOf": [
                    {"type": "string", "enum": sorted(REPORT_STATUSES)},
                    {"type": "null"},
                ]
            }
        },
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.username)
            if not _is_sysop(user):
                return _finish(handler, 403, {}, "The sysop role is required")

            query = session.query(SrcReport)
            requested_status = handler.data.get("status")
            if requested_status:
                query = query.filter(SrcReport.status == requested_status)
            reports = query.order_by(SrcReport.updated_at.desc()).all()
            count_rows = (
                session.query(SrcReport.status, func.count(SrcReport.id))
                .group_by(SrcReport.status)
                .all()
            )
            counts = {status: 0 for status in REPORT_STATUSES}
            counts.update({status: int(count) for status, count in count_rows})
            data = {
                "reports": [_serialize_report(report) for report in reports],
                "counts": counts,
                "status_labels": REPORT_STATUSES,
            }
        return _finish(handler, 200, data, "SRC admin report list returned")


class RequestSrcUpdateReportStatusHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {
            "report_id": {"type": "string", "minLength": 1},
            "status": {"type": "string", "enum": sorted(REPORT_STATUSES)},
            "note_md": {
                "anyOf": [
                    {"type": "string", "maxLength": 20000},
                    {"type": "null"},
                ]
            },
        },
        "required": ["report_id", "status"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        report_id = handler.data["report_id"]
        next_status = handler.data["status"]
        note_md = (handler.data.get("note_md") or "").strip() or None
        with Session() as session:
            user = User.get_existing(session, handler.username)
            if not _is_sysop(user):
                return _finish(handler, 403, {}, "The sysop role is required")
            report = session.get(SrcReport, report_id)
            if report is None:
                return _finish(handler, 404, {}, "SRC report not found")

            previous_status = report.status
            if previous_status != next_status or note_md:
                now = time.time()
                report.status = next_status
                report.updated_at = now
                report.events.append(
                    SrcReportEvent(
                        actor_username=handler.username,
                        from_status=previous_status,
                        to_status=next_status,
                        note_md=note_md,
                        created_at=now,
                    )
                )
                session.commit()
            data = {"report": _serialize_report(report, detailed=True)}
        return _finish(handler, 200, data, "SRC report status updated", target=report_id)


class RequestSrcPrepareAttachmentDownloadHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {"attachment_id": {"type": "integer", "minimum": 1}},
        "required": ["attachment_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        attachment_id = handler.data["attachment_id"]
        with Session() as session:
            attachment = session.get(SrcReportAttachment, attachment_id)
            if attachment is None or attachment.document_id is None:
                return _finish(handler, 404, {}, "SRC attachment not found")
            report = _load_authorized_report(
                session, attachment.report_id, handler.username
            )
            if report is None:
                return _finish(handler, 404, {}, "SRC attachment not found")
            document = session.get(Document, attachment.document_id)
            if document is None:
                return _finish(handler, 410, {}, "SRC attachment is no longer available")
            try:
                file_record = document.get_latest_revision().file
            except (RuntimeError, LookupError):
                return _finish(handler, 410, {}, "SRC attachment is no longer available")
            task_data = create_file_task(
                session, file_record, transfer_mode=TransferMode.DOWNLOAD,
                issued_by_username=handler.username
            )
            session.commit()
            data = {"filename": attachment.filename, "task_data": task_data}
        return _finish(
            handler,
            200,
            data,
            "SRC attachment download prepared",
            target=str(attachment_id),
        )


@hookimpl
def ext_register_handlers() -> dict[str, type[RequestHandler]]:
    return {
        "src_create_report": RequestSrcCreateReportHandler,
        "src_list_my_reports": RequestSrcListMyReportsHandler,
        "src_get_leaderboard": RequestSrcGetLeaderboardHandler,
        "src_get_report": RequestSrcGetReportHandler,
        "src_list_reports": RequestSrcListReportsHandler,
        "src_update_report_status": RequestSrcUpdateReportStatusHandler,
        "src_prepare_attachment_download": RequestSrcPrepareAttachmentDownloadHandler,
    }


@hookimpl
def ext_register_extension_flags() -> set[str]:
    return {"src_portal"}
