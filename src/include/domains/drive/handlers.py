from __future__ import annotations

import redis
from sqlalchemy.exc import IntegrityError

from include.config.settings import global_config
from include.database.models.documents import Document
from include.database.models.identity import User, UserGroup
from include.database.models.shares import ShareLink
from include.database.session import Session
from include.domains.drive.homes import ensure_user_home
from include.domains.drive.quota import get_user_disk_usage
from include.domains.drive.shares import (
    SharePasswordError,
    ShareUnavailableError,
    hash_share_password,
    prepare_share_download,
    share_to_dict,
)
from include.domains.identity.commands.users import create_user_in_session
from include.domains.identity.validators.passwords import check_passwd_requirements
from include.domains.transfers.settings import get_transfer_settings
from include.domains.transfers.store import RedisTransferSessionStore
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


class RequestRegisterHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1, "maxLength": 64},
            "password": {"type": "string", "minLength": 1},
            "nickname": {
                "anyOf": [{"type": "string", "maxLength": 255}, {"type": "null"}]
            },
        },
        "required": ["username", "password"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        username = handler.data["username"]
        password = handler.data["password"]
        cfg = global_config["security"]
        try:
            check_passwd_requirements(
                password,
                cfg["passwd_min_length"],
                cfg["passwd_max_length"],
                cfg["passwd_rules"],
                cfg["passwd_min_passed_count"],
            )
        except ValueError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, target=username)

        with Session() as session:
            if session.get(UserGroup, "user") is None:
                handler.conclude_request(503, {}, "Default user group is unavailable")
                return Result(code=503, target=username)
            if session.get(User, username) is not None:
                handler.conclude_request(400, {}, "Username already exists")
                return Result(code=400, target=username)

            try:
                user = create_user_in_session(
                    session,
                    username=username,
                    password=password,
                    nickname=handler.data.get("nickname"),
                    groups=[{"group_name": "user", "start_time": 0, "end_time": None}],
                )
                session.flush()
                ensure_user_home(session, user)
                session.commit()
            except IntegrityError:
                session.rollback()
                handler.conclude_request(400, {}, "Username already exists")
                return Result(code=400, target=username)

        handler.conclude_request(200, {}, "User registered successfully")
        return Result(code=0, target=username)


class RequestGetQuotaHandler(RequestHandler):
    require_auth = True
    schema = {"type": "object", "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.username)
            data = {
                "disk_quota": user.disk_quota,
                "disk_used": get_user_disk_usage(session, user.username),
            }
        handler.conclude_request(200, data, "Quota returned")
        return Result(code=0, target=handler.username, username=handler.username)


class RequestCreateShareLinkHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {
            "document_id": {"type": "string", "minLength": 1, "maxLength": 255},
            "password": {
                "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]
            },
            "expires_at": {"anyOf": [{"type": "number"}, {"type": "null"}]},
            "max_downloads": {
                "anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]
            },
        },
        "required": ["document_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        document_id = handler.data["document_id"]
        with Session() as session:
            user = User.get_existing(session, handler.username)
            document = session.get(Document, document_id)
            if document is None:
                handler.conclude_request(404, {}, "Document not found")
                return Result(code=404, target=document_id, username=handler.username)
            if not document.check_access_requirements(user, "read"):
                handler.conclude_access_denial()
                return Result(code=403, target=document_id, username=handler.username)

            password = handler.data.get("password")
            link = ShareLink(
                document_id=document_id,
                created_by=handler.username,
                expires_at=handler.data.get("expires_at"),
                max_downloads=handler.data.get("max_downloads"),
                password_hash=hash_share_password(password) if password else None,
            )
            session.add(link)
            session.commit()
            data = share_to_dict(link)

        handler.conclude_request(200, {"share": data}, "Share link created")
        return Result(code=0, target=data["token"], username=handler.username)


class RequestListShareLinksHandler(RequestHandler):
    require_auth = True
    schema = {"type": "object", "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            links = (
                session.query(ShareLink)
                .filter(ShareLink.created_by == handler.username)
                .order_by(ShareLink.created_at.desc())
                .all()
            )
            shares = [share_to_dict(link) for link in links]
        handler.conclude_request(200, {"shares": shares}, "Share links listed")
        return Result(code=0, username=handler.username)


class RequestRevokeShareLinkHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {"token": {"type": "string", "minLength": 1}},
        "required": ["token"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        token = handler.data["token"]
        with Session() as session:
            link = session.get(ShareLink, token)
            if link is None:
                handler.conclude_request(404, {}, "Share link not found")
                return Result(code=404, target=token, username=handler.username)
            user = User.get_existing(session, handler.username)
            if link.created_by != handler.username and "sysop" not in user.all_groups:
                handler.conclude_permission_denial()
                return Result(code=403, target=token, username=handler.username)
            link.revoked = True
            session.commit()

        handler.conclude_request(200, {"token": token}, "Share link revoked")
        return Result(code=0, target=token, username=handler.username)


class RequestPrepareShareDownloadHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "minLength": 1},
            "password": {
                "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]
            },
        },
        "required": ["token"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        token = handler.data["token"]
        settings = get_transfer_settings()
        if not settings.enabled:
            handler.conclude_request(503, {}, "HTTP transfer data plane is disabled")
            return Result(code=503, target=token)

        try:
            with Session() as session:
                result = prepare_share_download(
                    session,
                    token=token,
                    password=handler.data.get("password"),
                    settings=settings,
                    store=RedisTransferSessionStore(),
                )
        except SharePasswordError as exc:
            handler.conclude_request(401, {}, str(exc))
            return Result(code=401, target=token)
        except ShareUnavailableError as exc:
            handler.conclude_request(410, {}, str(exc))
            return Result(code=410, target=token)
        except (redis.RedisError, OSError, ValueError):
            handler.conclude_request(503, {}, "Transfer service is unavailable")
            return Result(code=503, target=token)

        handler.conclude_request(200, result, "Share download prepared")
        return Result(code=0, target=result["task_id"])
