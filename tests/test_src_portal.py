import importlib
import time
from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


@dataclass
class FakeConnectionHandler:
    data: dict[str, Any]
    username: str
    responses: list[dict[str, Any]] = field(default_factory=list)

    def conclude_request(
        self,
        code: int,
        data: dict[str, Any] | None = None,
        message: str = "",
    ) -> None:
        self.responses.append({"code": code, "data": data or {}, "message": message})


@pytest.fixture
def src_context(protected_test_config, tmp_path, monkeypatch):
    monkeypatch.chdir(protected_test_config.src_dir)
    import include.database.models  # noqa: F401
    from include.database.session import Base

    portal = importlib.import_module("include.extensions.src_portal._extension")
    engine = create_engine(f"sqlite:///{tmp_path / 'src-portal.db'}")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    from include.database.models.documents import Folder
    with factory() as session:
        session.add(Folder(id="/", name="/", parent_id=None, inherit=False))
        session.commit()
    monkeypatch.setattr(portal, "Session", factory)
    yield portal, factory
    engine.dispose()


def _seed_user(session, username: str, *, sysop: bool = False):
    from include.database.models.identity import User, UserGroup, UserMembership

    if sysop and session.get(UserGroup, "sysop") is None:
        session.add(UserGroup(group_name="sysop", group_display_name="System operators"))
    user = User(
        username=username,
        pass_hash="unused",
        nickname=username,
        last_login=0,
        created_time=time.time(),
    )
    if sysop:
        user.groups.append(
            UserMembership(group_name="sysop", start_time=0, end_time=None)
        )
    session.add(user)
    session.flush()
    return user


def _seed_document(session, username: str, *, title: str = "evidence.txt"):
    from include.database.models.documents import (
        Document,
        DocumentMetadata,
        DocumentRevision,
    )
    from include.database.models.files import File

    file_record = File(
        path=f"content/files/{username}/{title}",
        size=8,
        sha256="a" * 64,
        active=True,
    )
    document = Document(title=title, inherit=False)
    document.metadata_record = DocumentMetadata(creator_username=username)
    revision = DocumentRevision(file=file_record)
    document.revisions.append(revision)
    document.current_revision = revision
    session.add_all([file_record, document, revision])
    session.flush()
    return document


def _call(portal, handler_type, username: str, data: dict[str, Any]):
    handler = FakeConnectionHandler(data=data, username=username)
    result = handler_type().handle(handler)
    assert result.code == handler.responses[-1]["code"]
    return handler.responses[-1]


def _create_report(
    portal,
    username: str,
    attachment_id: str | None = None,
    *,
    severity: str = "high",
):
    attachments = []
    if attachment_id:
        attachments.append(
            {"document_id": attachment_id, "filename": "request-response.txt"}
        )
    return _call(
        portal,
        portal.RequestSrcCreateReportHandler,
        username,
        {
            "title": "越权读取私有文件",
            "category": "访问控制",
            "severity": severity,
            "affected_url": "https://thesis.n1n3bird.top/files/1",
            "description_md": "## 复现步骤\n1. 登录普通账号\n2. 修改对象 ID",
            "attachments": attachments,
        },
    )


def test_src_extension_registers_complete_surface(src_context):
    portal, _factory = src_context
    assert set(portal.ext_register_handlers()) == {
        "src_create_report",
        "src_list_my_reports",
        "src_get_leaderboard",
        "src_get_report",
        "src_list_reports",
        "src_update_report_status",
        "src_prepare_attachment_download",
    }
    assert portal.ext_register_extension_flags() == {"src_portal"}


def test_report_owner_can_submit_markdown_and_own_attachment(src_context):
    portal, factory = src_context
    with factory() as session:
        _seed_user(session, "alice")
        document = _seed_document(session, "alice")
        session.commit()
        document_id = document.id

    response = _create_report(portal, "alice", document_id)
    assert response["code"] == 200
    report = response["data"]["report"]
    assert report["status"] == "审核中"
    assert report["description_md"].startswith("## 复现步骤")
    assert report["attachments"][0]["filename"] == "request-response.txt"
    assert report["events"][0]["to_status"] == "审核中"


def test_user_cannot_attach_another_users_document(src_context):
    portal, factory = src_context
    with factory() as session:
        _seed_user(session, "alice")
        _seed_user(session, "bob")
        document = _seed_document(session, "bob")
        session.commit()
        document_id = document.id

    response = _create_report(portal, "alice", document_id)
    assert response["code"] == 403


def test_personal_list_is_scoped_to_authenticated_reporter(src_context):
    portal, factory = src_context
    with factory() as session:
        _seed_user(session, "alice")
        _seed_user(session, "bob")
        session.commit()
    _create_report(portal, "alice")
    _create_report(portal, "bob")

    response = _call(portal, portal.RequestSrcListMyReportsHandler, "alice", {})
    assert response["code"] == 200
    assert [item["reporter_username"] for item in response["data"]["reports"]] == [
        "alice"
    ]


def test_only_sysop_can_review_and_status_changes_are_audited(src_context):
    portal, factory = src_context
    with factory() as session:
        _seed_user(session, "alice")
        _seed_user(session, "reviewer", sysop=True)
        session.commit()
    created = _create_report(portal, "alice")
    report_id = created["data"]["report"]["id"]

    denied = _call(portal, portal.RequestSrcListReportsHandler, "alice", {})
    assert denied["code"] == 403

    updated = _call(
        portal,
        portal.RequestSrcUpdateReportStatusHandler,
        "reviewer",
        {
            "report_id": report_id,
            "status": "fixing",
            "note_md": "已分派给存储模块维护者。",
        },
    )
    assert updated["code"] == 200
    report = updated["data"]["report"]
    assert report["status"] == "修复中"
    assert report["events"][-1]["actor_username"] == "reviewer"
    assert report["events"][-1]["note_md"] == "已分派给存储模块维护者。"


def test_leaderboard_scores_only_passed_reports_by_severity(src_context):
    portal, factory = src_context
    with factory() as session:
        _seed_user(session, "alice")
        _seed_user(session, "bob")
        _seed_user(session, "reviewer", sysop=True)
        session.commit()

    alice = _create_report(portal, "alice", severity="high")
    bob = _create_report(portal, "bob", severity="critical")
    _create_report(portal, "bob", severity="low")
    for report in (alice, bob):
        updated = _call(
            portal,
            portal.RequestSrcUpdateReportStatusHandler,
            "reviewer",
            {
                "report_id": report["data"]["report"]["id"],
                "status": "passed",
            },
        )
        assert updated["code"] == 200

    response = _call(
        portal, portal.RequestSrcGetLeaderboardHandler, "alice", {}
    )
    assert response["code"] == 200
    assert response["data"]["score_rules"] == {
        "low": 10,
        "medium": 30,
        "high": 60,
        "critical": 100,
    }
    assert [
        (item["rank"], item["username"], item["score"])
        for item in response["data"]["leaderboard"]
    ] == [(1, "bob", 100), (2, "alice", 60)]
    assert response["data"]["me"]["rank"] == 2
    assert response["data"]["me"]["accepted_count"] == 1


def test_report_owner_and_sysop_can_prepare_attachment_download(src_context):
    portal, factory = src_context
    with factory() as session:
        _seed_user(session, "alice")
        _seed_user(session, "bob")
        _seed_user(session, "reviewer", sysop=True)
        document = _seed_document(session, "alice")
        session.commit()
        document_id = document.id
    created = _create_report(portal, "alice", document_id)
    attachment_id = created["data"]["report"]["attachments"][0]["id"]

    owner = _call(
        portal,
        portal.RequestSrcPrepareAttachmentDownloadHandler,
        "alice",
        {"attachment_id": attachment_id},
    )
    reviewer = _call(
        portal,
        portal.RequestSrcPrepareAttachmentDownloadHandler,
        "reviewer",
        {"attachment_id": attachment_id},
    )
    denied = _call(
        portal,
        portal.RequestSrcPrepareAttachmentDownloadHandler,
        "bob",
        {"attachment_id": attachment_id},
    )
    assert owner["code"] == reviewer["code"] == 200
    assert owner["data"]["task_data"]["task_id"]
    assert denied["code"] == 404
