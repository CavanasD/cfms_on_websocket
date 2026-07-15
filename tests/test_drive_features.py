from __future__ import annotations

import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def drive_session_factory(protected_test_config, tmp_path):
    # Import only after protected_test_config has installed src/config.toml.
    import include.database.models  # noqa: F401
    from include.database.session import Base

    engine = create_engine(
        f"sqlite:///{tmp_path / 'drive-features.db'}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _configure_sqlite(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    yield factory
    engine.dispose()


def _new_user(username: str, *, quota: int = 10 * 1024**3):
    from include.database.models.identity import User

    return User(
        username=username,
        pass_hash="unused-in-unit-tests",
        nickname=username,
        last_login=0,
        created_time=time.time(),
        disk_quota=quota,
    )


def _seed_document(session, username: str, *, size: int | None = 4):
    from include.database.models.documents import (
        Document,
        DocumentMetadata,
        DocumentRevision,
    )
    from include.database.models.files import File

    file_record = File(
        path=f"content/files/{secrets.token_hex(16)}",
        size=size,
        sha256="a" * 64 if size is not None else None,
        active=size is not None,
    )
    document = Document(title=f"doc-{secrets.token_hex(4)}")
    document.metadata_record = DocumentMetadata(creator_username=username)
    revision = DocumentRevision(file=file_record)
    document.revisions.append(revision)
    document.current_revision = revision
    session.add_all([file_record, document, revision])
    session.flush()
    return document, file_record, revision


def test_personal_home_is_private_and_idempotent(drive_session_factory):
    from include.config.constants import HOME_PARENT_DIRECTORY_ID, ROOT_DIRECTORY_ID
    from include.database.models.access import ObjectAccessEntry
    from include.database.models.documents import Folder
    from include.domains.drive.homes import ensure_user_home

    with drive_session_factory() as session:
        session.add(Folder(id=ROOT_DIRECTORY_ID, name="/", inherit=False))
        user = _new_user("alice")
        session.add(user)
        session.flush()

        first_id = ensure_user_home(session, user)
        session.commit()

    with drive_session_factory() as session:
        user = session.get(type(user), "alice")
        second_id = ensure_user_home(session, user)
        session.commit()

        assert first_id == second_id == user.home_directory_id
        home = session.get(Folder, first_id)
        assert home.parent_id == HOME_PARENT_DIRECTORY_ID
        assert home.inherit is False
        assert home.check_access_requirements(user, "read") is True
        grants = (
            session.query(ObjectAccessEntry)
            .filter_by(
                entity_type="user",
                entity_identifier="alice",
                target_type="directory",
                target_identifier=first_id,
            )
            .all()
        )
        assert {grant.access_type for grant in grants} == {
            "read",
            "write",
            "move",
            "manage",
        }
        assert (
            session.query(Folder).filter_by(parent_id=HOME_PARENT_DIRECTORY_ID).count()
            == 1
        )


def test_disk_usage_counts_each_owned_file_once(drive_session_factory):
    from include.database.models.documents import (
        Document,
        DocumentMetadata,
        DocumentRevision,
    )
    from include.database.models.files import File
    from include.domains.drive.quota import get_user_disk_usage

    with drive_session_factory() as session:
        session.add(_new_user("alice"))
        session.flush()

        shared_file = File(path="content/files/shared", size=100, active=True)
        second_file = File(path="content/files/second", size=200, active=True)
        first = Document(
            title="first", metadata_record=DocumentMetadata(creator_username="alice")
        )
        second = Document(
            title="second", metadata_record=DocumentMetadata(creator_username="alice")
        )
        first.revisions.extend(
            [DocumentRevision(file=shared_file), DocumentRevision(file=second_file)]
        )
        second.revisions.append(DocumentRevision(file=shared_file))
        session.add_all([shared_file, second_file, first, second])
        session.commit()

        assert get_user_disk_usage(session, "alice") == 300


def test_prepare_upload_rejects_owner_quota_overflow(
    drive_session_factory, monkeypatch
):
    from include.database.models.files import FileTask, TransferMode
    from include.domains.transfers import handlers

    with drive_session_factory() as session:
        session.add(_new_user("alice", quota=3))
        session.flush()
        _document, file_record, _revision = _seed_document(session, "alice", size=None)
        task = FileTask(
            file=file_record,
            status=0,
            mode=TransferMode.UPLOAD,
            start_time=time.time(),
            end_time=time.time() + 60,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    monkeypatch.setattr(handlers, "Session", drive_session_factory)
    authorized, code, message = handlers._authorize_task(
        task_id, "alice", "upload", expected_size=4
    )

    assert authorized is None
    assert code == 413
    assert "quota" in message.lower()


def test_completion_event_rechecks_quota(drive_session_factory, monkeypatch):
    from include.database.models.files import FileTask, TransferMode
    from include.domains.transfers import consumer

    with drive_session_factory() as session:
        session.add(_new_user("alice", quota=3))
        session.flush()
        _document, file_record, _revision = _seed_document(session, "alice", size=None)
        task = FileTask(
            file=file_record,
            status=0,
            mode=TransferMode.UPLOAD,
            start_time=time.time(),
            end_time=time.time() + 60,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    class RecordingStorage:
        def __init__(self):
            self.objects = {file_record.path}
            self.removed = []

        def remove(self, path):
            self.removed.append(path)
            if path not in self.objects:
                return False
            self.objects.remove(path)
            return True

        def exists(self, path):
            return path in self.objects

    storage = RecordingStorage()
    monkeypatch.setattr(consumer, "Session", drive_session_factory)
    monkeypatch.setattr(
        consumer,
        "ProviderManager",
        lambda: type("Manager", (), {"storage": storage})(),
    )
    with pytest.raises(consumer.PermanentTransferEventError, match="quota"):
        consumer.apply_completion_event(
            {
                "task_id": task_id,
                "object_key": file_record.path,
                "size": "4",
                "sha256": "b" * 64,
                "status": "completed",
            }
        )

    with drive_session_factory() as session:
        task = session.get(FileTask, task_id)
        assert task.status == 2
        assert task.file.active is False
    assert storage.removed == [file_record.path]
    assert storage.objects == set()


def test_quota_rejection_replay_retries_object_cleanup(
    drive_session_factory, monkeypatch
):
    from include.database.models.files import FileTask, TransferMode
    from include.domains.transfers import consumer

    with drive_session_factory() as session:
        session.add(_new_user("alice", quota=3))
        session.flush()
        _document, file_record, _revision = _seed_document(session, "alice", size=None)
        task = FileTask(
            file=file_record,
            status=0,
            mode=TransferMode.UPLOAD,
            start_time=time.time(),
            end_time=time.time() + 60,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    class FlakyStorage:
        attempts = 0
        present = True

        def remove(self, _path):
            self.attempts += 1
            if self.attempts == 1:
                return False
            self.present = False
            return True

        def exists(self, _path):
            return self.present

    storage = FlakyStorage()
    monkeypatch.setattr(consumer, "Session", drive_session_factory)
    monkeypatch.setattr(
        consumer,
        "ProviderManager",
        lambda: type("Manager", (), {"storage": storage})(),
    )
    fields = {
        "task_id": task_id,
        "object_key": file_record.path,
        "size": "4",
        "sha256": "b" * 64,
        "status": "completed",
    }

    with pytest.raises(RuntimeError, match="could not be removed"):
        consumer.apply_completion_event(fields)
    with drive_session_factory() as session:
        task = session.get(FileTask, task_id)
        assert task.status == 2
        assert task.file.active is False

    with pytest.raises(consumer.QuotaExceededTransferEventError, match="quota"):
        consumer.apply_completion_event(fields)
    assert storage.attempts == 2
    assert storage.present is False


def test_failed_orphan_event_retries_object_cleanup(
    drive_session_factory, monkeypatch
):
    from include.database.models.files import FileTask, TransferMode
    from include.domains.transfers import consumer

    with drive_session_factory() as session:
        session.add(_new_user("alice"))
        session.flush()
        _document, file_record, _revision = _seed_document(session, "alice", size=None)
        task = FileTask(
            file=file_record,
            status=0,
            mode=TransferMode.UPLOAD,
            start_time=time.time(),
            end_time=time.time() + 60,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    class FlakyStorage:
        attempts = 0
        present = True

        def remove(self, _path):
            self.attempts += 1
            if self.attempts == 1:
                return False
            self.present = False
            return True

        def exists(self, _path):
            return self.present

    storage = FlakyStorage()
    monkeypatch.setattr(consumer, "Session", drive_session_factory)
    monkeypatch.setattr(
        consumer,
        "ProviderManager",
        lambda: type("Manager", (), {"storage": storage})(),
    )
    fields = {
        "task_id": task_id,
        "object_key": file_record.path,
        "status": "failed",
        "error": "object_store_failure",
        "orphaned": "true",
    }

    with pytest.raises(RuntimeError, match="could not be removed"):
        consumer.apply_completion_event(fields)
    with drive_session_factory() as session:
        assert session.get(FileTask, task_id).status == 2

    consumer.apply_completion_event(fields)
    assert storage.attempts == 2
    assert storage.present is False


def test_prepare_upload_forwards_type_metadata_to_transfer_session(
    monkeypatch, transfer_settings
):
    from include.domains.transfers import handlers

    captured = {}

    class FakeHandler:
        username = "alice"
        data = {
            "task_id": "task-1",
            "size": 12,
            "filename": "disguised.txt",
            "content_type": "text/plain",
            "sha256": None,
        }

        def conclude_request(self, code, data, message):
            captured["response"] = (code, data, message)

    monkeypatch.setattr(handlers, "get_transfer_settings", lambda: transfer_settings)
    monkeypatch.setattr(
        handlers,
        "_authorize_task",
        lambda *_args, **_kwargs: (
            handlers.TransferAuthorization(
                "content/files/object",
                None,
                None,
                "report.pdf",
                "application/pdf",
            ),
            200,
            "",
        ),
    )
    monkeypatch.setattr(
        handlers,
        "issue_transfer_ticket",
        lambda *_args, **_kwargs: ("ticket", int(time.time()) + 60),
    )

    def record_session(_handler, values, _ttl_seconds):
        from include.domains.transfers.store import TransferSessionReservation

        captured["session"] = values
        resumed = dict(values)
        resumed.update({"offset": "8", "status": "running"})
        return TransferSessionReservation(resumed, False, 30), None

    monkeypatch.setattr(
        handlers.RequestPrepareUploadHandler,
        "_reserve_upload_session",
        staticmethod(record_session),
    )

    result = handlers.RequestPrepareUploadHandler().handle(FakeHandler())

    assert result.code == 0
    assert captured["session"]["filename"] == "report.pdf"
    assert captured["session"]["content_type"] == "application/pdf"
    assert captured["response"][1]["offset"] == 8
    assert captured["response"][1]["status"] == "running"


@pytest.mark.parametrize(
    ("operation", "redis_status", "expected_status"),
    [
        ("download", "ready", "pending"),
        ("download", "receiving", "running"),
        ("download", "finalizing", "running"),
        ("download", "completed", "completed"),
        ("download", "failed", "failed"),
    ],
)
def test_transfer_status_normalizes_internal_states(
    monkeypatch,
    transfer_settings,
    operation,
    redis_status,
    expected_status,
):
    from include.domains.transfers import handlers

    captured = {}

    class FakeHandler:
        username = "alice"
        data = {"task_id": "task-1"}

        def conclude_request(self, code, data, message):
            captured["response"] = (code, data, message)

    class FakeStore:
        def get(self, _task_id):
            return {
                "task_id": "task-1",
                "username": "alice",
                "operation": operation,
                "status": redis_status,
            }

    monkeypatch.setattr(handlers, "get_transfer_settings", lambda: transfer_settings)
    monkeypatch.setattr(handlers, "RedisTransferSessionStore", FakeStore)

    result = handlers.RequestGetTransferStatusHandler().handle(FakeHandler())

    assert result.code == 0
    assert captured["response"][1]["status"] == expected_status


@pytest.mark.parametrize(
    ("database_status", "expected_status", "expected_error"),
    [
        (0, "running", None),
        (1, "completed", None),
        (2, "failed", "upload_rejected"),
    ],
)
def test_upload_status_waits_for_core_commit(
    drive_session_factory,
    monkeypatch,
    transfer_settings,
    database_status,
    expected_status,
    expected_error,
):
    from include.database.models.files import FileTask, TransferMode
    from include.domains.transfers import handlers

    with drive_session_factory() as session:
        session.add(_new_user("alice"))
        session.flush()
        _document, file_record, _revision = _seed_document(session, "alice", size=None)
        task = FileTask(
            file=file_record,
            status=database_status,
            mode=TransferMode.UPLOAD,
            start_time=time.time(),
            end_time=time.time() + 60,
        )
        session.add(task)
        session.commit()
        task_id = task.id

    captured = {}

    class FakeHandler:
        username = "alice"
        data = {"task_id": task_id}

        def conclude_request(self, code, data, message):
            captured["response"] = (code, data, message)

    class FakeStore:
        def get(self, _task_id):
            return {
                "task_id": task_id,
                "username": "alice",
                "operation": "upload",
                "status": "completed",
            }

    monkeypatch.setattr(handlers, "get_transfer_settings", lambda: transfer_settings)
    monkeypatch.setattr(handlers, "RedisTransferSessionStore", FakeStore)
    monkeypatch.setattr(handlers, "Session", drive_session_factory)

    result = handlers.RequestGetTransferStatusHandler().handle(FakeHandler())

    response = captured["response"][1]
    assert result.code == 0
    assert response["status"] == expected_status
    if expected_error is None:
        assert "error" not in response
    else:
        assert response["error"] == expected_error


def test_prepare_download_returns_and_stores_document_type_metadata(
    monkeypatch, transfer_settings
):
    from include.domains.transfers import handlers

    captured = {}

    class FakeHandler:
        username = "alice"
        data = {"task_id": "download-1"}

        def conclude_request(self, code, data, message):
            captured["response"] = (code, data, message)

    monkeypatch.setattr(handlers, "get_transfer_settings", lambda: transfer_settings)
    monkeypatch.setattr(
        handlers,
        "_authorize_task",
        lambda *_args, **_kwargs: (
            handlers.TransferAuthorization(
                "content/files/object",
                12,
                "a" * 64,
                "report.pdf",
                "application/pdf",
            ),
            200,
            "",
        ),
    )
    monkeypatch.setattr(
        handlers,
        "issue_transfer_ticket",
        lambda *_args, **_kwargs: ("ticket", int(time.time()) + 60),
    )

    def record_session(_handler, values, _ttl_seconds):
        captured["session"] = values
        return None

    monkeypatch.setattr(
        handlers.RequestPrepareDownloadHandler,
        "_store_session",
        staticmethod(record_session),
    )

    result = handlers.RequestPrepareDownloadHandler().handle(FakeHandler())

    assert result.code == 0
    assert captured["session"]["filename"] == "report.pdf"
    assert captured["session"]["content_type"] == "application/pdf"
    response = captured["response"][1]
    assert response["filename"] == "report.pdf"
    assert response["content_type"] == "application/pdf"
    assert response["download_url"].endswith("/download-1/content")
    assert response["ticket"] == "ticket"


@pytest.fixture
def transfer_settings(protected_test_config, tmp_path):
    from include.domains.transfers.settings import get_transfer_settings

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "share-transfer-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return replace(
        get_transfer_settings(),
        enabled=True,
        private_key_file=str(private_path),
        ticket_ttl_seconds=60,
        session_ttl_seconds=60,
        base_url="http://transfer.test",
    )


class _RecordingStore:
    def __init__(self):
        self.created = []
        self._lock = threading.Lock()

    def create(self, values, ttl_seconds):
        with self._lock:
            self.created.append((dict(values), ttl_seconds))


def _seed_share(
    factory,
    *,
    password: str | None = None,
    expires_at: float | None = None,
    max_downloads: int | None = None,
):
    from include.database.models.shares import ShareLink
    from include.domains.drive.shares import hash_share_password

    with factory() as session:
        session.add(_new_user("alice"))
        session.flush()
        document, _file, _revision = _seed_document(session, "alice")
        link = ShareLink(
            document_id=document.id,
            created_by="alice",
            expires_at=expires_at,
            max_downloads=max_downloads,
            password_hash=hash_share_password(password) if password else None,
        )
        session.add(link)
        session.commit()
        return link.token


def test_share_password_failure_does_not_consume_download(
    drive_session_factory, transfer_settings
):
    from include.database.models.shares import ShareLink
    from include.domains.drive.shares import (
        SharePasswordError,
        prepare_share_download,
    )

    token = _seed_share(
        drive_session_factory, password="correct-password", max_downloads=1
    )
    with drive_session_factory() as session:
        with pytest.raises(SharePasswordError):
            prepare_share_download(
                session,
                token=token,
                password="wrong-password",
                settings=transfer_settings,
                store=_RecordingStore(),
            )

    with drive_session_factory() as session:
        assert session.get(ShareLink, token).download_count == 0


def test_expired_share_does_not_consume_download(
    drive_session_factory, transfer_settings
):
    from include.database.models.shares import ShareLink
    from include.domains.drive.shares import (
        ShareUnavailableError,
        prepare_share_download,
    )

    token = _seed_share(
        drive_session_factory,
        expires_at=time.time() - 1,
        max_downloads=1,
    )
    with drive_session_factory() as session:
        with pytest.raises(ShareUnavailableError):
            prepare_share_download(
                session,
                token=token,
                password=None,
                settings=transfer_settings,
                store=_RecordingStore(),
            )

    with drive_session_factory() as session:
        assert session.get(ShareLink, token).download_count == 0


def test_share_download_limit_is_atomic_under_concurrency(
    drive_session_factory, transfer_settings
):
    from include.database.models.files import FileTask
    from include.database.models.shares import ShareLink
    from include.domains.drive.shares import (
        ShareUnavailableError,
        prepare_share_download,
    )

    token = _seed_share(drive_session_factory, max_downloads=1)
    barrier = threading.Barrier(2)
    store = _RecordingStore()

    def worker():
        barrier.wait()
        with drive_session_factory() as session:
            try:
                return prepare_share_download(
                    session,
                    token=token,
                    password=None,
                    settings=transfer_settings,
                    store=store,
                )
            except ShareUnavailableError:
                return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: worker(), range(2)))

    assert sum(result is not None for result in results) == 1
    with drive_session_factory() as session:
        assert session.get(ShareLink, token).download_count == 1
        assert session.query(FileTask).count() == 1
    assert len(store.created) == 1
    successful = next(result for result in results if result is not None)
    assert successful["filename"].startswith("doc-")
    assert successful["content_type"] == "application/octet-stream"
    assert store.created[0][0]["filename"] == successful["filename"]
    assert store.created[0][0]["content_type"] == successful["content_type"]


def test_share_download_action_is_anonymous_by_contract():
    from include.domains.drive.handlers import RequestPrepareShareDownloadHandler

    assert RequestPrepareShareDownloadHandler.require_auth is False


@pytest.mark.asyncio
async def test_frontend_registration_home_and_share_contract(
    unauthenticated_client, authenticated_client
):
    username = f"drive_{secrets.token_hex(4)}"
    password = "TestPassword123!"
    try:
        registered = await unauthenticated_client.send_request(
            "register",
            {"username": username, "password": password, "nickname": "Drive User"},
            include_auth=False,
        )
        assert registered["code"] == 200

        login = await unauthenticated_client.login(username, password)
        assert login["code"] == 200
        assert login["data"]["home_directory_id"]
        assert login["data"]["disk_quota"] == 10 * 1024**3
        assert login["data"]["disk_used"] == 0

        created = await unauthenticated_client.create_directory(
            "private", login["data"]["home_directory_id"]
        )
        assert created["code"] == 200

        document = await unauthenticated_client.create_document(
            "share-me", login["data"]["home_directory_id"]
        )
        assert document["code"] == 200
        await unauthenticated_client.upload_file_to_server(
            document["data"]["task_data"]["task_id"], "./pyproject.toml"
        )

        quota = await unauthenticated_client.send_request("get_quota", {})
        assert quota["code"] == 200
        assert quota["data"]["disk_quota"] == 10 * 1024**3
        assert quota["data"]["disk_used"] == Path("pyproject.toml").stat().st_size

        created_share = await unauthenticated_client.send_request(
            "create_share_link",
            {
                "document_id": document["data"]["document_id"],
                "password": "share-secret",
                "max_downloads": 2,
            },
        )
        assert created_share["code"] == 200
        token = created_share["data"]["share"]["token"]

        listed = await unauthenticated_client.send_request("list_share_links", {})
        assert listed["code"] == 200
        assert token in {share["token"] for share in listed["data"]["shares"]}

        revoked = await unauthenticated_client.send_request(
            "revoke_share_link", {"token": token}
        )
        assert revoked["code"] == 200
    finally:
        await authenticated_client.delete_user(username)
