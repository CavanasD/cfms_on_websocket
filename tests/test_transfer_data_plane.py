from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def transfer_modules(monkeypatch, tmp_path):
    src_dir = Path(__file__).resolve().parents[1] / "src"
    shutil.copy(src_dir / "config.toml.sample", tmp_path / "config.toml")
    (tmp_path / "init").write_text("test", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    from include.domains.transfers import consumer, settings, tickets

    return SimpleNamespace(consumer=consumer, settings=settings, tickets=tickets)


def test_completion_socket_timeout_exceeds_blocking_read(transfer_modules, monkeypatch):
    captured = {}
    monkeypatch.setattr(transfer_modules.consumer.redis, "Redis", lambda **kwargs: captured.update(kwargs))
    transfer_modules.consumer._redis_client()
    assert captured["socket_timeout"] > 5000 / 1000
    assert captured["socket_connect_timeout"] == 5


def test_rs256_ticket_binds_transfer_claims(transfer_modules, tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    config = replace(
        transfer_modules.settings.get_transfer_settings(),
        enabled=True,
        private_key_file=str(private_path),
        ticket_ttl_seconds=60,
    )

    token, expires_at = transfer_modules.tickets.issue_transfer_ticket(
        config,
        task_id="task-1",
        username="alice",
        operation="upload",
        object_key="content/files/object-1",
        max_size=1234,
        expected_sha256="A" * 64,
    )
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience="transfer-data-plane",
        issuer="thesis-drive-core",
    )

    assert claims["task_id"] == "task-1"
    assert claims["username"] == claims["sub"] == "alice"
    assert claims["operation"] == "upload"
    assert claims["object_key"] == "content/files/object-1"
    assert claims["max_size"] == 1234
    assert claims["expected_sha256"] == "a" * 64
    assert claims["iss"] == "thesis-drive-core"
    assert claims["aud"] == "transfer-data-plane"
    assert claims["exp"] == expires_at
    assert claims["jti"]


def test_empty_pending_stream_does_not_starve_new_completions(transfer_modules):
    from unittest.mock import Mock

    client = Mock()
    settings = transfer_modules.settings.get_transfer_settings()
    event = ("1-0", {"task_id": "new-upload", "status": "completed"})
    client.xreadgroup.side_effect = [
        [(settings.stream, [])],
        [(settings.stream, [event])],
    ]
    consumer = transfer_modules.consumer.TransferCompletionConsumer(settings, client)

    batches = consumer._read("0", 1) or consumer._read(">", 5000)

    assert batches == [(settings.stream, [event])]
    assert client.xreadgroup.call_args.args[2] == {settings.stream: ">"}


def test_completion_event_commits_before_it_can_be_acked(transfer_modules, monkeypatch):
    file_record = SimpleNamespace(
        path="content/files/object-1", size=None, sha256=None, active=False
    )
    task = SimpleNamespace(
        mode=transfer_modules.consumer.TransferMode.UPLOAD,
        status=0,
        file=file_record,
        end_time=None,
    )

    class FakeQuery:
        def with_for_update(self):
            return self

        def filter_by(self, **_kwargs):
            return self

        def first(self):
            return task

    class FakeSession:
        commits = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def query(self, *_args):
            return FakeQuery()

        def commit(self):
            self.commits += 1

    fake_session = FakeSession()
    monkeypatch.setattr(transfer_modules.consumer, "Session", lambda: fake_session)
    monkeypatch.setattr(
        transfer_modules.consumer, "file_owners_fit_quota", lambda *_args: True
    )
    fields = {
        "event_id": "event-1",
        "task_id": "task-1",
        "object_key": "content/files/object-1",
        "size": "4",
        "sha256": "a" * 64,
        "status": "completed",
    }

    transfer_modules.consumer.apply_completion_event(fields)
    transfer_modules.consumer.apply_completion_event(fields)

    assert fake_session.commits == 1
    assert task.status == 1
    assert file_record.size == 4
    assert file_record.sha256 == "a" * 64
    assert file_record.active is True


def test_conflicting_duplicate_completion_is_rejected(transfer_modules, monkeypatch):
    file_record = SimpleNamespace(
        path="content/files/object-1", size=4, sha256="a" * 64, active=True
    )
    task = SimpleNamespace(
        mode=transfer_modules.consumer.TransferMode.UPLOAD,
        status=1,
        file=file_record,
        end_time=None,
    )
    query = SimpleNamespace(
        with_for_update=lambda: query,
        filter_by=lambda **_kwargs: query,
        first=lambda: task,
    )
    session = SimpleNamespace(
        __enter__=lambda self: self,
        __exit__=lambda self, *_args: None,
        query=lambda *_args: query,
    )

    class SessionContext:
        def __enter__(self):
            return session

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(transfer_modules.consumer, "Session", SessionContext)

    with pytest.raises(
        transfer_modules.consumer.PermanentTransferEventError,
        match="conflicts",
    ):
        transfer_modules.consumer.apply_completion_event(
            {
                "task_id": "task-1",
                "object_key": "content/files/object-1",
                "size": "5",
                "sha256": "b" * 64,
                "status": "completed",
            }
        )


def test_quota_rejection_marks_redis_failed_before_ack(
    transfer_modules, monkeypatch
):
    fields = {
        "event_id": "event-1",
        "task_id": "task-1",
        "object_key": "content/files/object-1",
        "size": "4",
        "sha256": "a" * 64,
        "status": "completed",
    }

    class RecordingRedis:
        def __init__(self):
            self.operations = []

        def hset(self, key, mapping):
            self.operations.append(("hset", key, mapping))

        def xadd(self, stream, payload):
            self.operations.append(("xadd", stream, payload))

        def xack(self, stream, group, message_id):
            self.operations.append(("xack", stream, group, message_id))

    client = RecordingRedis()
    config = transfer_modules.settings.get_transfer_settings()
    completion_consumer = transfer_modules.consumer.TransferCompletionConsumer(
        config, client
    )
    monkeypatch.setattr(completion_consumer, "_ensure_group", lambda: None)

    def read_once(_marker, _block):
        completion_consumer._stop.set()
        return [(config.stream, [("1-0", fields)])]

    monkeypatch.setattr(completion_consumer, "_read", read_once)
    monkeypatch.setattr(
        transfer_modules.consumer,
        "apply_completion_event",
        lambda _fields: (_ for _ in ()).throw(
            transfer_modules.consumer.QuotaExceededTransferEventError(
                "Upload exceeds quota"
            )
        ),
    )

    completion_consumer._run()

    assert client.operations[0] == (
        "hset",
        "transfer:session:task-1",
        {"status": "failed", "error": "quota_exceeded"},
    )
    assert client.operations[1][0] == "xadd"
    assert client.operations[2] == (
        "xack",
        config.stream,
        config.consumer_group,
        "1-0",
    )


def test_transient_completion_failure_is_not_acked(transfer_modules, monkeypatch):
    fields = {
        "task_id": "task-1",
        "object_key": "content/files/object-1",
        "status": "completed",
    }

    class RecordingRedis:
        def __init__(self):
            self.acked = []

        def xack(self, *args):
            self.acked.append(args)

    client = RecordingRedis()
    config = transfer_modules.settings.get_transfer_settings()
    completion_consumer = transfer_modules.consumer.TransferCompletionConsumer(
        config, client
    )
    monkeypatch.setattr(completion_consumer, "_ensure_group", lambda: None)

    def read_once(_marker, _block):
        completion_consumer._stop.set()
        return [(config.stream, [("1-0", fields)])]

    monkeypatch.setattr(completion_consumer, "_read", read_once)
    monkeypatch.setattr(
        transfer_modules.consumer,
        "apply_completion_event",
        lambda _fields: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
    )

    completion_consumer._run()

    assert client.acked == []


class _ScriptRedis:
    def __init__(self):
        self.hashes = {}
        self.ttls = {}

    def eval(self, _script, _numkeys, key, *arguments):
        cursor = 0
        requested_ttl = int(arguments[cursor])
        cursor += 1
        immutable_count = int(arguments[cursor])
        cursor += 1
        exists = key in self.hashes
        for _ in range(immutable_count):
            field = str(arguments[cursor])
            present = int(arguments[cursor + 1]) == 1
            expected = str(arguments[cursor + 2])
            cursor += 3
            if exists and (
                (present and self.hashes[key].get(field) != expected)
                or (not present and field in self.hashes[key])
            ):
                return [-1, field]

        mapping_count = int(arguments[cursor])
        cursor += 1
        mapping = {}
        for _ in range(mapping_count):
            mapping[str(arguments[cursor])] = str(arguments[cursor + 1])
            cursor += 2
        if not exists:
            self.hashes[key] = mapping
            self.ttls[key] = requested_ttl

        flattened = []
        for field, value in self.hashes[key].items():
            flattened.extend((field, value))
        return [0 if exists else 1, self.ttls[key], *flattened]


def test_transfer_session_retry_reuses_resume_state_and_rejects_conflicts(
    protected_test_config,
):
    from include.domains.transfers.store import (
        RedisTransferSessionStore,
        TransferSessionConflictError,
    )

    client = _ScriptRedis()
    store = RedisTransferSessionStore(client)
    immutable_fields = (
        "task_id",
        "username",
        "operation",
        "object_key",
        "max_size",
        "expected_sha256",
        "filename",
        "content_type",
    )
    values = {
        "task_id": "task-1",
        "username": "alice",
        "operation": "upload",
        "object_key": "content/files/object-1",
        "max_size": 16,
        "expected_sha256": "a" * 64,
        "filename": "report.pdf",
        "content_type": "application/pdf",
        "offset": 0,
        "status": "pending",
        "expires_at": 200,
    }

    created = store.create_or_reuse(values, 60, immutable_fields=immutable_fields)
    assert created.created is True

    key = store.key("task-1")
    client.hashes[key]["offset"] = "8"
    client.hashes[key]["status"] = "running"
    client.ttls[key] = 42
    retry_values = {**values, "offset": 0, "status": "pending", "expires_at": 999}
    reused = store.create_or_reuse(retry_values, 60, immutable_fields=immutable_fields)

    assert reused.created is False
    assert reused.ttl_seconds == 42
    assert reused.values["offset"] == "8"
    assert reused.values["status"] == "running"
    assert reused.values["expires_at"] == "200"

    with pytest.raises(TransferSessionConflictError, match="filename"):
        store.create_or_reuse(
            {**retry_values, "filename": "different.pdf"},
            60,
            immutable_fields=immutable_fields,
        )
