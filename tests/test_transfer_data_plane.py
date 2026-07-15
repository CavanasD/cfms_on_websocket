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


def test_completion_event_commits_before_it_can_be_acked(
    transfer_modules, monkeypatch
):
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


def test_conflicting_duplicate_completion_is_rejected(
    transfer_modules, monkeypatch
):
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
