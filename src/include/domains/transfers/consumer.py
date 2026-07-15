from __future__ import annotations

import re
import threading
import time
from typing import Any

import redis
from loguru import logger

from include.config.settings import global_config
from include.database.models.files import FileTask, TransferMode
from include.database.session import Session
from include.domains.drive.quota import file_owners_fit_quota
from include.domains.transfers.settings import TransferSettings, get_transfer_settings
from include.domains.transfers.store import RedisTransferSessionStore
from include.providers.manager import ProviderManager

_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class PermanentTransferEventError(ValueError):
    pass


class QuotaExceededTransferEventError(PermanentTransferEventError):
    error_code = "quota_exceeded"


def _remove_rejected_object(object_key: str) -> None:
    """Delete a data-plane object before its rejected event can be acknowledged."""
    storage = ProviderManager().storage
    if storage.remove(object_key):
        return
    if storage.exists(object_key):
        raise RuntimeError(f"Rejected upload object could not be removed: {object_key}")


def _redis_client() -> redis.Redis:
    cfg = global_config["redis"]
    return redis.Redis(
        host=cfg["host"],
        port=cfg.get("port", 6379),
        password=cfg.get("password", ""),
        db=cfg.get("db", 0),
        decode_responses=True,
    )


def apply_completion_event(fields: dict[str, str]) -> None:
    task_id = fields.get("task_id", "")
    object_key = fields.get("object_key", "")
    status = fields.get("status", "")
    if not task_id or not object_key or status not in {"completed", "failed"}:
        raise PermanentTransferEventError("Malformed transfer completion event")

    with Session() as session:
        task = session.query(FileTask).with_for_update().filter_by(id=task_id).first()
        if task is None or task.mode != TransferMode.UPLOAD:
            raise PermanentTransferEventError("Upload task does not exist")
        if task.file.path != object_key:
            raise PermanentTransferEventError("Object key does not match upload task")

        if status == "failed":
            if task.status == 0:
                task.status = 2
                task.end_time = time.time()
                session.commit()
            if fields.get("orphaned", "").lower() == "true":
                # Transfer reports this only when its own MinIO rollback failed.
                # A cleanup failure remains transient so the stream event is
                # replayed instead of acknowledging a known orphan.
                _remove_rejected_object(object_key)
            return

        try:
            size = int(fields["size"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PermanentTransferEventError("Invalid completed size") from exc
        sha256 = fields.get("sha256", "").lower()
        if size < 0 or not _SHA256_PATTERN.fullmatch(sha256):
            raise PermanentTransferEventError("Invalid completed checksum")

        if task.status == 1:
            if task.file.size != size or task.file.sha256 != sha256:
                raise PermanentTransferEventError(
                    "Duplicate completion event conflicts with committed metadata"
                )
            return
        if task.status == 2 and not task.file.active:
            # The database commit may have succeeded before object cleanup or the
            # Redis status update. Replaying the unacknowledged event must finish
            # both side effects instead of turning the object into an orphan.
            _remove_rejected_object(object_key)
            raise QuotaExceededTransferEventError(
                "Upload exceeds the document owner's quota"
            )
        if task.status != 0:
            raise PermanentTransferEventError("Upload task is not pending")

        if not file_owners_fit_quota(session, task.file, size):
            task.file.active = False
            task.status = 2
            task.end_time = time.time()
            session.commit()
            _remove_rejected_object(object_key)
            raise QuotaExceededTransferEventError(
                "Upload exceeds the document owner's quota"
            )

        task.file.size = size
        task.file.sha256 = sha256
        task.file.active = True
        task.status = 1
        task.end_time = time.time()
        session.commit()


class TransferCompletionConsumer:
    def __init__(self, settings: TransferSettings, client: redis.Redis | None = None):
        self.settings = settings
        self.client = client or _redis_client()
        self._thread = threading.Thread(
            target=self._run, name="transfer-completion-consumer", daemon=True
        )
        self._stop = threading.Event()

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _ensure_group(self) -> None:
        try:
            self.client.xgroup_create(
                self.settings.stream,
                self.settings.consumer_group,
                id="0",
                mkstream=True,
            )
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def _dead_letter(self, message_id: str, fields: dict[str, str], error: str) -> None:
        payload: dict[str, Any] = dict(fields)
        payload.update({"source_message_id": message_id, "error": error})
        self.client.xadd(f"{self.settings.stream}:dead-letter", payload)

    def _read(self, marker: str, block: int) -> list:
        return self.client.xreadgroup(
            self.settings.consumer_group,
            self.settings.consumer_name,
            {self.settings.stream: marker},
            count=16,
            block=block,
        )

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._ensure_group()
                # A stable consumer name allows a restarted Core to first replay its
                # own unacknowledged messages, then consume new events.
                batches = self._read("0", 1) or self._read(">", 5000)
                for _stream, messages in batches:
                    for message_id, fields in messages:
                        try:
                            apply_completion_event(fields)
                            RedisTransferSessionStore(self.client).client.hset(
                                RedisTransferSessionStore.key(fields["task_id"]),
                                mapping={
                                    key: fields[key]
                                    for key in ("status", "size", "sha256")
                                    if key in fields
                                },
                            )
                        except QuotaExceededTransferEventError as exc:
                            RedisTransferSessionStore(self.client).client.hset(
                                RedisTransferSessionStore.key(fields["task_id"]),
                                mapping={
                                    "status": "failed",
                                    "error": exc.error_code,
                                },
                            )
                            self._dead_letter(message_id, fields, str(exc))
                        except PermanentTransferEventError as exc:
                            self._dead_letter(message_id, fields, str(exc))
                        self.client.xack(
                            self.settings.stream,
                            self.settings.consumer_group,
                            message_id,
                        )
            except (redis.RedisError, OSError):
                logger.exception("Transfer completion consumer is unavailable")
                self._stop.wait(2)
            except Exception:
                # Database and other transient failures deliberately leave the event
                # unacknowledged so it is replayed after recovery.
                logger.exception("Transfer completion event will be retried")
                self._stop.wait(1)


_consumer: TransferCompletionConsumer | None = None
_consumer_lock = threading.Lock()


def start_transfer_completion_consumer() -> TransferCompletionConsumer | None:
    global _consumer
    settings = get_transfer_settings()
    if not settings.enabled:
        return None
    with _consumer_lock:
        if _consumer is None:
            _consumer = TransferCompletionConsumer(settings)
            _consumer.start()
    return _consumer
