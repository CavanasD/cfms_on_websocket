from __future__ import annotations

import os
import socket
from dataclasses import dataclass

from include.config.settings import global_config


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class TransferSettings:
    enabled: bool
    base_url: str
    private_key_file: str
    ticket_ttl_seconds: int
    session_ttl_seconds: int
    chunk_size: int
    max_upload_size: int
    stream: str
    consumer_group: str
    consumer_name: str


def get_transfer_settings() -> TransferSettings:
    cfg = global_config.get("transfer", {})
    return TransferSettings(
        enabled=_env_bool(
            "CFMS_HTTP_TRANSFER_ENABLED", bool(cfg.get("enabled", False))
        ),
        base_url=os.getenv(
            "CFMS_TRANSFER_BASE_URL", str(cfg.get("base_url", "http://localhost:8082"))
        ).rstrip("/"),
        private_key_file=os.getenv(
            "CFMS_TRANSFER_PRIVATE_KEY_FILE",
            str(cfg.get("private_key_file", "./content/transfer-private.pem")),
        ),
        ticket_ttl_seconds=int(
            os.getenv(
                "CFMS_TRANSFER_TICKET_TTL_SECONDS",
                str(cfg.get("ticket_ttl_seconds", 900)),
            )
        ),
        session_ttl_seconds=int(
            os.getenv(
                "CFMS_TRANSFER_SESSION_TTL_SECONDS",
                str(cfg.get("session_ttl_seconds", 86400)),
            )
        ),
        chunk_size=int(
            os.getenv("CFMS_TRANSFER_CHUNK_SIZE", str(cfg.get("chunk_size", 8388608)))
        ),
        max_upload_size=int(
            os.getenv(
                "CFMS_TRANSFER_MAX_UPLOAD_SIZE",
                str(cfg.get("max_upload_size", 10737418240)),
            )
        ),
        stream=os.getenv(
            "CFMS_TRANSFER_COMPLETION_STREAM",
            str(cfg.get("completion_stream", "transfer:completed")),
        ),
        consumer_group=os.getenv(
            "CFMS_TRANSFER_CONSUMER_GROUP",
            str(cfg.get("consumer_group", "drive-core")),
        ),
        consumer_name=os.getenv(
            "CFMS_TRANSFER_CONSUMER_NAME",
            str(cfg.get("consumer_name", f"drive-core-{socket.gethostname()}")),
        ),
    )
