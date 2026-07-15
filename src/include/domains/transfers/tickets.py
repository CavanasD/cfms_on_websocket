from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any, Literal

import jwt

from include.domains.transfers.settings import TransferSettings

TransferOperation = Literal["upload", "download"]


def issue_transfer_ticket(
    settings: TransferSettings,
    *,
    task_id: str,
    username: str,
    operation: TransferOperation,
    object_key: str,
    max_size: int,
) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + settings.ticket_ttl_seconds
    private_key = Path(settings.private_key_file).read_text(encoding="utf-8")
    payload: dict[str, Any] = {
        "task_id": task_id,
        "sub": username,
        "username": username,
        "operation": operation,
        "object_key": object_key,
        "max_size": max_size,
        "jti": secrets.token_urlsafe(24),
        "iss": settings.issuer,
        "aud": settings.audience,
        "iat": now,
        "exp": expires_at,
    }
    return jwt.encode(payload, private_key, algorithm="RS256"), expires_at
