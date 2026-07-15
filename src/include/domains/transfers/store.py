from __future__ import annotations

import time
from typing import Any

import redis

from include.config.settings import global_config


class RedisTransferSessionStore:
    def __init__(self, client: redis.Redis | None = None):
        if client is None:
            cfg = global_config["redis"]
            client = redis.Redis(
                host=cfg["host"],
                port=cfg.get("port", 6379),
                password=cfg.get("password", ""),
                db=cfg.get("db", 0),
                decode_responses=True,
            )
        self.client = client

    @staticmethod
    def key(task_id: str) -> str:
        return f"transfer:session:{task_id}"

    def create(self, values: dict[str, Any], ttl_seconds: int) -> None:
        task_id = str(values["task_id"])
        mapping = {key: str(value) for key, value in values.items() if value is not None}
        mapping.setdefault("created_at", str(int(time.time())))
        pipe = self.client.pipeline(transaction=True)
        pipe.hset(self.key(task_id), mapping=mapping)
        pipe.expire(self.key(task_id), ttl_seconds)
        pipe.execute()

    def get(self, task_id: str) -> dict[str, str] | None:
        values = self.client.hgetall(self.key(task_id))
        return values or None
