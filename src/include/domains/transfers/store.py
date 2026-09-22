from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import redis

from include.config.settings import global_config


class TransferSessionConflictError(ValueError):
    """Raised when a task ID is reused with different authorization metadata."""


@dataclass(frozen=True)
class TransferSessionReservation:
    values: dict[str, str]
    created: bool
    ttl_seconds: int


_CREATE_OR_REUSE_SCRIPT = """
local key = KEYS[1]
local cursor = 1
local requested_ttl = tonumber(ARGV[cursor])
cursor = cursor + 1
local immutable_count = tonumber(ARGV[cursor])
cursor = cursor + 1
local exists = redis.call('EXISTS', key) == 1

for _ = 1, immutable_count do
    local field = ARGV[cursor]
    local expected_present = ARGV[cursor + 1] == '1'
    local expected_value = ARGV[cursor + 2]
    cursor = cursor + 3
    if exists then
        local current_value = redis.call('HGET', key, field)
        if (expected_present and current_value ~= expected_value)
            or (not expected_present and current_value ~= false) then
            return {-1, field}
        end
    end
end

local mapping_count = tonumber(ARGV[cursor])
cursor = cursor + 1
if not exists then
    for _ = 1, mapping_count do
        redis.call('HSET', key, ARGV[cursor], ARGV[cursor + 1])
        cursor = cursor + 2
    end
    redis.call('EXPIRE', key, requested_ttl)
end

local result = {exists and 0 or 1, redis.call('TTL', key)}
local stored = redis.call('HGETALL', key)
for index = 1, #stored do
    table.insert(result, stored[index])
end
return result
"""


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
        mapping = {
            key: str(value) for key, value in values.items() if value is not None
        }
        mapping.setdefault("created_at", str(int(time.time())))
        pipe = self.client.pipeline(transaction=True)
        pipe.hset(self.key(task_id), mapping=mapping)
        pipe.expire(self.key(task_id), ttl_seconds)
        pipe.execute()

    def create_or_reuse(
        self,
        values: dict[str, Any],
        ttl_seconds: int,
        *,
        immutable_fields: tuple[str, ...],
    ) -> TransferSessionReservation:
        """Atomically create a session or reuse its resume state.

        Existing sessions keep their current offset, status, expiry and other
        mutable fields. A caller cannot change authorization metadata by
        retrying the same task ID.
        """
        task_id = str(values["task_id"])
        mapping = {
            key: str(value) for key, value in values.items() if value is not None
        }
        mapping.setdefault("created_at", str(int(time.time())))

        arguments: list[str | int] = [ttl_seconds, len(immutable_fields)]
        for field in immutable_fields:
            value = values.get(field)
            arguments.extend(
                (field, 0 if value is None else 1, "" if value is None else str(value))
            )
        arguments.append(len(mapping))
        for field, value in mapping.items():
            arguments.extend((field, value))

        raw = self.client.eval(
            _CREATE_OR_REUSE_SCRIPT,
            1,
            self.key(task_id),
            *arguments,
        )
        if not raw or int(raw[0]) == -1:
            field = str(raw[1]) if raw and len(raw) > 1 else "unknown"
            raise TransferSessionConflictError(
                f"Transfer session metadata conflicts at {field}"
            )

        stored = {
            str(raw[index]): str(raw[index + 1]) for index in range(2, len(raw), 2)
        }
        return TransferSessionReservation(
            values=stored,
            created=int(raw[0]) == 1,
            ttl_seconds=int(raw[1]),
        )

    def get(self, task_id: str) -> dict[str, str] | None:
        values = self.client.hgetall(self.key(task_id))
        return values or None
