from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Any

import orjson
from loguru import logger as log

from include.extensions.manager import hookimpl
from include.providers.manager import ProviderManager
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result

logger = log.bind(name="thesis_attack_lab")

FEATURE_ENV = {
    "sqli": "CFMS_VULN_SQLI_ENABLED",
    "rce": "CFMS_VULN_RCE_ENABLED",
    "auth_bypass": "CFMS_VULN_AUTH_BYPASS_ENABLED",
    "path_traversal": "CFMS_VULN_PATH_TRAVERSAL_ENABLED",
    "idor": "CFMS_VULN_IDOR_ENABLED",
}

LAB_USERS: dict[str, dict[str, Any]] = {
    "lab-alice": {
        "lab": True,
        "nickname": "Alice (LAB)",
        "role": "user",
        "honeytoken": False,
    },
    "lab-bob": {
        "lab": True,
        "nickname": "Bob (LAB)",
        "role": "user",
        "honeytoken": False,
    },
    "lab-decoy-admin": {
        "lab": True,
        "nickname": "Administrator Backup (LAB DECOY)",
        "role": "admin-decoy",
        "honeytoken": True,
    },
    # This negative fixture proves the experiment never crosses into real data.
    "prod-root-sentinel": {
        "lab": False,
        "nickname": "NON-LAB SENTINEL",
        "role": "blocked",
        "honeytoken": False,
    },
}

LAB_OBJECTS: dict[str, dict[str, Any]] = {
    "LAB-DOC-ALICE": {
        "lab": True,
        "owner": "lab-alice",
        "content": "Alice's isolated lab note",
        "honeytoken": False,
    },
    "LAB-DOC-BOB": {
        "lab": True,
        "owner": "lab-bob",
        "content": "Bob's isolated lab note",
        "honeytoken": False,
    },
    "LAB-DOC-DECOY": {
        "lab": True,
        "owner": "lab-decoy-admin",
        "content": "THESIS-HONEYTOKEN-IDOR",
        "honeytoken": True,
    },
    "PROD-DOC-SENTINEL": {
        "lab": False,
        "owner": "prod-root-sentinel",
        "content": "NEVER_RETURN_THIS_VALUE",
        "honeytoken": False,
    },
}

VIRTUAL_FILES = {
    "/public/readme.txt": "CFMS thesis attack lab virtual filesystem",
    "/decoys/honeytoken.txt": "THESIS-HONEYTOKEN-PATH-TRAVERSAL",
}

ALLOWED_SQLI_PAYLOADS = frozenset(
    {
        "' or '1'='1",
        "' or 1=1 --",
        "admin' or '1'='1' --",
    }
)
SIMULATED_COMMANDS = {
    "whoami": "lab-sandbox-user",
    "id": "uid=65534(lab-sandbox) gid=65534(lab-sandbox)",
    "list-decoys": "honeytoken.txt\nidor-decoy.json",
    "read-honeytoken": "THESIS-HONEYTOKEN-RCE",
}
ALLOWED_PATH_PROBES = frozenset(
    {
        "readme.txt",
        "../decoys/honeytoken.txt",
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "/etc/passwd",
    }
)

CHAIN_STEPS = {
    "identity_takeover": ("enumerate", "bypass", "idor"),
    "sandbox_breach": ("traverse", "execute"),
}
CHAIN_REQUIREMENTS = {
    "identity_takeover": frozenset({"sqli", "auth_bypass", "idor"}),
    "sandbox_breach": frozenset({"path_traversal", "rce"}),
}
CHAIN_EXERCISES = {
    ("identity_takeover", "enumerate"): {
        "action": "lab_sqli",
        "data": {"query": "' OR '1'='1", "dataset": "LAB_USERS"},
    },
    ("identity_takeover", "bypass"): {
        "action": "lab_auth_bypass",
        "data": {"username": "lab-decoy-admin", "proof": "LAB-BYPASS-DEMO"},
    },
    ("identity_takeover", "idor"): {
        "action": "lab_idor",
        "data": {"object_id": "LAB-DOC-DECOY"},
    },
    ("sandbox_breach", "traverse"): {
        "action": "lab_path_traversal",
        "data": {"path": "../decoys/honeytoken.txt"},
    },
    ("sandbox_breach", "execute"): {
        "action": "lab_rce",
        "data": {"command": "read-honeytoken"},
    },
}

_state_lock = threading.RLock()
_alerts: deque[dict[str, Any]] = deque(maxlen=100)
_chain_progress = {name: 0 for name in CHAIN_STEPS}
_epoch = 1
_alert_sequence = 0


def _env_true(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() in {"1", "true", "yes", "on"}


def _enabled_features() -> set[str]:
    if not _env_true("LAB_MODE"):
        return set()
    return {name for name, env_name in FEATURE_ENV.items() if _env_true(env_name)}


def _feature_enabled(name: str) -> bool:
    return name in _enabled_features()


def _finish(
    handler: ConnectionHandler,
    code: int,
    data: dict[str, Any],
    message: str,
    *,
    target: str | None = None,
) -> Result:
    handler.conclude_request(code, data, message)
    return Result(
        code=code,
        target=target,
        data=data,
        username=handler.username,
    )


def _guard_feature(handler: ConnectionHandler, feature: str) -> Result | None:
    if _feature_enabled(feature):
        return None
    return _finish(
        handler,
        403,
        {"lab": False, "feature": feature},
        "Attack lab feature is disabled",
        target=feature,
    )


def _emit_honeytoken_alert(kind: str, target: str, actor: str | None) -> dict[str, Any]:
    global _alert_sequence
    with _state_lock:
        _alert_sequence += 1
        alert = {
            "alert_id": f"LAB-ALERT-{_epoch}-{_alert_sequence}",
            "kind": kind,
            "target": target,
            "actor": actor or "anonymous",
            "timestamp": time.time(),
        }
        _alerts.append(alert)

    logger.warning("[LAB-HONEYTOKEN] {}", alert)
    try:
        ProviderManager().event_bus.publish(
            "cfms.lab.honeytoken",
            orjson.dumps(alert).decode("utf-8"),
        )
    except Exception as exc:
        # Unit tests and maintenance commands may run before providers exist.
        logger.debug("Honeytoken event bus is unavailable: {}", exc)
    return alert


def _reset_lab_state() -> dict[str, Any]:
    global _alert_sequence, _epoch
    with _state_lock:
        _epoch += 1
        _alert_sequence = 0
        _alerts.clear()
        for chain in _chain_progress:
            _chain_progress[chain] = 0
        return {
            "epoch": _epoch,
            "chain_progress": dict(_chain_progress),
            "alerts": 0,
        }


def _state_snapshot() -> dict[str, Any]:
    with _state_lock:
        return {
            "epoch": _epoch,
            "chain_progress": dict(_chain_progress),
            "alerts": list(_alerts),
        }


def _normalize_virtual_path(probe: str) -> str | None:
    if not probe or probe.startswith(("/", "\\")) or "\\" in probe or "\x00" in probe:
        return None

    parts = ["public"]
    for part in probe.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        if ":" in part:
            return None
        parts.append(part)
    return "/" + "/".join(parts)


def _chain_is_enabled(chain: str) -> bool:
    requirements = CHAIN_REQUIREMENTS.get(chain)
    return requirements is not None and requirements <= _enabled_features()


def _chain_evidence(chain: str, completed_steps: int) -> str:
    return f"LAB-EVIDENCE:{_epoch}:{chain}:{completed_steps}"


class RequestLabSQLiHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 128},
            "dataset": {"const": "LAB_USERS"},
        },
        "required": ["query", "dataset"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _guard_feature(handler, "sqli"):
            return denied

        query = handler.data["query"].strip()
        normalized = query.lower()
        if normalized in ALLOWED_SQLI_PAYLOADS:
            rows = [
                {"username": username, **record}
                for username, record in LAB_USERS.items()
                if record["lab"]
            ]
            alert = _emit_honeytoken_alert("sqli", "lab-decoy-admin", handler.username)
            data = {
                "lab": True,
                "vulnerability": "sqli",
                "triggered": True,
                "dataset": "LAB_USERS",
                "rows": rows,
                "honeytoken": True,
                "alert": alert,
            }
            return _finish(handler, 200, data, "Allowlisted SQLi simulation completed")

        record = LAB_USERS.get(query)
        if record is not None and not record["lab"]:
            return _finish(
                handler,
                403,
                {"lab": True, "blocked_boundary": "non_lab_record"},
                "Non-LAB records are outside the experiment boundary",
                target=query,
            )
        if record is not None:
            rows = [{"username": query, **record}]
        elif any(marker in normalized for marker in ("'", "--", "/*", ";")):
            return _finish(
                handler,
                400,
                {"lab": True, "allowlisted": False},
                "SQLi payload is not allowlisted for this lab",
            )
        else:
            rows = []

        return _finish(
            handler,
            200,
            {
                "lab": True,
                "vulnerability": "sqli",
                "triggered": False,
                "dataset": "LAB_USERS",
                "rows": rows,
                "honeytoken": False,
            },
            "LAB user lookup completed",
        )


class RequestLabRCEHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {"command": {"type": "string", "enum": list(SIMULATED_COMMANDS)}},
        "required": ["command"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _guard_feature(handler, "rce"):
            return denied
        command = handler.data["command"]
        if command not in SIMULATED_COMMANDS:
            return _finish(
                handler,
                400,
                {"lab": True, "allowlisted": False},
                "Command is not in the simulation allowlist",
                target=command,
            )

        alert = None
        if command == "read-honeytoken":
            alert = _emit_honeytoken_alert("rce", command, handler.username)
        data = {
            "lab": True,
            "vulnerability": "rce",
            "execution": "simulated",
            "sandbox": "virtual://cfms-thesis-lab",
            "command": command,
            "stdout": SIMULATED_COMMANDS[command],
            "exit_code": 0,
            "host_process_started": False,
            "honeytoken": alert is not None,
            "alert": alert,
        }
        return _finish(handler, 200, data, "Allowlisted RCE simulation completed")


class RequestLabAuthBypassHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "maxLength": 64},
            "proof": {"const": "LAB-BYPASS-DEMO"},
        },
        "required": ["username", "proof"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _guard_feature(handler, "auth_bypass"):
            return denied
        username = handler.data["username"]
        if handler.data["proof"] != "LAB-BYPASS-DEMO":
            return _finish(handler, 401, {"lab": True}, "Invalid lab bypass proof")

        user = LAB_USERS.get(username)
        if user is None:
            return _finish(handler, 404, {"lab": True}, "LAB account not found")
        if not user["lab"]:
            return _finish(
                handler,
                403,
                {"lab": True, "blocked_boundary": "non_lab_account"},
                "Authentication bypass is restricted to LAB accounts",
                target=username,
            )

        alert = None
        if user["honeytoken"]:
            alert = _emit_honeytoken_alert("auth_bypass", username, handler.username)
        data = {
            "lab": True,
            "vulnerability": "auth_bypass",
            "username": username,
            "simulated_token": f"LAB-SIMULATED:{username}:NOT-A-CORE-TOKEN",
            "usable_for_core_authentication": False,
            "honeytoken": alert is not None,
            "alert": alert,
        }
        return _finish(
            handler,
            200,
            data,
            "LAB-only authentication bypass simulated",
            target=username,
        )


class RequestLabPathTraversalHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 128}},
        "required": ["path"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _guard_feature(handler, "path_traversal"):
            return denied
        probe = handler.data["path"]
        if probe not in ALLOWED_PATH_PROBES:
            return _finish(
                handler,
                400,
                {"lab": True, "allowlisted": False},
                "Path probe is not allowlisted for this lab",
                target=probe,
            )

        resolved = _normalize_virtual_path(probe)
        if resolved is None:
            return _finish(
                handler,
                403,
                {"lab": True, "blocked_boundary": "virtual_sandbox_root"},
                "Path would escape the virtual lab sandbox",
                target=probe,
            )
        content = VIRTUAL_FILES.get(resolved)
        if content is None:
            return _finish(
                handler,
                404,
                {"lab": True, "resolved_path": resolved},
                "Virtual lab file not found",
                target=resolved,
            )

        alert = None
        if resolved == "/decoys/honeytoken.txt":
            alert = _emit_honeytoken_alert("path_traversal", resolved, handler.username)
        data = {
            "lab": True,
            "vulnerability": "path_traversal",
            "sandbox": "virtual://cfms-thesis-lab",
            "resolved_path": resolved,
            "content": content,
            "host_filesystem_accessed": False,
            "honeytoken": alert is not None,
            "alert": alert,
        }
        return _finish(
            handler,
            200,
            data,
            "Virtual sandbox path resolved",
            target=resolved,
        )


class RequestLabIDORHandler(RequestHandler):
    require_auth = True
    schema = {
        "type": "object",
        "properties": {"object_id": {"type": "string", "maxLength": 64}},
        "required": ["object_id"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _guard_feature(handler, "idor"):
            return denied
        actor = handler.username
        if not actor:
            return _finish(
                handler,
                401,
                {"lab": True, "blocked_boundary": "unauthenticated_actor"},
                "IDOR experiment requires an authenticated Core account",
            )

        object_id = handler.data["object_id"]
        obj = LAB_OBJECTS.get(object_id)
        if obj is None:
            return _finish(handler, 404, {"lab": True}, "LAB object not found")
        if not obj["lab"]:
            return _finish(
                handler,
                403,
                {"lab": True, "blocked_boundary": "non_lab_object"},
                "IDOR experiment cannot access non-LAB objects",
                target=object_id,
            )

        alert = None
        if obj["honeytoken"]:
            alert = _emit_honeytoken_alert("idor", object_id, actor)
        data = {
            "lab": True,
            "vulnerability": "idor",
            "object_id": object_id,
            "owner": obj["owner"],
            "content": obj["content"],
            "idor_triggered": obj["owner"] != actor,
            "authorization_check": "intentionally_skipped_for_lab_object",
            "honeytoken": alert is not None,
            "alert": alert,
        }
        return _finish(
            handler,
            200,
            data,
            "LAB object returned with intentionally missing ownership check",
            target=object_id,
        )


class RequestResetLabHandler(RequestHandler):
    schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler) -> Result:
        if not _enabled_features():
            return _finish(handler, 403, {"lab": False}, "Attack lab is disabled")
        state = _reset_lab_state()
        return _finish(
            handler,
            200,
            {
                "lab": True,
                **state,
                "lab_accounts": [name for name, row in LAB_USERS.items() if row["lab"]],
                "lab_objects": [
                    name for name, row in LAB_OBJECTS.items() if row["lab"]
                ],
            },
            "Attack lab state reset",
        )


class RequestLabStatusHandler(RequestHandler):
    schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler) -> Result:
        features = _enabled_features()
        if not features:
            return _finish(handler, 403, {"lab": False}, "Attack lab is disabled")
        return _finish(
            handler,
            200,
            {
                "lab": True,
                "enabled_features": sorted(features),
                "available_chains": [
                    chain for chain in CHAIN_STEPS if _chain_is_enabled(chain)
                ],
                **_state_snapshot(),
            },
            "Attack lab status retrieved",
        )


class RequestLabChainStepHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "chain": {"type": "string", "enum": list(CHAIN_STEPS)},
            "step": {
                "type": "string",
                "enum": sorted(
                    {step for steps in CHAIN_STEPS.values() for step in steps}
                ),
            },
            "evidence": {"type": "string", "maxLength": 128},
        },
        "required": ["chain", "step"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        chain = handler.data["chain"]
        step = handler.data["step"]
        if not _chain_is_enabled(chain):
            return _finish(
                handler,
                403,
                {"lab": True, "chain": chain},
                "Required vulnerability gates for this chain are disabled",
                target=chain,
            )
        steps = CHAIN_STEPS[chain]
        if step not in steps:
            return _finish(
                handler,
                400,
                {"lab": True, "chain": chain},
                "Step does not belong to the selected chain",
                target=chain,
            )

        index = steps.index(step)
        error_data = None
        error_message = None
        with _state_lock:
            progress = _chain_progress[chain]
            if index > progress:
                error_data = {"lab": True, "expected_step": steps[progress]}
                error_message = "Attack chain step is out of order"
            elif index > 0 and handler.data.get("evidence") != _chain_evidence(
                chain, index
            ):
                error_data = {
                    "lab": True,
                    "expected_evidence": _chain_evidence(chain, index),
                }
                error_message = "Previous chain evidence is missing or invalid"
            else:
                replayed = index < progress
                if not replayed:
                    _chain_progress[chain] = index + 1
                evidence = _chain_evidence(chain, index + 1)
                completed = _chain_progress[chain] == len(steps)

        if error_data is not None:
            return _finish(
                handler,
                409,
                error_data,
                error_message or "Attack chain step rejected",
                target=chain,
            )

        alert = None
        if completed and not replayed:
            alert = _emit_honeytoken_alert("attack_chain", chain, handler.username)
        return _finish(
            handler,
            200,
            {
                "lab": True,
                "chain": chain,
                "step": step,
                "step_number": index + 1,
                "completed": completed,
                "replayed": replayed,
                "evidence": evidence,
                "exercise": CHAIN_EXERCISES[(chain, step)],
                "honeytoken": alert is not None,
                "alert": alert,
            },
            "Attack chain step completed",
            target=chain,
        )


@hookimpl
def ext_register_handlers() -> dict[str, type[RequestHandler]]:
    features = _enabled_features()
    handlers: dict[str, type[RequestHandler]] = {}
    feature_handlers = {
        "sqli": ("lab_sqli", RequestLabSQLiHandler),
        "rce": ("lab_rce", RequestLabRCEHandler),
        "auth_bypass": ("lab_auth_bypass", RequestLabAuthBypassHandler),
        "path_traversal": ("lab_path_traversal", RequestLabPathTraversalHandler),
        "idor": ("lab_idor", RequestLabIDORHandler),
    }
    for feature in features:
        action, handler = feature_handlers[feature]
        handlers[action] = handler

    if features:
        handlers["reset_lab"] = RequestResetLabHandler
        handlers["lab_status"] = RequestLabStatusHandler
    if any(requirements <= features for requirements in CHAIN_REQUIREMENTS.values()):
        handlers["lab_chain_step"] = RequestLabChainStepHandler
    return handlers


@hookimpl
def ext_register_extension_flags() -> set[str]:
    features = _enabled_features()
    if not features:
        return set()
    flags = {"thesis_attack_lab"}
    flags.update(f"lab_vuln_{feature}" for feature in features)
    flags.update(
        f"lab_chain_{chain}"
        for chain, requirements in CHAIN_REQUIREMENTS.items()
        if requirements <= features
    )
    return flags
