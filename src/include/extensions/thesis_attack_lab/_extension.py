from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Any, ClassVar

import orjson
from loguru import logger as log

from include.database.models.identity import User
from include.database.session import Session
from include.extensions.manager import hookimpl
from include.providers.manager import ProviderManager
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import Result
from include.extensions.thesis_request import ThesisRequestHandler as RequestHandler

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
EXERCISES = {
    step: exercise for (_chain, step), exercise in CHAIN_EXERCISES.items()
}
EXERCISE_FEATURES = {
    "enumerate": "sqli",
    "bypass": "auth_bypass",
    "idor": "idor",
    "traverse": "path_traversal",
    "execute": "rce",
}
CHAIN_REQUIREMENTS = {
    chain: frozenset(EXERCISE_FEATURES[step] for step in steps)
    for chain, steps in CHAIN_STEPS.items()
}

_state_lock = threading.RLock()
_alerts: deque[dict[str, Any]] = deque(maxlen=100)
_chain_progress = {name: 0 for name in CHAIN_STEPS}
_custom_chains: dict[str, tuple[str, tuple[str, ...]]] = {}
_runtime_feature_overrides: dict[str, bool] = {}
_epoch = 1
_alert_sequence = 0


def _env_true(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() in {"1", "true", "yes", "on"}


def _enabled_features() -> set[str]:
    if not _env_true("LAB_MODE"):
        return set()
    with _state_lock:
        return {
            name
            for name, env_name in FEATURE_ENV.items()
            if _runtime_feature_overrides.get(name, _env_true(env_name))
        }


def _feature_enabled(name: str) -> bool:
    return name in _enabled_features()


def _lab_mode_enabled() -> bool:
    return _env_true("LAB_MODE")


def _set_feature_enabled(feature: str, enabled: bool) -> bool:
    if feature not in FEATURE_ENV or (enabled and not _lab_mode_enabled()):
        return False
    with _state_lock:
        _runtime_feature_overrides[feature] = enabled
    logger.warning(f"[LAB VULN SWITCH] {feature} -> {enabled}")
    return True


def _chain_definition(chain: str) -> tuple[str, tuple[str, ...]] | None:
    if chain in CHAIN_STEPS:
        return chain.replace("_", " ").title(), CHAIN_STEPS[chain]
    with _state_lock:
        return _custom_chains.get(chain)


def _chain_requirements(chain: str) -> frozenset[str] | None:
    definition = _chain_definition(chain)
    if definition is None:
        return None
    return frozenset(EXERCISE_FEATURES[step] for step in definition[1])


def _chain_snapshot() -> list[dict[str, Any]]:
    with _state_lock:
        definitions = {
            **{
                name: (name.replace("_", " ").title(), steps)
                for name, steps in CHAIN_STEPS.items()
            },
            **_custom_chains,
        }
        enabled_features = _enabled_features()
        return [
            {
                "id": chain,
                "title": title,
                "steps": list(steps),
                "required_features": sorted(
                    EXERCISE_FEATURES[step] for step in steps
                ),
                "available": {EXERCISE_FEATURES[step] for step in steps}
                <= enabled_features,
                "custom": chain in _custom_chains,
            }
            for chain, (title, steps) in definitions.items()
        ]


def _is_sysop(username: str | None) -> bool:
    if not username:
        return False
    with Session() as session:
        user = session.get(User, username)
        return user is not None and "sysop" in user.all_groups


def _require_lab_admin(handler: ConnectionHandler) -> Result | None:
    if _is_sysop(handler.username):
        return None
    return _finish(
        handler,
        403,
        {"lab": _lab_mode_enabled(), "required_role": "sysop"},
        "LAB configuration requires the sysop role",
    )


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
    requirements = _chain_requirements(chain)
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
        if not _lab_mode_enabled():
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
        if not _lab_mode_enabled():
            return _finish(handler, 403, {"lab": False}, "Attack lab is disabled")
        features = _enabled_features()
        return _finish(
            handler,
            200,
            {
                "lab": True,
                "enabled_features": sorted(features),
                "available_chains": [
                    chain["id"] for chain in _chain_snapshot() if chain["available"]
                ],
                "chains": _chain_snapshot(),
                "available_exercises": sorted(EXERCISES),
                **_state_snapshot(),
            },
            "Attack lab status retrieved",
        )


class RequestLabSetVulnerabilityHandler(RequestHandler):
    require_auth = True
    schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "feature": {"type": "string", "enum": sorted(FEATURE_ENV)},
            "enabled": {"type": "boolean"},
        },
        "required": ["feature", "enabled"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _require_lab_admin(handler):
            return denied
        feature = handler.data["feature"]
        enabled = handler.data["enabled"]
        if not _set_feature_enabled(feature, enabled):
            return _finish(
                handler,
                403,
                {"lab": False, "feature": feature, "enabled": False},
                "LAB_MODE is disabled",
                target=feature,
            )
        return _finish(
            handler,
            200,
            {
                "lab": True,
                "feature": feature,
                "enabled": enabled,
                "enabled_features": sorted(_enabled_features()),
            },
            "LAB vulnerability switch updated",
            target=feature,
        )


class RequestLabConfigureChainHandler(RequestHandler):
    require_auth = True
    schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "chain": {
                "type": "string",
                "pattern": "^custom-[a-z][a-z0-9_-]{0,39}$",
            },
            "title": {"type": "string", "minLength": 1, "maxLength": 80},
            "steps": {
                "type": "array",
                "minItems": 1,
                "maxItems": 5,
                "items": {"type": "string", "enum": sorted(EXERCISES)},
            },
        },
        "required": ["chain", "title", "steps"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result:
        if denied := _require_lab_admin(handler):
            return denied
        if not _lab_mode_enabled():
            return _finish(handler, 403, {"lab": False}, "Attack lab is disabled")

        chain = handler.data["chain"]
        title = handler.data["title"].strip()
        steps = tuple(handler.data["steps"])
        if not title:
            return _finish(
                handler,
                400,
                {"lab": True, "chain": chain},
                "Teaching chain title cannot be blank",
                target=chain,
            )
        if len(set(steps)) != len(steps):
            return _finish(
                handler,
                400,
                {"lab": True, "chain": chain},
                "An exercise may appear only once in a chain",
                target=chain,
            )

        requirements = frozenset(EXERCISE_FEATURES[step] for step in steps)
        missing = sorted(requirements - _enabled_features())
        if missing:
            return _finish(
                handler,
                409,
                {"lab": True, "chain": chain, "missing_features": missing},
                "Enable every required vulnerability before publishing a chain",
                target=chain,
            )

        with _state_lock:
            _custom_chains[chain] = (title, steps)
            _chain_progress[chain] = 0
        return _finish(
            handler,
            200,
            {
                "lab": True,
                "chain": chain,
                "title": title,
                "steps": list(steps),
                "required_features": sorted(requirements),
            },
            "Custom teaching chain published",
            target=chain,
        )


class RequestLabChainStepHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "chain": {"type": "string", "minLength": 1, "maxLength": 47},
            "step": {"type": "string", "minLength": 1, "maxLength": 40},
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
        definition = _chain_definition(chain)
        if definition is None:
            return _finish(
                handler,
                404,
                {"lab": True, "chain": chain},
                "Teaching chain was not found",
                target=chain,
            )
        _title, steps = definition
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
            progress = _chain_progress.setdefault(chain, 0)
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
                "exercise": EXERCISES[step],
                "honeytoken": alert is not None,
                "alert": alert,
            },
            "Attack chain step completed",
            target=chain,
        )


@hookimpl
def ext_register_handlers() -> dict[str, type[RequestHandler]]:
    if not _lab_mode_enabled():
        return {}
    handlers: dict[str, type[RequestHandler]] = {
        "reset_lab": RequestResetLabHandler,
        "lab_status": RequestLabStatusHandler,
        "lab_set_vulnerability": RequestLabSetVulnerabilityHandler,
        "lab_configure_chain": RequestLabConfigureChainHandler,
        "lab_chain_step": RequestLabChainStepHandler,
    }
    feature_handlers = {
        "sqli": ("lab_sqli", RequestLabSQLiHandler),
        "rce": ("lab_rce", RequestLabRCEHandler),
        "auth_bypass": ("lab_auth_bypass", RequestLabAuthBypassHandler),
        "path_traversal": ("lab_path_traversal", RequestLabPathTraversalHandler),
        "idor": ("lab_idor", RequestLabIDORHandler),
    }
    for feature in FEATURE_ENV:
        action, handler = feature_handlers[feature]
        handlers[action] = handler
    return handlers


@hookimpl
def ext_register_extension_flags() -> set[str]:
    if not _lab_mode_enabled():
        return set()
    features = _enabled_features()
    flags = {"thesis_attack_lab"}
    flags.update(f"lab_vuln_{feature}" for feature in features)
    flags.update(
        f"lab_chain_{chain['id']}"
        for chain in _chain_snapshot()
        if chain["available"]
    )
    return flags
