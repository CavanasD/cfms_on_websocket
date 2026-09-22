from __future__ import annotations

import os
import re
import threading
import time
from collections import deque
from typing import Any, ClassVar

import orjson
from loguru import logger as log

from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS, ROOT_DIRECTORY_ID
from include.config.paths import EXTENSION_ROOT
from include.config.settings import global_config
from include.database.models.identity import User
from include.database.session import Session, engine
from include.domains.identity.tokens import Token
from include.extensions.manager import hookimpl, hot_reload_extension
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
    # 教学关卡 · 链 3：热插件上传 → 覆写 → RCE
    "hot_plugin": "CFMS_VULN_HOT_PLUGIN_ENABLED",
    # 教学关卡 · 链 4：业务面 ORDER BY 注入（文件列表「按时间排序」）
    "listing_sort": "CFMS_VULN_LISTING_SORT_ENABLED",
    # 教学关卡 · 第 5：JWT 弱 HMAC 密钥（secret123），伪造 admin 身份
    "jwt_weak_secret": "CFMS_VULN_JWT_WEAK_SECRET_ENABLED",
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
# 教学关卡 · 链 2 的 proof 常量。它写在源码里、可被任意学生读到，
# 因此"持有 proof"不构成任何身份证明 —— 这正是该实验点的缺陷本意。
LAB_BYPASS_PROOF = "LAB-BYPASS-DEMO"

# 教学关卡 · 链 3 的插件落点。与 include/config/paths.py 的 EXTENSION_ROOT
# 保持一致：扩展加载器会从该目录发现并 import 模块。
LAB_HOT_PLUGIN_ROOT = EXTENSION_ROOT


def _drop_bytecode_cache(target: str) -> None:
    """Delete stale ``__pycache__`` entries for a just-written plugin file.

    ``importlib`` validates cached bytecode against the source file's mtime, and
    that timestamp only has one-second resolution. Two writes to the same plugin
    inside one second would therefore be treated as "unchanged" and the second
    payload would never be compiled -- the teaching step would silently fail.
    Removing the cache on write keeps "overwrite -> reload -> new code runs"
    honest and repeatable.

    Args:
        target: Absolute path of the file that was just written.
    """
    directory = os.path.dirname(os.path.abspath(target)) or "."
    cache = os.path.join(directory, "__pycache__")
    if not os.path.isdir(cache):
        return
    stem = os.path.splitext(os.path.basename(target))[0]
    try:
        for entry in os.listdir(cache):
            # Only drop bytecode that belongs to this module, leave siblings alone.
            if entry.endswith(".pyc") and entry.split(".", 1)[0] == stem:
                try:
                    os.remove(os.path.join(cache, entry))
                except OSError:
                    log.debug(f"[LAB HOT PLUGIN] unable to drop bytecode {entry}")
    except OSError:
        log.debug(f"[LAB HOT PLUGIN] unable to scan bytecode cache {cache}")


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
    # 教学关卡 · 三条主线，与 require.txt 的承载点一一对应。
    # 第 1：业务面 SQL 注入（文件列表「按时间排序」）
    "sqli_chain": ("sqli_probe", "sqli_inject", "sqli_exfil"),
    # 第 2：JWT 弱 HMAC 密钥（secret123）→ 伪造 admin 身份
    "jwt_admin_chain": ("jwt_forge", "jwt_admin_login"),
    # 第 3：业务面 ORDER BY 注入 → 文件列表「按时间排序」的真实业务接口
    "listing_orderby_chain": ("listing_probe", "listing_inject", "listing_exfil"),
}
CHAIN_EXERCISES = {
    # ── 第 1：业务面 SQL 注入 ──────────────────────────────────────────
    # 走的是「真实业务接口」list_directory，不是 lab_* 桩动作。
    # 第 1 步：确认参数可控（合法值，先摸清形状）
    ("sqli_chain", "sqli_probe"): {
        "action": "list_directory",
        "data": {"sort_by": "created_time", "sort_order": "desc"},
    },
    # 第 2 步：确认注入位置（ORDER BY 可拼接子查询）
    ("sqli_chain", "sqli_inject"): {
        "action": "list_directory",
        "data": {"sort_by": "created_time,(SELECT 1)", "sort_order": "desc"},
    },
    # 第 3 步：报错带外，读出数据库版本 / 结构
    ("sqli_chain", "sqli_exfil"): {
        "action": "list_directory",
        "data": {
            "sort_by": "extractvalue(1,concat(0x7e,version()))",
            "sort_order": "desc",
        },
    },
    # ── 第 2：JWT 弱 HMAC 密钥 ────────────────────────────────────────
    # 第 1 步：用固定弱口令 secret123 自签一个 admin token（无需其密码）
    ("jwt_admin_chain", "jwt_forge"): {
        "action": "get_user_info",
        "data": {"username": "admin"},
    },
    # 第 2 步：拿该 token 走业务接口，验证已被认定为 admin
    ("jwt_admin_chain", "jwt_admin_login"): {
        "action": "get_user_info",
        "data": {"username": "admin"},
    },
    # ── 第 3：业务面 ORDER BY 注入 ─────────────────────────────────────
    # 注意：走的是「真实业务接口」list_directory，不是 lab_* 桩动作。
    # 普通用户登录后，文件列表点「按时间排序」触发的就是这条链。
    # 第 1 步：确认排序参数可控（合法值，先摸清形状）
    ("listing_orderby_chain", "listing_probe"): {
        "action": "list_directory",
        "data": {"sort_by": "created_time", "sort_order": "desc"},
    },
    # 第 2 步：确认注入位置，ORDER BY 可拼接子查询
    ("listing_orderby_chain", "listing_inject"): {
        "action": "list_directory",
        "data": {"sort_by": "created_time,(SELECT 1)", "sort_order": "desc"},
    },
    # 第 3 步：报错带外，读取数据库版本
    ("listing_orderby_chain", "listing_exfil"): {
        "action": "list_directory",
        "data": {
            "sort_by": "extractvalue(1,concat(0x7e,version()))",
            "sort_order": "desc",
        },
    },
}
EXERCISES = {
    step: exercise for (_chain, step), exercise in CHAIN_EXERCISES.items()
}
EXERCISE_FEATURES = {
    # 第 1：业务面 SQL 注入
    "sqli_probe": "sqli",
    "sqli_inject": "sqli",
    "sqli_exfil": "sqli",
    # 第 2：JWT 弱 HMAC 密钥（真实开关 CFMS_VULN_JWT_WEAK_SECRET_ENABLED）
    "jwt_forge": "jwt_weak_secret",
    "jwt_admin_login": "jwt_weak_secret",
    # 第 3：业务面 ORDER BY 注入
    "listing_probe": "listing_sort",
    "listing_inject": "listing_sort",
    "listing_exfil": "listing_sort",
}

CHAIN_REQUIREMENTS = {
    chain: frozenset(EXERCISE_FEATURES[step] for step in steps)
    for chain, steps in CHAIN_STEPS.items()
}

# 已下线的教学链：后端不再存在对应漏洞点，面板以绿色「已修复」呈现。
# 保留条目是为了让学习者看到「这里曾经有一个洞，现在关掉了」。
FIXED_CHAINS: dict[str, dict[str, str]] = {
    "identity_takeover": {
        "title": "Identity Takeover",
        "status": "fixed",
        "color": "green",
        "reason": "依赖的 lab_* 桩动作已下线，后端不存在该漏洞点",
    },
    "sandbox_breach": {
        "title": "Sandbox Breach",
        "status": "fixed",
        "color": "green",
        "reason": "依赖的 lab_* 桩动作已下线，后端不存在该漏洞点",
    },
    "hot_plugin_chain": {
        "title": "Hot Plugin Chain",
        "status": "fixed",
        "color": "green",
        "reason": "依赖的 lab_* 桩动作已下线，后端不存在该漏洞点",
    },
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


def _lab_simulate(mode_env: str) -> bool:
    """Judge whether a handler runs its simulated (safe) branch.

    Each vulnerability handler accepts a ``*_MODE`` environment variable:

      * ``simulate`` — only touch in-memory fixtures / virtual files;
      * anything else (default ``real``) — run the genuine vulnerable path.

    This gives the instructor a per-feature rollback switch that is independent
    from the three-level on/off gate, so a live session can be downgraded to the
    harmless demo without restarting the service.
    """
    return os.getenv(mode_env, "real").strip().lower() in {
        "simulate",
        "simulated",
        "safe",
        "sandbox",
    }


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
    """面板用的链路快照。

    包含三类：
      · 内置活跃链（CHAIN_STEPS）——真实业务面，可开关；
      · 自定义链（_custom_chains）；
      · 已下线链（FIXED_CHAINS）——后端漏洞点已移除，
        以 status=fixed / color=green 呈现，available 恒为 False。
    """
    with _state_lock:
        definitions = {
            **{
                name: (name.replace("_", " ").title(), steps)
                for name, steps in CHAIN_STEPS.items()
            },
            **_custom_chains,
        }
        enabled_features = _enabled_features()
        snapshot: list[dict[str, Any]] = [
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
                "status": "active",
                "color": "blue",
                "fixed_reason": None,
            }
            for chain, (title, steps) in definitions.items()
        ]

        # 已下线链：漏洞点不存在了，永远不可用，以绿色「已修复」标记。
        for chain, meta in FIXED_CHAINS.items():
            if chain in definitions:
                continue
            snapshot.append(
                {
                    "id": chain,
                    "title": meta.get("title") or chain.replace("_", " ").title(),
                    "steps": [],
                    "required_features": [],
                    "available": False,
                    "custom": False,
                    "status": meta.get("status", "fixed"),
                    "color": meta.get("color", "green"),
                    "fixed_reason": meta.get("reason"),
                }
            )
        return snapshot



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


FLAG_PATTERN = re.compile(r"THESIS\{[^}]*\}?")


def _extract_flag(text: str | None) -> str | None:
    """从数据库报错回显里抠出 flag。

    报错带外读 flag 时，MySQL 会把读取结果嵌进错误串，形如::

        XPATH syntax error: '~THESIS{order_by_identifier_injection}'

    这里只做"取证"用途：不影响注入本身，仅在回显里出现 flag 时把它标记出来。
    允许右花括号缺失，因为 ``extractvalue`` 的错误串有 32 字节上限，
    长 flag 会被截断（例如 ``'~THESIS{order_by_identifier_inje'``）。
    """
    if not text:
        return None
    match = FLAG_PATTERN.search(text)
    return match.group(0) if match else None


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
class RequestLabListDirectoryHandler(RequestHandler):
    """教学关卡 · 链 4：业务面 ORDER BY 注入（文件列表「按时间排序」）。

    与链 1 的区别：链 1 暴露的是一个专门的 ``lab_sqli`` 教学动作，学生需要先知道
    这个动作名才能打；本链走的是**真实业务接口** —— 普通用户登录网盘后在文件列表
    把排序切成「时间」，前端发出的就是这个 ``list_directory`` 请求。也就是说注入点
    长在正常功能里，不需要任何"教学专用"知识就能碰到。

    本 handler 通过扩展注册表顶替内建的 ``list_directory``（见 main.py 的
    ``available_functions.update(handler_dict)``），因此业务层代码零改动。

    —— 开关语义 ——
    ``CFMS_VULN_LISTING_SORT_ENABLED=false``（默认）：
        排序字段走白名单映射，未知值兜底 ``created_time``。与内建 handler 等价、安全。
    ``CFMS_VULN_LISTING_SORT_ENABLED=true``：
        ``sort_by`` 原样拼入 ``ORDER BY``，构成可注入点；数据库报错原样回显。

    权限：``require_auth = True``，但**不限制角色** —— 任意登录用户（含刚注册的普通
    用户）都能触发，对应"普通用户即可测试"的靶场形态。
    """

    require_auth = True
    rate_limit_cost = 3

    schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": ["string", "null"]},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 200},
            "cursor": {"type": ["string", "null"]},
            # 教学扩展：服务端排序参数。关闭开关时被白名单约束，开启时被拼接。
            "sort_by": {"type": "string", "maxLength": 256},
            "sort_order": {"type": "string", "maxLength": 8},
        },
        "additionalProperties": True,
    }

    # 关闭开关时允许的排序字段 —— 与前端下拉一一对应。
    # 值必须是本查询中真实存在的列/别名，否则白名单自己就会报错。
    SAFE_SORT_COLUMNS = {
        "created_time": "created_time",
        "last_modified": "created_time",  # 目录没有独立修改时间，退化为创建时间
        "size": "created_time",           # 同上，列在文档侧，这里退化为创建时间
        "title": "n.name",
        "name": "n.name",
    }

    def _safe_sort_expression(self, sort_by: str) -> str:
        """白名单映射：未知字段一律兜底 created_time（与内建 handler 等价的安全行为）。"""
        return self.SAFE_SORT_COLUMNS.get(sort_by, "created_time")

    def handle(self, handler: ConnectionHandler) -> Result:
        # 开关关闭时本 handler 依然注册（用于顶替），但必须走安全路径。
        injectable = _feature_enabled("listing_sort")

        folder_id = handler.data.get("folder_id") or ROOT_DIRECTORY_ID
        raw_sort_by = str(handler.data.get("sort_by") or "created_time")
        raw_sort_order = str(handler.data.get("sort_order") or "desc").strip().lower()
        sort_order = "DESC" if raw_sort_order == "desc" else "ASC"

        if injectable:
            # 教学点①：sort_by 未做白名单校验，直接拼入 ORDER BY —— 注入点在此。
            #
            # 但要区分两种情况，否则正常用户会被自己前端发的值打挂：
            #   · 已知的合法排序键（前端下拉框那几个）→ 走白名单映射，
            #     避免撞上不存在的列（例如 nodes.title / nodes.size）而 500；
            #   · 其它任何值 → 原样拼入 ORDER BY，注入点保持可用。
            # 这样"正常业务可用"与"注入可打"同时成立。
            if raw_sort_by in self.SAFE_SORT_COLUMNS:
                order_clause = f"{self.SAFE_SORT_COLUMNS[raw_sort_by]} {sort_order}"
                order_source = "whitelist"
            else:
                order_clause = f"{raw_sort_by} {sort_order}"
                order_source = "raw"
        else:
            order_clause = f"{self._safe_sort_expression(raw_sort_by)} {sort_order}"
            order_source = "whitelist"

        # 只有真正走了原始拼接（order_source == "raw"）时，游标才不可用；
        # 已知合法键即使开关开着也是稳定表达式，游标照常支持。
        _cursor = None if order_source == "raw" else handler.data.get("cursor")

        from include.database.models.documents import EntityStatus, Folder
        from include.database.models.identity import User

        with Session() as session:
            user = session.get(User, handler.username)
            if user is None:
                return _finish(handler, 401, {"lab": True}, "Unknown user", target=folder_id)

            folder = session.query(Folder).filter(Folder.id == folder_id).first()
            if folder is None:
                return _finish(handler, 404, {"lab": True}, "Directory not found", target=folder_id)

            # 排序表达式直接进入 ORDER BY。用 exec_driver_sql 执行，使注入生效，
            # 且数据库错误能原样捕获后回显（教学点②：报错带外）。
            #
            # 真实业务语义：列出一个目录下的子项，按时间/名称排序。
            # nodes 表本身没有 created_time（它在 folders / documents 子表上），
            # 所以要 LEFT JOIN 两个子表 —— 这也让"按时间排序"是一个真实存在的需求。
            # 注意：mysql-connector 的 paramstyle 是 pyformat，占位符必须写成 %s，
            # 不能用 SQLAlchemy 风格的 :pid（exec_driver_sql 不做 :name -> %(name)s 翻译，
            # 冒号会原样发给 MySQL 直接报 1064）。改为位置参数 %s，按顺序传值。
            sql = (
                "SELECT n.id, n.name, n.type, "
                "COALESCE(f.created_time, d.created_time) AS created_time "
                "FROM nodes n "
                "LEFT JOIN folders f ON f.id = n.id "
                "LEFT JOIN documents d ON d.id = n.id "
                "WHERE n.parent_id = %s "
                f"AND n.status != {EntityStatus.DELETED.value} "
                f"ORDER BY {order_clause} LIMIT 200"
            )
            # 占位符已在上面写成 %s，安全路径下 folder_id 由位置参数绑定。
            try:
                result = session.connection().exec_driver_sql(sql, (folder_id,))
                columns = list(result.keys())
                rows = [dict(zip(columns, row)) for row in result.fetchall()]
            except Exception as exc:  # noqa: BLE001 - 教学点：数据库报错原文回显
                # 教学关卡 · flag 判定：MySQL 报错带外时，flag 会以
                # ``XPATH syntax error: '~THESIS{...}'`` 的形态原样回带。
                # 从回显里把 flag 抠出来，作为"通关凭证"挂到响应上。
                # 注意：extractvalue/updatexml 的错误串有 32 字节上限，
                # 超长 flag 需要 substr() 分段读取 —— 这本身就是一个教学点。
                raw_error = str(exc)
                flag_found = _extract_flag(raw_error)
                alert = _emit_honeytoken_alert("listing_sort", raw_sort_by, handler.username)
                if flag_found:
                    # 命中 flag 属于"得分事件"，单独再发一条蜜罐告警，便于蓝方
                    # 在告警面把"探测"和"拿分"区分开。
                    alert = _emit_honeytoken_alert(
                        "listing_flag", flag_found, handler.username
                    )
                return _finish(
                    handler,
                    500,
                    {
                        "lab": True,
                        "vulnerability": "listing_sort",
                        "execution": "real",
                        "injectable": order_source == "raw",
                        "order_source": order_source,
                        "sort_by": raw_sort_by,
                        "sql": sql,
                        "db_error": raw_error,
                        "db_error_type": type(exc).__name__,
                        "flag_found": flag_found is not None,
                        "flag": flag_found,
                        # 教学提示：报错回显上限 32 字节，长 flag 要分段读
                        "flag_truncated": (
                            flag_found is not None and len(flag_found) >= 30
                        ),
                        "alert": alert,
                    },
                    "LAB listing sort: database error echoed verbatim",
                    target=raw_sort_by,
                )

        if injectable and raw_sort_by not in self.SAFE_SORT_COLUMNS:
            alert = _emit_honeytoken_alert("listing_sort", raw_sort_by, handler.username)
        else:
            alert = None

        # 关键：必须保持内建 handler 的响应契约 {folders, documents, parent_id}，
        # 否则前端文件列表（App.vue 读 response.data.folders / .documents）会直接崩。
        # 教学诊断信息挂在同一 data 里，作为额外字段返回。
        folders = [
            {"id": r["id"], "name": r["name"], "created_time": r.get("created_time")}
            for r in rows
            if r.get("type") == "directory"
        ]
        documents = [
            {"id": r["id"], "title": r["name"], "name": r["name"],
             "created_time": r.get("created_time")}
            for r in rows
            if r.get("type") != "directory"
        ]

        return _finish(
            handler,
            200,
            {
                "folders": folders,
                "documents": documents,
                "parent_id": None,
                "cursor": None,
                # —— 教学诊断（仅实验模式可见，不影响正常功能）——
                "lab": True,
                "vulnerability": "listing_sort",
                "execution": "real",
                "injectable": injectable,
                "order_source": order_source,
                "sort_by": raw_sort_by,
                "sort_order": raw_sort_order,
                "sql": sql,
                "count": len(rows),
                "alert": alert,
            },
            "Directory listing successful",
            target=raw_sort_by,
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
    # 只保留「真实业务面」的动作；原有 lab_* 桩动作
    # （lab_sqli / lab_rce / lab_auth_bypass / lab_path_traversal /
    #  lab_idor / lab_hot_plugin_upload）已下线，其对应教学链
    # 以绿色「已修复」标记在面板中。
    # 只保留「真实业务面」的动作。原有 lab_* 桩动作已全部下线，
    # 对应的 identity_takeover / sandbox_breach / hot_plugin_chain
    # 三条链在面板中以绿色「已修复」（FIXED_CHAINS）呈现。

    # 第 3 条链走的是真实业务接口 list_directory，单独注册；
    # handler 内部自行判断开关状态，关闭时走加固安全路径。
    handlers["list_directory"] = RequestLabListDirectoryHandler
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
