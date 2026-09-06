from __future__ import annotations

import ast
import importlib
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pluggy
import pytest


@dataclass
class FakeConnectionHandler:
    data: dict[str, Any]
    username: str | None = None
    responses: list[dict[str, Any]] = field(default_factory=list)

    def conclude_request(
        self,
        code: int,
        data: dict[str, Any] | None = None,
        message: str = "",
    ) -> None:
        self.responses.append({"code": code, "data": data or {}, "message": message})


FEATURE_ENV = {
    "sqli": "CFMS_VULN_SQLI_ENABLED",
    "rce": "CFMS_VULN_RCE_ENABLED",
    "auth_bypass": "CFMS_VULN_AUTH_BYPASS_ENABLED",
    "path_traversal": "CFMS_VULN_PATH_TRAVERSAL_ENABLED",
    "idor": "CFMS_VULN_IDOR_ENABLED",
}
FEATURE_ACTIONS = {
    "sqli": "lab_sqli",
    "rce": "lab_rce",
    "auth_bypass": "lab_auth_bypass",
    "path_traversal": "lab_path_traversal",
    "idor": "lab_idor",
}
FEATURE_REQUESTS = {
    "sqli": ({"query": "lab-alice", "dataset": "LAB_USERS"}, None),
    "rce": ({"command": "whoami"}, None),
    "auth_bypass": (
        {"username": "lab-alice", "proof": "LAB-BYPASS-DEMO"},
        None,
    ),
    "path_traversal": ({"path": "readme.txt"}, None),
    "idor": ({"object_id": "LAB-DOC-ALICE"}, "real-core-user"),
}


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    """Import the real extension with the same config precondition as the server."""
    temp_root = tmp_path_factory.mktemp("attack-lab-config")
    source_root = Path(__file__).resolve().parents[1]
    shutil.copy(source_root / "src" / "config.toml.sample", temp_root / "config.toml")
    (temp_root / "init").write_text("test", encoding="utf-8")

    original_cwd = Path.cwd()
    os.chdir(temp_root)
    try:
        return importlib.import_module(
            "include.extensions.thesis_attack_lab._extension"
        )
    finally:
        os.chdir(original_cwd)


@pytest.fixture(autouse=True)
def disabled_clean_lab(monkeypatch, lab):
    monkeypatch.delenv("LAB_MODE", raising=False)
    for env_name in FEATURE_ENV.values():
        monkeypatch.delenv(env_name, raising=False)
    with lab._state_lock:
        lab._runtime_feature_overrides.clear()
        lab._custom_chains.clear()
        lab._chain_progress = {name: 0 for name in lab.CHAIN_STEPS}
    lab._reset_lab_state()


def enable(monkeypatch, lab, *features: str) -> None:
    monkeypatch.setenv("LAB_MODE", "true")
    for feature in features:
        monkeypatch.setenv(FEATURE_ENV[feature], "true")


def call(lab, handler_type, data, *, username=None):
    connection = FakeConnectionHandler(data=data, username=username)
    result = handler_type().handle(connection)
    assert isinstance(result, lab.Result)
    assert connection.responses[-1]["code"] == result.code
    return result, connection.responses[-1]


def test_default_environment_registers_no_lab_surface(lab):
    assert lab.ext_register_handlers() == {}
    assert lab.ext_register_extension_flags() == set()


def test_lab_extension_has_no_host_execution_storage_or_database_primitives(lab):
    tree = ast.parse(Path(lab.__file__).read_text(encoding="utf-8"))
    forbidden_modules = {
        "ctypes",
        "multiprocessing",
        "pathlib",
        "shlex",
        "socket",
        "sqlite3",
        "sqlalchemy",
        "subprocess",
    }
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imported_roots.isdisjoint(forbidden_modules)

    forbidden_builtins = {"__import__", "compile", "eval", "exec", "open"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden_builtins
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ):
            assert node.func.attr == "getenv"


def test_real_extension_manager_loads_new_directory_entrypoint(
    monkeypatch, lab, tmp_path
):
    import include.extensions.manager as extension_manager

    plugin_manager = pluggy.PluginManager("cfms")
    plugin_manager.add_hookspecs(extension_manager.ServerHookSpecs)
    monkeypatch.setattr(extension_manager, "pm", plugin_manager)
    extension_root = tmp_path / "extensions"
    extension_root.mkdir()
    shutil.copytree(
        Path(lab.__file__).resolve().parent,
        extension_root / "thesis_attack_lab",
    )
    previous = sys.modules.pop("thesis_attack_lab", None)
    try:
        shutil.copytree(Path(extension_manager.__file__).parent / "builtin", extension_root / "builtin")
        from include.config.settings import global_config
        extension_manager.load_extensions_from_directory(
            extension_root, ("thesis_attack_lab",), config=global_config
        )
        assert plugin_manager.has_plugin("thesis_attack_lab")
        assert lab.ext_register_handlers() == {}
    finally:
        sys.modules.pop("thesis_attack_lab", None)
        if previous is not None:
            sys.modules["thesis_attack_lab"] = previous


@pytest.mark.parametrize(("feature", "action"), FEATURE_ACTIONS.items())
def test_each_action_requires_both_lab_and_feature_gate(
    monkeypatch, lab, feature: str, action: str
):
    monkeypatch.setenv(FEATURE_ENV[feature], "true")
    assert action not in lab.ext_register_handlers()

    monkeypatch.setenv("LAB_MODE", "true")
    handlers = lab.ext_register_handlers()
    assert action in handlers
    assert "reset_lab" in handlers
    assert "lab_status" in handlers


@pytest.mark.parametrize(("feature", "action"), FEATURE_ACTIONS.items())
def test_runtime_gate_still_rejects_after_registered_flag_is_disabled(
    monkeypatch, lab, feature: str, action: str
):
    enable(monkeypatch, lab, feature)
    handler_type = lab.ext_register_handlers()[action]
    monkeypatch.setenv(FEATURE_ENV[feature], "false")
    data, username = FEATURE_REQUESTS[feature]

    result, _ = call(lab, handler_type, data, username=username)

    assert result.code == 403


def test_sqli_simulation_returns_only_lab_rows_and_blocks_non_lab_boundary(
    monkeypatch, lab
):
    enable(monkeypatch, lab, "sqli")

    result, _ = call(
        lab,
        lab.RequestLabSQLiHandler,
        {"query": "' OR '1'='1", "dataset": "LAB_USERS"},
    )
    assert result.code == 200
    assert result.data["triggered"] is True
    assert all(row["lab"] is True for row in result.data["rows"])
    assert "prod-root-sentinel" not in {row["username"] for row in result.data["rows"]}
    assert result.data["alert"]["kind"] == "sqli"

    blocked, _ = call(
        lab,
        lab.RequestLabSQLiHandler,
        {"query": "prod-root-sentinel", "dataset": "LAB_USERS"},
    )
    assert blocked.code == 403

    unlisted, _ = call(
        lab,
        lab.RequestLabSQLiHandler,
        {"query": "x'; drop table users; --", "dataset": "LAB_USERS"},
    )
    assert unlisted.code == 400


def test_rce_is_a_fixed_simulation_and_rejects_non_allowlisted_commands(
    monkeypatch, lab
):
    enable(monkeypatch, lab, "rce")

    result, _ = call(lab, lab.RequestLabRCEHandler, {"command": "read-honeytoken"})
    assert result.code == 200
    assert result.data["execution"] == "simulated"
    assert result.data["host_process_started"] is False
    assert result.data["sandbox"].startswith("virtual://")
    assert result.data["alert"]["kind"] == "rce"

    blocked, _ = call(lab, lab.RequestLabRCEHandler, {"command": "rm -rf /"})
    assert blocked.code == 400


def test_auth_bypass_issues_no_real_token_and_only_targets_lab_accounts(
    monkeypatch, lab
):
    enable(monkeypatch, lab, "auth_bypass")

    result, _ = call(
        lab,
        lab.RequestLabAuthBypassHandler,
        {"username": "lab-decoy-admin", "proof": "LAB-BYPASS-DEMO"},
    )
    assert result.code == 200
    assert result.data["usable_for_core_authentication"] is False
    assert result.data["simulated_token"].startswith("LAB-SIMULATED:")
    assert result.data["alert"]["kind"] == "auth_bypass"

    blocked, _ = call(
        lab,
        lab.RequestLabAuthBypassHandler,
        {"username": "prod-root-sentinel", "proof": "LAB-BYPASS-DEMO"},
    )
    assert blocked.code == 403


def test_path_traversal_reaches_virtual_decoy_but_never_escapes_sandbox(
    monkeypatch, lab
):
    enable(monkeypatch, lab, "path_traversal")

    result, _ = call(
        lab,
        lab.RequestLabPathTraversalHandler,
        {"path": "../decoys/honeytoken.txt"},
    )
    assert result.code == 200
    assert result.data["resolved_path"] == "/decoys/honeytoken.txt"
    assert result.data["host_filesystem_accessed"] is False
    assert result.data["alert"]["kind"] == "path_traversal"

    for probe in ("../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/passwd"):
        blocked, _ = call(lab, lab.RequestLabPathTraversalHandler, {"path": probe})
        assert blocked.code == 403
        assert blocked.data["blocked_boundary"] == "virtual_sandbox_root"

    unlisted, _ = call(
        lab,
        lab.RequestLabPathTraversalHandler,
        {"path": "../../../unexpected"},
    )
    assert unlisted.code == 400


def test_idor_skips_owner_only_for_authenticated_actor_and_lab_object(
    monkeypatch, lab
):
    enable(monkeypatch, lab, "idor")

    result, _ = call(
        lab,
        lab.RequestLabIDORHandler,
        {"object_id": "LAB-DOC-BOB"},
        username="real-core-user",
    )
    assert lab.RequestLabIDORHandler.require_auth is True
    assert result.code == 200
    assert result.data["idor_triggered"] is True
    assert result.data["owner"] == "lab-bob"

    non_lab_object, _ = call(
        lab,
        lab.RequestLabIDORHandler,
        {"object_id": "PROD-DOC-SENTINEL"},
        username="real-core-user",
    )
    assert non_lab_object.code == 403
    assert "NEVER_RETURN_THIS_VALUE" not in repr(non_lab_object.data)

    unauthenticated_actor, _ = call(
        lab,
        lab.RequestLabIDORHandler,
        {"object_id": "LAB-DOC-BOB"},
    )
    assert unauthenticated_actor.code == 401


def test_honeytoken_alert_is_published_to_existing_event_bus(monkeypatch, lab):
    published = []

    class FakeEventBus:
        def publish(self, channel, message):
            published.append((channel, message))

    class FakeProviderManager:
        event_bus = FakeEventBus()

    monkeypatch.setattr(lab, "ProviderManager", FakeProviderManager)
    enable(monkeypatch, lab, "path_traversal")

    result, _ = call(
        lab,
        lab.RequestLabPathTraversalHandler,
        {"path": "../decoys/honeytoken.txt"},
        username="lab-alice",
    )

    assert result.code == 200
    assert published[0][0] == "cfms.lab.honeytoken"
    assert "LAB-ALERT" in published[0][1]


def test_identity_attack_chain_is_ordered_and_resettable(monkeypatch, lab):
    enable(monkeypatch, lab, "sqli", "auth_bypass", "idor")
    handlers = lab.ext_register_handlers()
    assert "lab_chain_step" in handlers

    reset, _ = call(lab, lab.RequestResetLabHandler, {})
    assert reset.code == 200

    out_of_order, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {"chain": "identity_takeover", "step": "bypass"},
    )
    assert out_of_order.code == 409

    first, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {"chain": "identity_takeover", "step": "enumerate"},
    )
    second, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {
            "chain": "identity_takeover",
            "step": "bypass",
            "evidence": first.data["evidence"],
        },
    )
    final, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {
            "chain": "identity_takeover",
            "step": "idor",
            "evidence": second.data["evidence"],
        },
    )
    assert final.code == 200
    assert final.data["completed"] is True
    assert final.data["alert"]["kind"] == "attack_chain"
    assert final.data["exercise"]["action"] == "lab_idor"

    call(lab, lab.RequestResetLabHandler, {})
    status, _ = call(lab, lab.RequestLabStatusHandler, {})
    assert status.data["chain_progress"]["identity_takeover"] == 0
    assert status.data["alerts"] == []


def test_sandbox_attack_chain_requires_traversal_and_rce_gates(monkeypatch, lab):
    enable(monkeypatch, lab, "path_traversal")
    assert "lab_chain_step" in lab.ext_register_handlers()

    blocked, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {"chain": "sandbox_breach", "step": "traverse"},
    )
    assert blocked.code == 403

    enable(monkeypatch, lab, "path_traversal", "rce")
    assert "lab_chain_step" in lab.ext_register_handlers()

    first, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {"chain": "sandbox_breach", "step": "traverse"},
    )
    final, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {
            "chain": "sandbox_breach",
            "step": "execute",
            "evidence": first.data["evidence"],
        },
    )
    assert final.code == 200
    assert final.data["completed"] is True
    assert final.data["exercise"]["action"] == "lab_rce"


def test_sysop_can_hot_switch_lab_features_without_restart(monkeypatch, lab):
    monkeypatch.setenv("LAB_MODE", "true")
    monkeypatch.setattr(lab, "_is_sysop", lambda username: username == "teacher")

    enabled, _ = call(
        lab,
        lab.RequestLabSetVulnerabilityHandler,
        {"feature": "sqli", "enabled": True},
        username="teacher",
    )
    assert enabled.code == 200
    assert lab.RequestLabSQLiHandler().handle(
        FakeConnectionHandler({"query": "lab-alice", "dataset": "LAB_USERS"})
    ).code == 200

    disabled, _ = call(
        lab,
        lab.RequestLabSetVulnerabilityHandler,
        {"feature": "sqli", "enabled": False},
        username="teacher",
    )
    assert disabled.code == 200
    assert lab.RequestLabSQLiHandler().handle(
        FakeConnectionHandler({"query": "lab-alice", "dataset": "LAB_USERS"})
    ).code == 403


def test_sysop_can_publish_an_ordered_custom_teaching_chain(monkeypatch, lab):
    enable(monkeypatch, lab, "sqli", "rce")
    monkeypatch.setattr(lab, "_is_sysop", lambda username: username == "teacher")

    denied, _ = call(
        lab,
        lab.RequestLabConfigureChainHandler,
        {
            "chain": "custom-demo",
            "title": "自定义演练",
            "steps": ["enumerate", "execute"],
        },
        username="student",
    )
    assert denied.code == 403

    published, _ = call(
        lab,
        lab.RequestLabConfigureChainHandler,
        {
            "chain": "custom-demo",
            "title": "自定义演练",
            "steps": ["enumerate", "execute"],
        },
        username="teacher",
    )
    assert published.code == 200

    first, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {"chain": "custom-demo", "step": "enumerate"},
    )
    final, _ = call(
        lab,
        lab.RequestLabChainStepHandler,
        {
            "chain": "custom-demo",
            "step": "execute",
            "evidence": first.data["evidence"],
        },
    )
    assert final.code == 200
    assert final.data["completed"] is True
    assert final.data["exercise"]["action"] == "lab_rce"


def test_profile_files_preserve_double_gate_contract(lab):
    profile_root = Path(lab.__file__).resolve().parent / "profiles"
    unprotected = (profile_root / "unprotected.env").read_text(encoding="utf-8")
    baseline = (profile_root / "baseline.env").read_text(encoding="utf-8")
    hardened = (profile_root / "hardened.env").read_text(encoding="utf-8")

    for profile in (unprotected, baseline):
        assert "LAB_MODE=true" in profile
        assert all(f"{env_name}=true" in profile for env_name in FEATURE_ENV.values())
    assert "LAB_MODE=false" in hardened
    assert all(f"{env_name}=false" in hardened for env_name in FEATURE_ENV.values())
