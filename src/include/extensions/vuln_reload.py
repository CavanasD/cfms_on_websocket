# INTENTIONALLY VULNERABLE - 教学用途
# pluggy 插件: vuln_reload
# action: vuln_reload_extensions
#
# 暴露 pluggy 插件目录的运行时热插拔入口。本插件就是热插拔机制本身的入口，
# 当 vuln.extension_hot_reload 关闭或本文件被改名为 .py.example 时，热插拔
# 通道也随之关闭——只能重启服务才能再恢复。
#
# 漏洞要点:
#   1. 仅检查 require_auth (任意已登录用户可调用)，不验证管理员权限。
#   2. 重新扫描 include/extensions/ 目录:
#         - 对已加载插件: pm.unregister + sys.modules.pop + 重新 exec_module
#         - 对新增 .py:  首次注册
#         - 对消失的:    自动 unregister 并清出派发表
#      过程中对落地的恶意插件没有任何白名单/签名校验。
#   3. 配合 RequestCreateDocumentHandler 的 path_traversal_upload，
#      攻击者可先把恶意 .py 写入 extensions/ 再调用本端点触发执行 → RCE。
#   4. 攻击者也可用同名文件覆盖现有插件 (例如把 vuln_sqli.py 换成自带后门
#      的版本)，下一次调用便会替换其行为。

from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config
from include.constants import ROOT_ABSPATH
from include.system.extmgr import hookimpl, load_extensions_from_directory


class RequestVulnReloadExtensionsHandler(RequestHandler):
    data_schema = {"type": "object", "additionalProperties": False}
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        _vuln = global_config.get("vuln", {})
        if not (_vuln.get("enabled") and _vuln.get("extension_hot_reload")):
            handler.conclude_request(404, {}, "Unknown action")
            return 404, None, handler.username

        ext_dir = ROOT_ABSPATH / "include" / "extensions"
        load_extensions_from_directory(ext_dir)

        # Rebuild the router dispatch table so newly registered / unregistered
        # plugin actions take effect immediately. Late import: main imports
        # this module transitively at startup, so importing prepare_handlers
        # at module scope would deadlock.
        from main import prepare_handlers
        prepare_handlers()

        handler.conclude_request(
            200,
            {"directory": str(ext_dir)},
            "Extensions reloaded",
        )
        return 0, str(ext_dir), handler.username


@hookimpl
def ext_register_handlers():
    return {"vuln_reload_extensions": RequestVulnReloadExtensionsHandler}
