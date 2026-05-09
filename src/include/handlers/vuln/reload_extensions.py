# INTENTIONALLY VULNERABLE - 教学用途
# action: vuln_reload_extensions
#
# 暴露 pluggy 插件目录的运行时重载入口。开关:
#   vuln.enabled = true 且 vuln.extension_hot_reload = true
#
# 漏洞要点：
#   1. 仅检查 require_auth（任意已登录用户可调用），不验证管理员权限。
#   2. 重新扫描 include/extensions/ 目录并通过 importlib.exec_module 执行
#      其中所有 .py 文件，对落地的恶意插件没有任何白名单/签名校验。
#   3. 配合 RequestCreateDocumentHandler 的 path_traversal_upload，
#      攻击者可先把恶意 .py 写入 extensions/ 再调用本端点触发执行 → RCE。

from include.constants import ROOT_ABSPATH
from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config
from include.system.extmgr import load_extensions_from_directory


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

        handler.conclude_request(
            200,
            {"directory": str(ext_dir)},
            "Extensions reloaded",
        )
        return 0, str(ext_dir), handler.username
