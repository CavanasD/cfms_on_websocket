# INTENTIONALLY VULNERABLE - 教学用途
# action: vuln_export
#
# 模拟"按文档名导出归档"功能，把客户端 name 字段直接拼进 shell 命令
# 并用 subprocess.run(shell=True) 执行。
#
# 开关: vuln.enabled = true 且 vuln.cmdi = true
#
# 典型 payload (绕 WAF 后):
#   data.name = "report.txt; cat /etc/passwd"
#   data.name = "a$IFS$9&&id"
#   data.name = "x`whoami`"

import subprocess

from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config


class RequestVulnExportHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        _vuln = global_config.get("vuln", {})
        if not (_vuln.get("enabled") and _vuln.get("cmdi")):
            handler.conclude_request(404, {}, "Unknown action")
            return 404, None, handler.username

        name: str = handler.data["name"]

        # INTENTIONALLY VULNERABLE: shell=True + 字符串拼接
        cmd = f"echo Exporting: {name}"
        try:
            completed = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            output = completed.stdout + completed.stderr
        except Exception as e:
            handler.conclude_request(500, {"error": str(e)}, "Command execution failed")
            return 500, name, handler.username

        handler.conclude_request(
            200,
            {"executed_cmd": cmd, "output": output, "returncode": completed.returncode},
            "Export executed",
        )
        return 0, name, handler.username
