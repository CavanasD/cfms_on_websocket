# INTENTIONALLY VULNERABLE - 教学用途
# action: vuln_import_state
#
# 模拟"客户端导入会话状态"接口，对客户端 base64 字段执行 pickle.loads。
# pickle 的反序列化过程会执行任意 __reduce__ 钩子 → 等价于任意代码执行。
#
# 开关: vuln.enabled = true 且 vuln.deser = true
#
# 典型 payload 生成:
#   import pickle, base64, os
#   class E:
#       def __reduce__(self): return (os.system, ("id > /tmp/pwned",))
#   print(base64.b64encode(pickle.dumps(E())).decode())

import base64
import pickle  # noqa: S403  教学项目故意使用

from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config


class RequestVulnImportStateHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {"state": {"type": "string"}},
        "required": ["state"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        _vuln = global_config.get("vuln", {})
        if not (_vuln.get("enabled") and _vuln.get("deser")):
            handler.conclude_request(404, {}, "Unknown action")
            return 404, None, handler.username

        try:
            raw = base64.b64decode(handler.data["state"])
            # INTENTIONALLY VULNERABLE: pickle.loads on attacker-controlled bytes
            obj = pickle.loads(raw)  # noqa: S301
        except Exception as e:
            handler.conclude_request(400, {"error": str(e)}, "Failed to import state")
            return 400, None, handler.username

        handler.conclude_request(
            200,
            {"type": type(obj).__name__, "repr": repr(obj)[:200]},
            "State imported",
        )
        return 0, None, handler.username
