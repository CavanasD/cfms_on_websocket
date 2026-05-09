# INTENTIONALLY VULNERABLE - 教学用途
# action: vuln_search
#
# 暴露一个"按用户名前缀模糊查询"接口，使用 SQLAlchemy text() + 字符串拼接
# 把用户输入直接嵌入 SQL，未做任何转义。
#
# 开关: vuln.enabled = true 且 vuln.sqli = true
#
# 对照: 项目其它 handler 全部走 SQLAlchemy ORM 参数化查询，本接口纯粹为
# 演示 SQLi 而存在。
#
# 典型 payload (绕 WAF 后):
#   data.q = "x' UNION SELECT username, pass_hash FROM users -- "

from sqlalchemy import text

from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config
from include.database.handler import Session


class RequestVulnSearchHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {"q": {"type": "string"}},
        "required": ["q"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        _vuln = global_config.get("vuln", {})
        if not (_vuln.get("enabled") and _vuln.get("sqli")):
            handler.conclude_request(404, {}, "Unknown action")
            return 404, None, handler.username

        q: str = handler.data["q"]

        # INTENTIONALLY VULNERABLE: 字符串拼接 SQL
        unsafe_sql = f"SELECT username FROM users WHERE username LIKE '{q}%'"

        with Session() as session:
            try:
                result = session.execute(text(unsafe_sql)).all()
                rows = [list(r) for r in result]
            except Exception as e:
                handler.conclude_request(500, {"error": str(e)}, "SQL execution failed")
                return 500, q, handler.username

        handler.conclude_request(
            200,
            {"rows": rows, "executed_sql": unsafe_sql},
            f"Found {len(rows)} row(s)",
        )
        return 0, q, handler.username
