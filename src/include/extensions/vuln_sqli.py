 #NTENTIONALLY VULNERABLE - 教学用途
# pluggy 插件: vuln_sqli
# action: vuln_search
#
# 暴露一个"按用户名前缀模糊查询"接口，使用 SQLAlchemy text() + 字符串拼接
# 把用户输入直接嵌入 SQL，未做任何转义。
#
# 开关:
#   1. config.toml [vuln] enabled = true 且 sqli = true (handle() 内现读，
#      可通过运行时 set_vuln_flag 端点切换，不必重启)
#   2. 本文件存在于 include/extensions/ 下且后缀为 .py
#      → 删除文件或改名为 .py.example，再调 vuln_reload_extensions 即可
#        把该 action 从派发表里移除
#
# 典型 payload:
#   data.q = "x' UNION SELECT username, pass_hash FROM users -- "

from sqlalchemy import text

from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config
from include.database.handler import Session
from include.system.extmgr import hookimpl


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


@hookimpl
def ext_register_handlers():
    return {"vuln_search": RequestVulnSearchHandler}
