__all__ = ["RequestGetQuotaHandler"]

from include.classes.connection_handler import ConnectionHandler
from include.classes.request_handler import RequestHandler
from include.database.handler import Session
from include.database.models.classic import User
from include.util.quota import get_user_disk_usage


class RequestGetQuotaHandler(RequestHandler):
    """
    Returns the calling user's disk quota and current usage. Cheap to call,
    safe to poll from a UI usage indicator.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        # Self-query is the default; sysop can target other users by name.
        target_username = handler.data.get("username", handler.username)

        with Session() as session:
            caller = User.get_existing(session, handler.username)
            if target_username != handler.username:
                # Only sysop / users with manage permission can peek at others.
                # We piggyback on group membership rather than introducing a
                # new permission flag — sysop already controls everything.
                if "sysop" not in caller.all_groups:
                    handler.conclude_request(
                        403, {}, "Cannot view another user's quota"
                    )
                    return 1, target_username

            target = session.get(User, target_username)
            if target is None:
                handler.conclude_request(404, {}, "User not found")
                return 1, target_username

            handler.conclude_request(
                200,
                {
                    "username": target.username,
                    "disk_quota": target.disk_quota,
                    "disk_used": get_user_disk_usage(session, target.username),
                },
                "ok",
            )
            return 0, target_username
