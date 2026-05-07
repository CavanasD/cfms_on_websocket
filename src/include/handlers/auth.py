import time
from typing import Any, Optional

from include.classes.connection_handler import ConnectionHandler
from include.classes.exceptions import (
    UserNotActiveError,
    UserTOTPFailedError,
    UserTOTPRequiredError,
)
from include.classes.misc.guard import LoginGuard
from include.classes.request_handler import RequestHandler
from include.conf_loader import global_config
from include.database.handler import Session
from include.database.models.classic import User, UserGroup
from include.database.models.keyring import UserKey
from include.util.address import get_client_ip
from include.util.audit import log_audit
from include.util.pwd import (
    InvaildPasswordLengthError,
    MissingComponentsError,
    check_passwd_requirements,
)
from include.util.user import create_user, ensure_user_home


class RequestLoginHandler(RequestHandler):
    """
    Handles user login requests.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1},
            "2fa_token": {"type": "string", "minLength": 1},
        },
        "required": ["username", "password"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        username: str = handler.data["username"]
        password: str = handler.data["password"]
        totp_token: str = handler.data.get("2fa_token", "")

        ip = get_client_ip(handler.stream.connection._ws)

        def respond(code: int, message: str, data: Optional[dict[str, Any]] = None):
            handler.conclude_request(code=code, data=data or {}, message=message)
            return code, username

        def fail(code: int, message: str):
            # Throttle by both IP+username and IP-only
            LoginGuard.report_failure(ip, username, max_attempts=5, ip_max_attempts=20)
            return respond(code, message)

        # Check access: both by IP+username and IP-only are checked simultaneously
        if not LoginGuard.check_access(ip, username):
            return respond(429, "Too many login attempts. Please try again later.")

        cfg = global_config["security"]

        with Session() as session:
            user = session.get(User, username)

            if not user:
                return fail(401, "Invalid credentials")

            try:
                token = user.authenticate_and_create_token(
                    password, totp_token=totp_token
                )
            except UserTOTPRequiredError:
                return respond(
                    202, "Two-factor authentication required", {"method": "totp"}
                )
            except UserTOTPFailedError:
                return fail(401, "Invalid two-factor authentication token")
            except UserNotActiveError:
                return fail(4003, "User account is not active")

            if not token:
                return fail(401, "Invalid credentials")

            LoginGuard.report_success(ip, username)

            try:
                check_passwd_requirements(
                    password,
                    cfg["passwd_min_length"],
                    cfg["passwd_max_length"],
                    cfg["passwd_must_contain"],
                )
            except ValueError:
                return respond(4001, "Password must be changed before you can log in")

            if cfg["enable_passwd_force_expiration"]:
                expiration_seconds = 3600 * 24 * cfg["passwd_expire_after_days"]
                if time.time() - user.passwd_last_modified > expiration_seconds:
                    return respond(
                        4002, "Password should be changed because it's expired"
                    )

            success_data = {
                "token": token.raw,
                "exp": token.exp,
                "nickname": user.nickname,
                "avatar_id": user.avatar_id,
                "permissions": list(user.all_permissions),
                "groups": list(user.all_groups),
                "home_directory_id": user.home_directory_id,
            }

            if user.preference_dek_id:
                preference_dek = session.get(UserKey, user.preference_dek_id)
                if preference_dek:
                    success_data["preference_dek"] = {
                        "key_id": preference_dek.id,
                        "key_content": preference_dek.content,
                        "label": preference_dek.label,
                    }

            return respond(200, "Login successful", success_data)


class RequestRefreshTokenHandler(RequestHandler):
    """
    Handles token refresh requests.
    This util processes a token refresh request by validating the existing token and generating a new one if valid.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200   - Token refreshed successfully, returns a new token in the response data.
        400 - Missing or invalid token in the request.
        500 - Internal server error, with the exception message.
    """

    data_schema = {"type": "object", "properties": {}, "additionalProperties": False}
    require_auth = True

    def handle(self, handler: ConnectionHandler):

        # Parse the refresh token request
        old_token = handler.token

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if user and user.is_token_valid(old_token):
                new_token = user.renew_token()
                response = {
                    "code": 200,
                    "message": "Token refreshed successfully",
                    "data": {"token": new_token.raw, "exp": new_token.exp},
                }
                log_audit(
                    "refresh_token",
                    target=handler.username,
                    result=0,
                    remote_address=handler.remote_address,
                )
            else:
                response = {
                    "code": 400,
                    "message": "Invalid or expired token",
                    "data": {},
                }
                log_audit(
                    "refresh_token",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )

        # Send the response back to the client
        handler.conclude_request(**response)


class RequestRegisterHandler(RequestHandler):
    """Handles public user registration requests."""

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1, "maxLength": 64},
            "password": {"type": "string", "minLength": 1},
            "nickname": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
        "required": ["username", "password"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        username: str = handler.data["username"]
        password: str = handler.data["password"]
        nickname: Optional[str] = handler.data.get("nickname")

        cfg = global_config["security"]

        try:
            check_passwd_requirements(
                password,
                cfg["passwd_min_length"],
                cfg["passwd_max_length"],
                cfg["passwd_must_contain"],
            )
        except InvaildPasswordLengthError as exc:
            handler.conclude_request(400, {}, str(exc))
            return 1, username
        except MissingComponentsError as exc:
            handler.conclude_request(400, {}, str(exc))
            return 1, username

        with Session() as session:
            if session.get(User, username):
                handler.conclude_request(400, {}, "Username already exists")
                return 1, username

            default_group = session.get(UserGroup, "user")
            if not default_group:
                handler.conclude_request(
                    500,
                    {},
                    "Registration is temporarily unavailable: default group not found",
                )
                return 1, username

        create_user(
            username=username,
            password=password,
            nickname=nickname,
            permissions=[],
            groups=[{"group_name": "user", "start_time": 0, "end_time": None}],
        )

        ensure_user_home(username)

        handler.conclude_request(200, {}, "User registered successfully")
        return 0, username
