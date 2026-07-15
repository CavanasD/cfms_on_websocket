import time

from argon2 import PasswordHasher
from sqlalchemy.orm import Session as ORMSession

from include.config.constants import DEFAULT_DISK_QUOTA_BYTES
from include.database.models.identity import User, UserMembership, UserPermission
from include.database.session import Session

# Module-level PasswordHasher instance — reused across all calls to avoid
# repeated construction overhead.
_password_hasher = PasswordHasher()


def create_user_in_session(session: ORMSession, **kwargs) -> User:
    """Build and add a user using the caller's transaction."""
    pass_hash = _password_hasher.hash(kwargs["password"])
    user = User(
        username=kwargs["username"],
        pass_hash=pass_hash,
        nickname=kwargs.get("nickname"),
        last_login=0,
        created_time=time.time(),
        disk_quota=kwargs.get("disk_quota", DEFAULT_DISK_QUOTA_BYTES),
    )
    for item in kwargs.get("permissions", []):
        user.rights.append(
            UserPermission(
                user=user,
                permission=item["permission"],
                granted=item.get("granted", True),
                start_time=item.get("start_time", time.time()),
                end_time=item.get("end_time"),
            )
        )

    for item in kwargs.get("groups", []):
        user.groups.append(
            UserMembership(
                user=user,
                group_name=item["group_name"],
                start_time=item.get("start_time", time.time()),
                end_time=item.get("end_time"),
            )
        )

    session.add(user)
    return user


def create_user(**kwargs) -> None:
    """
    Create a new user in the system.

    This utility hashes the provided password using argon2id and creates
    a user record along with associated permissions and group memberships.

    Args:
        **kwargs: Arbitrary keyword arguments that may include:
            - username (str): The username for the new user.
            - password (str): The password for the new user.
            - nickname (str, optional): The nickname for the new user.
            - permissions (list, optional): A list of dicts for user
              permissions. Each dict may contain:
                - permission (str): The permission to be granted.
                - granted (bool, optional): Whether the permission is
                  granted (default is True).
                - start_time (float, optional): The start time for the
                  permission (default is current time).
                - end_time (float, optional): The end time for the
                  permission (default is None).
            - groups (list, optional): A list of dicts for user group
              memberships. Each dict may contain:
                - group_name (str): The name of the group.
                - start_time (float, optional): The start time for the
                  membership (default is current time).
                - end_time (float, optional): The end time for the
                  membership (default is None).

    Returns:
        None: Commits the new user to the database.
    """

    with Session() as session:
        create_user_in_session(session, **kwargs)
        session.commit()
