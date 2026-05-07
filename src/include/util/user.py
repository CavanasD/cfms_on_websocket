import time

from argon2 import PasswordHasher

from include.constants import HOME_PARENT_DIRECTORY_ID
from include.database.handler import Session
from include.database.models.classic import (
    ObjectAccessEntry,
    User,
    UserMembership,
    UserPermission,
)
from include.database.models.entity import Folder
from include.util.rule.applying import set_access_rules

# Module-level PasswordHasher instance — reused across all calls to avoid
# repeated construction overhead.
_password_hasher = PasswordHasher()


# Access rule that denies non-sysop users via the rule path. Owners get access
# through ObjectAccessEntry grants which short-circuit before rules are evaluated.
_SYSOP_ONLY_RULE = {
    "match": "all",
    "match_groups": [
        {
            "match": "all",
            "groups": {"match": "all", "require": ["sysop"]},
        }
    ],
}
_SYSOP_ONLY_RULES = {
    "read": [_SYSOP_ONLY_RULE],
    "write": [_SYSOP_ONLY_RULE],
    "manage": [_SYSOP_ONLY_RULE],
}


def ensure_user_home(username: str) -> str:
    """
    Ensure the given user has a personal home directory under ``/home``.

    Creates ``/home/<username>`` (if missing), wires read/write/manage grants
    to that user via ObjectAccessEntry, and stores the folder id on
    ``User.home_directory_id``. Sets ``inherit=False`` on the home folder so
    access checks do not bubble up into ``/home`` (which is sysop-only).

    Returns the folder id.
    """
    with Session() as session:
        user = session.get(User, username)
        if user is None:
            raise ValueError(f"User not found: {username}")

        if user.home_directory_id:
            existing = session.get(Folder, user.home_directory_id)
            if existing is not None:
                return existing.id

        home_folder = Folder(
            name=username,
            parent_id=HOME_PARENT_DIRECTORY_ID,
            inherit=False,
        )
        session.add(home_folder)
        session.flush()  # populate generated id

        set_access_rules(home_folder, _SYSOP_ONLY_RULES, inherit_parent=False)

        now = time.time()
        for access_type in ("read", "write", "manage"):
            session.add(
                ObjectAccessEntry(
                    entity_type="user",
                    entity_identifier=username,
                    target_type="directory",
                    target_identifier=home_folder.id,
                    access_type=access_type,
                    start_time=now,
                    end_time=None,
                )
            )

        user.home_directory_id = home_folder.id
        session.commit()
        return home_folder.id


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

    pass_hash = _password_hasher.hash(kwargs["password"])
    with Session() as session:
        user = User(
            username=kwargs["username"],
            pass_hash=pass_hash,
            nickname=kwargs.get("nickname", None),
            last_login=0,
            created_time=time.time(),
        )
        for i in kwargs.get("permissions", []):
            permission = UserPermission(
                user=user,
                permission=i["permission"],
                granted=i.get("granted", True),
                start_time=i.get("start_time", time.time()),
                end_time=i.get("end_time", None),
            )
            user.rights.append(permission)

        for k in kwargs.get("groups", []):
            membership = UserMembership(
                user=user,
                group_name=k["group_name"],
                start_time=k.get("start_time", time.time()),
                end_time=k.get("end_time", None),
            )
            user.groups.append(membership)

        session.add(user)
        session.commit()
