from __future__ import annotations

import time

from sqlalchemy.orm import Session

from include.config.constants import HOME_PARENT_DIRECTORY_ID, ROOT_DIRECTORY_ID
from include.database.models.access import ObjectAccessEntry
from include.database.models.documents import Folder
from include.database.models.identity import User
from include.domains.access.authorization.access_rules import set_access_rules
from sqlalchemy import select

_SYSOP_RULE = {
    "match": "all",
    "match_groups": [
        {
            "match": "all",
            "groups": {"match": "all", "require": ["sysop"]},
        }
    ],
}
_PRIVATE_RULES = {
    access_type: [_SYSOP_RULE] for access_type in ("read", "write", "move", "manage")
}


def ensure_home_parent(session: Session) -> Folder:
    """Ensure the non-browsable ``/home`` container exists."""
    existing = session.get(Folder, HOME_PARENT_DIRECTORY_ID)
    if existing is not None:
        return existing

    root = session.scalar(select(Folder).where(Folder.id == ROOT_DIRECTORY_ID).with_for_update())
    if root is None:
        raise RuntimeError("Root directory must exist before creating user homes")

    existing = session.get(Folder, HOME_PARENT_DIRECTORY_ID)
    if existing is not None:
        return existing

    home_parent = Folder(
        id=HOME_PARENT_DIRECTORY_ID,
        name="home",
        parent_id=ROOT_DIRECTORY_ID,
        inherit=False,
    )
    session.add(home_parent)
    set_access_rules(home_parent, _PRIVATE_RULES, inherit_parent=False)
    return home_parent


def ensure_user_home(session: Session, user: User) -> str:
    """Create one private home for ``user`` in the caller's transaction."""
    parent = ensure_home_parent(session)
    session.scalar(select(Folder).where(Folder.id == parent.id).with_for_update())

    locked_user = (
        session.query(User)
        .with_for_update()
        .populate_existing()
        .filter(User.username == user.username)
        .one()
    )
    if locked_user.home_directory_id:
        existing = session.get(Folder, locked_user.home_directory_id)
        if existing is not None:
            return existing.id

    home = Folder(name=locked_user.username, parent=parent, inherit=False)
    session.add(home)
    session.flush()
    set_access_rules(home, _PRIVATE_RULES, inherit_parent=False)

    now = time.time()
    for access_type in ("read", "write", "move", "manage"):
        session.add(
            ObjectAccessEntry(
                entity_type="user",
                entity_identifier=locked_user.username,
                target_type="directory",
                target_identifier=home.id,
                access_type=access_type,
                start_time=now,
                end_time=None,
            )
        )

    locked_user.home_directory_id = home.id
    session.flush()
    return home.id
