import threading
import time

from sqlalchemy import event, or_
from sqlalchemy.orm import Session

from include.config.constants import ROOT_DIRECTORY_ID
from include.config.settings import global_config
from include.database.models.documents import Document, DocumentRevision, Folder
from include.database.models.files import FileTask
from include.database.models.identity import User
from include.messages import Messages as smsg

# SQLite ignores SELECT ... FOR UPDATE. These bounded, process-local locks keep
# development/test deployments correct. The parent-row lock below is the
# cross-process guarantee for the project's MySQL deployment.
_NAME_SCOPE_LOCKS = tuple(threading.RLock() for _ in range(256))


def lock_name_scope(session: Session, folder_id: str | None) -> Folder | None:
    """Serialize name changes in one directory until the transaction ends."""
    normalized_id = folder_id or ROOT_DIRECTORY_ID
    if global_config["document"]["allow_name_duplicate"]:
        return session.get(Folder, normalized_id)

    lock_index = hash(normalized_id) % len(_NAME_SCOPE_LOCKS)
    held_indexes: set[int] = session.info.setdefault("name_scope_locks", set())
    if lock_index not in held_indexes:
        _NAME_SCOPE_LOCKS[lock_index].acquire()
        held_indexes.add(lock_index)

        if not session.info.get("name_scope_release_listener"):
            session.info["name_scope_release_listener"] = True

            @event.listens_for(session, "after_transaction_end")
            def _release_name_scope_locks(_session, transaction):
                if transaction.parent is not None:
                    return
                indexes = _session.info.pop("name_scope_locks", set())
                for index in indexes:
                    _NAME_SCOPE_LOCKS[index].release()

    # Lock the stable parent row. Locking only a possibly empty name query leaves
    # a gap race and cannot coordinate documents with directories in two tables.
    return (
        session.query(Folder)
        .with_for_update()
        .filter(Folder.id == normalized_id)
        .first()
    )


def _document_has_live_transfer(session: Session, document_id: str) -> bool:
    now = time.time()
    return (
        session.query(FileTask.id)
        .join(DocumentRevision, DocumentRevision.file_id == FileTask.file_id)
        .filter(
            DocumentRevision.document_id == document_id,
            FileTask.status == 0,
            or_(FileTask.end_time == None, FileTask.end_time >= now),
        )
        .first()
        is not None
    )


def get_target_folder_and_check_write(
    session: Session, user: User, target_folder_id: str | None, super_permission: str
) -> tuple[Folder | None, int, str]:
    """
    Looks up the target folder, locks it, and checks write access.
    Returns (folder_object, error_code, error_message).
    If valid, error_code is 0.
    """
    if not target_folder_id:
        target_folder_id = ROOT_DIRECTORY_ID

    target_folder = (
        session.query(Folder).with_for_update().filter_by(id=target_folder_id).first()
    )
    if not target_folder:
        return None, 404, smsg.TARGET_DIRECTORY_NOT_FOUND

    if not target_folder.check_access_requirements(user, "write"):
        if (
            target_folder_id == ROOT_DIRECTORY_ID
            and super_permission in user.all_permissions
        ):
            return target_folder, 0, ""
        return None, 403, smsg.ACCESS_DENIED_WRITE_DIRECTORY

    return target_folder, 0, ""


def handle_name_duplicate(
    session: Session, user: User, folder_id: str | None, title: str
) -> tuple[bool, int, dict, str]:
    """
    Checks if a document or folder with `title` exists under `folder_id`.
    If yes, safely deletes deleted documents or returns conflict details.
    Returns: (has_conflict, error_code, error_data, error_message).
    If no conflict, returns (False, 0, {}, "").
    """
    if global_config["document"]["allow_name_duplicate"]:
        return False, 0, {}, ""

    if not folder_id:
        folder_id = ROOT_DIRECTORY_ID

    lock_name_scope(session, folder_id)

    existing_doc = (
        session.query(Document)
        .with_for_update()
        .filter_by(folder_id=folder_id, title=title)
        .first()
    )
    existing_folder = (
        session.query(Folder)
        .with_for_update()
        .filter_by(parent_id=folder_id, name=title)
        .first()
    )

    if existing_doc:
        # A newly-created document remains inactive until its bytes arrive. It
        # must still reserve the name while its upload task is live; otherwise
        # a concurrent create can delete its revision/task and also return 200.
        if existing_doc.active or _document_has_live_transfer(session, existing_doc.id):
            resp_id = (
                existing_doc.id
                if existing_doc.check_access_requirements(user, "read")
                else None
            )
            payload = {"type": "document", "id": resp_id}
            if resp_id is not None:
                payload["duplicate_id"] = resp_id

            return (
                True,
                409,
                payload,
                smsg.DOCUMENT_NAME_DUPLICATE,
            )
        else:
            if existing_doc.check_access_requirements(user, "write"):
                try:
                    existing_doc.delete_all_revisions(do_commit=False)
                except PermissionError:
                    return (
                        True,
                        500,
                        {},
                        "Failed to delete revisions. Perhaps a file task is in progress?",
                    )
                session.delete(existing_doc)
                # Let caller commit
            else:
                resp_id = (
                    existing_doc.id
                    if existing_doc.check_access_requirements(user, "read")
                    else None
                )
                payload = {"type": "document", "id": resp_id}
                if resp_id is not None:
                    payload["duplicate_id"] = resp_id

                return (
                    True,
                    409,
                    payload,
                    getattr(
                        smsg,
                        "DENIED_FOR_DOC_NAME_DUPLICATE",
                        smsg.DOCUMENT_NAME_DUPLICATE,
                    ),
                )

    elif existing_folder:
        resp_id = (
            existing_folder.id
            if existing_folder.check_access_requirements(user, "read")
            else None
        )
        payload = {"type": "directory", "id": resp_id, "entity": existing_folder}
        if resp_id is not None:
            payload["duplicate_id"] = resp_id

        return (
            True,
            409,
            payload,
            smsg.DIRECTORY_NAME_DUPLICATE,
        )

    return False, 0, {}, ""
