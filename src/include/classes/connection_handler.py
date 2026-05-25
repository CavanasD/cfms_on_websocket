import base64
import hashlib
import os
import time
from typing import Optional

import jsonschema
import orjson
import websockets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from loguru import logger as log
from websockets.typing import Data

from include.classes.multiplexer import FrameType, Stream
from include.conf_loader import global_config
from include.constants import FILE_TRANSFER_MAX_CHUNK_SIZE, FILE_TRANSFER_MIN_CHUNK_SIZE
from include.database.handler import Session
from include.database.models.file import File, FileTask
from include.providers.manager import ProviderManager
from include.system.extmgr import pm
from include.system.messages import Messages as smsg
from include.util.log import log_exception_with_id
from include.util.quota import check_quota_for_upload

logger = log.bind(name="conn")


def calculate_sha256(file_path):
    hasher = hashlib.sha256()
    with ProviderManager().storage.fopen(file_path, "rb") as f:
        while chunk := f.read(global_config["server"]["file_chunk_size"]):
            hasher.update(chunk)
    return hasher.hexdigest()


# JSON Schema for the top-level request envelope.
# Validates field types so downstream code can rely on concrete types.
_REQUEST_ENVELOPE_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string"},
        "data": {"type": "object"},
        "username": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        "nonce": {"type": "string"},
        "timestamp": {"type": "number"},
    },
    "required": ["action", "data"],
    "dependentRequired": {
        "username": ["token"],
        "token": ["username"],
    },
}


class ConnectionHandler:
    def __init__(self, stream: Stream) -> None:
        self.stream = stream
        self.remote_address = self.stream.connection._ws.remote_address[0]

        # Since a thread is created only after a new request has been
        # received, the necessary initial data should be available
        # immediately here.
        self.request = orjson.loads(stream.recv().data)
        self.logger = logger

        # Validate the request envelope structure and field types
        jsonschema.validate(self.request, _REQUEST_ENVELOPE_SCHEMA)

        self.action: str = self.request["action"]
        self.data: dict = self.request["data"]

        self.username: str = self.request.get("username", "")
        self.token: str = self.request.get("token", "")

        self.nonce: str = self.request.get("nonce", "")
        self.request_timestamp: float = self.request.get("timestamp", 0.0)

    def conclude_permission_denial(self) -> None:
        self.conclude_request(403, {}, smsg.PERMISSION_DENIED)

    def conclude_access_denial(self) -> None:
        self.conclude_request(403, {}, smsg.ACCESS_DENIED)

    def conclude_request(
        self, code: int, data: Optional[dict] = None, message: str = ""
    ) -> None:
        """
        Conclude the request by sending a response back to the client.

        Args:
            code: HTTP status code for the response.
            data: Data dictionary to include in the response.
            message: Message string to include in the response.
        """
        response = {
            "code": code,
            "data": data if data is not None else {},
            "message": message,
            "timestamp": time.time(),
        }

        response_json = orjson.dumps(
            response,
        )
        self.logger.debug(f"Sending response: {response_json}")

        self.stream.send(response_json, frame_type=FrameType.CONCLUSION)

    def report_error(
        self,
        exc: Exception,
        code: int = 500,
        context: Optional[str] = None,
        send_to_client: bool = True,
    ) -> str:
        """
        Log an exception with a generated log id and optionally send a safe message to client.

        Returns the generated log id.
        """
        log_id = log_exception_with_id(exc, self.logger, context=context)
        if send_to_client:
            self.conclude_request(
                code,
                {
                    "log_id": log_id,
                },
                context if context is not None else "Internal server error",
            )
        return log_id

    def send_file(self, task_id: str) -> None:
        """
        Sends a file associated with the given task ID to the client over a websocket connection using AES encryption.
        The method performs the following steps:
        1. Retrieves the file ID and file path based on the provided task ID.
        2. Calculates the SHA-256 hash and size of the file.
        3. Notifies the client of the impending file transfer, including the hash and size.
        4. Waits for the client to acknowledge readiness to receive the file.
        5. Encrypts the file using AES-256 in GCM mode with a randomly generated key and nonce.
        6. Sends the nonce with the first encrypted chunk, then sends the remaining encrypted chunks.
        7. After the file is sent, transmits the AES key and tag to the client (base64 encoded).
        8. Handles errors and logs relevant information.
        Args:
            task_id (str): The identifier for the task whose associated file is to be sent.
        Raises:
            ValueError: If the file ID or file path cannot be found for the given task ID.
            Exception: If an error occurs during file encryption or transmission.
        Returns:
            None
        """

        with Session() as session:
            # Query the FileTask table to get the file_id associated with the task_id
            file_task = session.get(FileTask, task_id)
            if not file_task:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if file_task.mode != 0:
                raise ValueError(f"Not a read-mode task: {task_id}")
            if file_task.status != 0:
                raise ValueError(
                    f"File transfer task already completed or cancelled: {task_id}"
                )
            # Query the File table to get the file path associated with the file_id
            file = session.get(File, file_task.file_id)
            if not file:
                raise ValueError(f"File not found for file_id: {file_task.file_id}")

            self.logger.info(
                f"Task {file_task.id}: preparing to send file (id: {file_task.file_id})."
            )

            file_size = ProviderManager().storage.getsize(file.path)
            sha256 = calculate_sha256(file.path) if file_size else None

            self.logger.info(
                f"Calculation complete. SHA256: {sha256}, File size: {file_size}"
            )

            file_path = file.path  # 防止 Session 关闭后可能出现的异常

            ### 发送方首先发出文件信息
            chunk_size = global_config["server"]["file_chunk_size"]  # 文件分块大小
            total_chunks = (file_size + chunk_size - 1) // chunk_size

            self.stream.send(
                orjson.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "sha256": sha256,  # 原始文件的 SHA256 哈希值
                            "file_size": file_size,  # 原始文件的大小
                            "chunk_size": chunk_size,  # 分块大小
                            "total_chunks": total_chunks,  # 文件总分块数
                        },
                    },
                )
            )

            received_response = (
                self.stream.recv()
            )  # Wait for client acknowledgment before sending the file
            if received_response.data != b"ready":
                self.logger.error(
                    "Client did not acknowledge readiness for file "
                    f"transfer: {received_response}"
                )
                self.conclude_request(400, {}, "Client not ready for file transfer")
                return

            if file_size != 0:
                self.logger.info("File transmission begin.")
                try:
                    aes_key = get_random_bytes(32)  # AES-256
                    nonce = get_random_bytes(16)
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=16)

                    with ProviderManager().storage.fopen(file_path, "rb") as file:
                        chunk_index = 0
                        while True:
                            chunk = file.read(chunk_size)
                            if not chunk:
                                break
                            chunk_hash = hashlib.sha256(chunk).hexdigest()
                            encrypted_chunk = cipher.encrypt(chunk)
                            payload = {
                                "action": "file_chunk",
                                "data": {
                                    "index": chunk_index,
                                    "hash": chunk_hash,
                                    "chunk": base64.b64encode(encrypted_chunk).decode(),
                                },
                            }
                            self.stream.send(
                                orjson.dumps(
                                    payload,
                                )
                            )
                            chunk_index += 1

                    tag = cipher.digest()

                    # send AES key, nonce and tag to client after file transfer is complete
                    self.stream.send(
                        orjson.dumps(
                            {
                                "action": "aes_key",
                                "data": {
                                    "key": base64.b64encode(aes_key).decode(),
                                    "nonce": base64.b64encode(nonce).decode(),
                                    "tag": base64.b64encode(tag).decode(),
                                },
                            },
                        )
                    )
                    file_task.status = 1
                    session.commit()

                except Exception as e:
                    self.report_error(e, context=f"Error sending file {file_path}")
                    return

            else:
                self.logger.info("Empty file, no need to send")

        self.logger.info(f"File {file_path} sent successfully.")

    def receive_file(self, task_id: str) -> None:
        """
        Receives a file from the client over a websocket connection using AES encryption.
        The method performs the following steps:
        1. Waits for the client to send the file transfer request, including the SHA-256 hash and file size.
        2. Acknowledges readiness to receive the file.
        3. Receives the encrypted file data in chunks, decrypting each chunk using AES-256 in GCM mode.
        4. Writes the decrypted data to a file on disk.
        5. Handles errors and logs relevant information.
        Returns:
            None
        """

        handshake_msg = {
            "action": "transfer_file",
            "data": {},
            "message": "waiting for file transfer",
        }

        self.stream.send(
            orjson.dumps(
                handshake_msg,
            )
        )
        self.logger.info("Receiving file: handshake sent")

        task_info = orjson.loads(self.stream.recv().data)

        try:
            jsonschema.validate(
                task_info,
                {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "pattern": "^transfer_file$"},
                        "data": {
                            "type": "object",
                            "properties": {
                                "sha256": {
                                    "anyOf": [{"type": "string"}, {"type": "null"}]
                                },
                                "file_size": {"type": "integer"},
                                "max_chunk_size": {
                                    "type": "integer",
                                    "minimum": FILE_TRANSFER_MIN_CHUNK_SIZE,
                                },
                            },
                            "required": ["file_size"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["data"],
                    "additionalProperties": False,
                },
            )
        except jsonschema.ValidationError:
            self.conclude_request(400, {}, "Invalid request for file transfer")
            return

        sha256: str = task_info["data"].get("sha256")
        file_size: int = task_info["data"].get("file_size")
        max_chunk_size: int = task_info["data"].get(
            "max_chunk_size", FILE_TRANSFER_MAX_CHUNK_SIZE
        )

        chunk_size = (
            FILE_TRANSFER_MAX_CHUNK_SIZE
            if max_chunk_size > FILE_TRANSFER_MAX_CHUNK_SIZE
            else max_chunk_size
        )

        ### 获取任务与文件基本信息
        with Session() as session:
            # Quota check up front, before opening any file or sending "ready".
            # Skipped for unauthenticated transfers (self.username falsy);
            # any auth-required upload action will have already enforced login.
            if self.username and not check_quota_for_upload(
                session, self.username, file_size
            ):
                self.conclude_request(
                    413,
                    {},
                    "Disk quota exceeded",
                )
                return

            # Query the FileTask table to get the file_id associated with the task_id
            file_task = session.get(FileTask, task_id)
            if not file_task:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if file_task.mode != 1:
                raise ValueError(f"Not a write-mode task: {task_id}")
            if file_task.status != 0:
                raise ValueError(
                    f"File transfer task already completed or cancelled: {task_id}"
                )
            # Query the File table to get the file path associated with the file_id
            file = session.get(File, file_task.file_id)
            if not file:
                raise ValueError(f"File not found for file_id: {file_task.file_id}")

            if file_size == 0:  # 空文件
                self.stream.send("stop")
                ProviderManager().storage.makedirs(
                    os.path.dirname(file.path), exist_ok=True
                )
                ProviderManager().storage.fopen(file.path, "wb").close()
                file.active = True
                if self.username:
                    file.uploaded_by = self.username
                file.stored_size = 0
                session.commit()

                pm.hook.ext_on_empty_file_uploaded(id=file.id, path=file.path)
                return

            self.stream.send(f"ready {chunk_size}")
            try:
                logger.info("Receiving file: transfer started")
                ProviderManager().storage.makedirs(
                    os.path.dirname(file.path), exist_ok=True
                )
                with ProviderManager().storage.fopen(file.path, "wb") as f:
                    try:
                        hasher = hashlib.sha256()
                        while True:
                            # Receive encrypted data from the client
                            data = self.stream.recv().data
                            f.write(data)
                            hasher.update(data)

                            if not data or len(data) < chunk_size:
                                break
                    except (
                        websockets.ConnectionClosed,
                        websockets.exceptions.ConnectionClosedOK,
                    ):
                        raise

                # 校验文件大小
                actual_size = ProviderManager().storage.getsize(file.path)
                if file_size and actual_size != file_size:
                    self.logger.error(
                        f"File size mismatch: expected {file_size}, got {actual_size}"
                    )
                    ProviderManager().storage.remove(file.path)

                    self.conclude_request(
                        400,
                        {},
                        f"File size mismatch: expected {file_size}, got {actual_size}",
                    )
                    return

                # 校验sha256
                if sha256:
                    actual_sha256 = hasher.hexdigest()
                    if actual_sha256 != sha256:
                        self.logger.error(
                            f"SHA256 mismatch: expected {sha256}, got {actual_sha256}"
                        )
                        ProviderManager().storage.remove(file.path)

                        self.conclude_request(
                            400,
                            {},
                            f"SHA256 mismatch: expected {sha256}, got {actual_sha256}",
                        )
                        return

                file_task.status = 1
                file.sha256 = sha256
                file.active = True
                if self.username:
                    file.uploaded_by = self.username
                file.stored_size = actual_size
                session.commit()

                pm.hook.ext_on_file_uploaded(id=file.id, path=file.path, sha256=sha256)

                self.logger.info(
                    f"File received and saved to {file.path}, total size: {actual_size}"
                )

                self.conclude_request(200, {}, "File received successfully")

            except (
                websockets.ConnectionClosed,
                websockets.exceptions.ConnectionClosedError,
                websockets.exceptions.ConnectionClosedOK,
            ):
                raise

            except Exception as e:
                self.report_error(e, context=f"Error receiving file for task {task_id}")
                return

    def broadcast(
        self,
        message: Data,
        raise_exceptions: bool = False,
    ):
        if isinstance(message, (bytes, bytearray, memoryview)):
            message = bytes(message).decode("utf-8")
        elif not isinstance(message, str):
            raise TypeError("data must be str or bytes")

        ProviderManager().event_bus.publish("system:broadcast", message)
