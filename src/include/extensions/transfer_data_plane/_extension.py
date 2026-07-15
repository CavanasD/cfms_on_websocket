from include.domains.transfers.consumer import start_transfer_completion_consumer
from include.domains.transfers.handlers import (
    RequestGetTransferStatusHandler,
    RequestPrepareDownloadHandler,
    RequestPrepareUploadHandler,
)
from include.domains.transfers.settings import get_transfer_settings
from include.extensions.manager import hookimpl


@hookimpl
def ext_register_handlers():
    start_transfer_completion_consumer()
    return {
        "prepare_upload": RequestPrepareUploadHandler,
        "prepare_download": RequestPrepareDownloadHandler,
        "get_transfer_status": RequestGetTransferStatusHandler,
    }


@hookimpl
def ext_register_extension_flags():
    if not get_transfer_settings().enabled:
        return set()
    return {"http_transfer", "resume_upload"}
