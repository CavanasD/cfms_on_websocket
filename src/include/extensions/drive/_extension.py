from include.domains.drive.handlers import (
    RequestCreateShareLinkHandler,
    RequestGetQuotaHandler,
    RequestListShareLinksHandler,
    RequestPrepareShareDownloadHandler,
    RequestRegisterHandler,
    RequestRevokeShareLinkHandler,
)
from include.extensions.manager import hookimpl


@hookimpl
def ext_register_handlers():
    return {
        "register": RequestRegisterHandler,
        "get_quota": RequestGetQuotaHandler,
        "create_share_link": RequestCreateShareLinkHandler,
        "list_share_links": RequestListShareLinksHandler,
        "revoke_share_link": RequestRevokeShareLinkHandler,
        "prepare_share_download": RequestPrepareShareDownloadHandler,
    }


@hookimpl
def ext_register_whitelisted_actions():
    return {"register"}
