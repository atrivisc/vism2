"""Router for ACME base operations."""
from fastapi import APIRouter
from starlette.responses import JSONResponse, Response

from acme.acme import VismACMEController
from acme.config import acme_logger
from acme.routers import AcmeRequest
from lib.util import absolute_url


class BaseRouter:
    """Router for handling ACME base endpoints like directory."""

    def __init__(self, controller: VismACMEController):
        self.controller = controller
        self.router = APIRouter()
        self.router.get("/directory")(self.directory)
        self.router.head("/new-nonce")(self.new_nonce)
        self.router.get("/new-nonce")(self.new_nonce)

    async def new_nonce(self):
        """Return new nonce."""
        acme_logger.info("Received request to create new nonce.")
        nonce = await self.controller.nonce_manager.new_nonce()
        return Response(status_code=200, headers={"Replay-Nonce": nonce})

    async def directory(self, request: AcmeRequest):
        """Return the ACME directory with service endpoints and metadata."""
        dir_obj = {
            "newNonce": absolute_url(request, "/new-nonce"),
            "newAccount": absolute_url(request, "/new-account"),
            "newOrder": absolute_url(request, "/new-order"),
            "revokeCert": absolute_url(request, "/revoke-cert"),
            "keyChange": None,
            "meta": {
                "profiles": {
                    profile.name: profile.to_dict()
                    for profile in self.controller.config.profiles
                }
            }
        }
        return JSONResponse(dir_obj)
