"""Router for ACME base operations."""
from fastapi import APIRouter
from starlette.responses import JSONResponse, Response

from acme.acme import VismACMEController
from acme.config import acme_logger
from acme.routers import AcmeRequest
from vism_lib.util import absolute_url


class BaseRouter:
    """Router for handling ACME base endpoints like directory."""

    def __init__(self, controller: VismACMEController):
        self.controller = controller
        self.router = APIRouter()
        self.router.get("/directory")(self.directory)
        self.router.head("/new-nonce")(self._new_nonce)
        self.router.get("/new-nonce")(self._new_nonce)
        self.router.get("/health")(self.health)
        self.router.get("/ready")(self.ready)

    async def ready(self):
        if self.controller.ready:
            return Response(status_code=200, content="OK")
        else:
            return Response(status_code=503, content="Service not ready")

    @staticmethod
    async def health():
        return Response(status_code=200, content="OK")

    async def _new_nonce(self, request: AcmeRequest):
        """Return new nonce."""
        acme_logger.info("Received request to create new nonce.")
        nonce = self.controller.database.new_nonce().nonce
        status_code = 200 if request.method == "HEAD" else 204
        return Response(
            status_code=status_code,
            headers={
                "Replay-Nonce": nonce,
                "Cache-Control": "no-store",
            }
        )

    async def directory(self, request: AcmeRequest):
        """Return the ACME directory with service endpoints and metadata."""
        dir_obj = {
            "newNonce": absolute_url(request, "/new-nonce"),
            "newAccount": absolute_url(request, "/new-account"),
            "newOrder": absolute_url(request, "/new-order"),
            "revokeCert": absolute_url(request, "/revoke-cert"),
            "keyChange": None
        }
        return JSONResponse(dir_obj)
