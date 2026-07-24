"""VISM ACME Controller module for handling ACME protocol operations."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from cryptography import x509
from fastapi import FastAPI
from sqlalchemy import URL, create_engine
from starlette.responses import JSONResponse
from vism_lib.data.validation import DataValidation
from vism_lib.rabbitmq import RabbitMQClient, RabbitMQExchange
from vism_lib.s3 import AsyncS3Client

from acme.config import AcmeConfig, acme_logger
from acme.database import VismAcmeDatabase
from acme.db import OrderEntity, OrderStatus, ErrorEntity
from acme.errors import ACMEProblemResponse
from acme.middleware import AcmeAccountMiddleware, JWSMiddleware
from vism_lib.controller import Controller
from vism_lib.data.exchange import DataExchangeCertMessage, DataExchange
from vism_lib.errors import VismException


class VismACMEController(Controller):
    """Controller class for VISM ACME server operations."""

    def __init__(
            self,
            config: AcmeConfig,
            database: VismAcmeDatabase,
            data_exchange_module: DataExchange,
            s3: AsyncS3Client,
    ):
        super().__init__(config)
        acme_logger.info("Starting VISM ACME server")

        self.config = config
        self.database = database
        self.data_exchange_module = data_exchange_module
        self.s3 = s3

        self.api = FastAPI(lifespan=self.lifespan)
        self.setup_exception_handlers()
        self.setup_middleware()
        self.setup_routes()

        self.ready = False

    async def _get_order_for_csr(self, order_id: str) -> OrderEntity:
        """Get and validate order for CSR processing."""
        order = self.database.get_order_by_id(order_id)

        if order is None:
            raise VismException(f"Order {order_id} not found")

        order_expired = order.status == OrderStatus.EXPIRED
        if not order_expired:
            order_expired = order.expires < datetime.now(tz=timezone.utc)

        if order_expired:
            order.status = OrderStatus.EXPIRED
            self.database.save_to_db(order)
            raise VismException(f"Order {order_id} expired, can not accept certificate")

        if order.status != OrderStatus.PROCESSING:
            order.set_error(ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail=f"Order {order_id} is not in processing state"
            ))
            self.database.save_to_db(order)
            raise VismException(order.error.detail)

        return order

    async def handle_chain_from_ca(self, message: DataExchangeCertMessage):
        order = await self._get_order_for_csr(message.order_id)

        try:
            certificates = x509.load_pem_x509_certificates(message.chain.encode("utf-8"))
        except ValueError as exc:
            error = ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail=str(exc)
            )
            order.set_error(error)
            self.database.save_to_db(order)
            raise VismException(
                f"Failed to load certificates from chain: {exc}"
            ) from exc

        try:
            csr = x509.load_pem_x509_csr(order.csr_pem.encode("utf-8"))
        except ValueError as exc:
            order.set_error(ErrorEntity(
                type="invalidOrder",
                title="Failed to validate csr",
                detail=str(exc)
            ))
            self.database.save_to_db(order)
            raise VismException from exc

        ordered_cert = certificates[0]
        cert_san = ordered_cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        csr_san = csr.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)

        public_key_matches = csr.public_key() == ordered_cert.public_key()
        subject_matches = csr.subject == ordered_cert.subject
        san_matches = csr_san.value == cert_san.value

        if not (public_key_matches and subject_matches and san_matches):
            order.set_error(ErrorEntity(
                type="invalidOrder",
                title="Failed to validate CA csr response",
                detail="CSR and certificate do not match"
            ))
            self.database.save_to_db(order)
            raise VismException(order.error.detail)

        acme_logger.info("Certificate for order %s accepted.", message.order_id)
        order.status = OrderStatus.VALID
        order.crt_pem = message.chain
        self.database.save_to_db(order)

        # Before we exit, run nonce cleanup
        self.database.nonce_cleanup(self.config.nonce_ttl_seconds)

        return None

    @asynccontextmanager
    async def lifespan(self, _api: FastAPI):
        """Manage application lifespan with an async context manager."""
        asyncio.create_task(
            self.data_exchange_module.receive_messages(DataExchangeCertMessage, self.handle_chain_from_ca)
        )
        self.ready = True
        yield
        await asyncio.shield(self.data_exchange_module.cleanup(full=True))

    def setup_middleware(self):
        """Configure middleware for the FastAPI application."""
        self.api.add_middleware(
            AcmeAccountMiddleware,
            jwk_paths=["/new-account", "/revoke-cert"],
            kid_paths=["/account/", "/new-order", "/authz"],
            controller=self,
        )

        self.api.add_middleware(
            JWSMiddleware,
            skip_paths=["/directory", "/new-nonce", "/health"],
            controller=self,
        )

    def setup_exception_handlers(self):
        """Set up exception handlers for the FastAPI application."""
        @self.api.exception_handler(ACMEProblemResponse)
        async def acme_problem_response_handler(_request, exc: ACMEProblemResponse):
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.error_json,
                headers={"Content-Type": "application/problem+json"}
            )

        @self.api.exception_handler(VismException)
        async def vism_exception_handler(_request, _exc: VismException):
            return JSONResponse(
                status_code=500,
                content={
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "title": "An internal server error occurred",
                },
                headers={"Content-Type": "application/problem+json"}
            )

    def setup_routes(self):
        """Set up routes for the FastAPI application."""
        # Import routers here to avoid circular imports
        from acme.routers import AccountRouter  # pylint: disable=import-outside-toplevel
        from acme.routers import BaseRouter  # pylint: disable=import-outside-toplevel
        from acme.routers import OrderRouter  # pylint: disable=import-outside-toplevel
        from acme.routers import AuthzRouter  # pylint: disable=import-outside-toplevel
        from acme.routers import PubRouter  # pylint: disable=import-outside-toplevel

        base_router = BaseRouter(self)
        account_router = AccountRouter(self)
        order_router = OrderRouter(self)
        authz_router = AuthzRouter(self)
        pub_router = PubRouter(self)

        self.api.include_router(account_router.router)
        self.api.include_router(base_router.router)
        self.api.include_router(order_router.router)
        self.api.include_router(authz_router.router)
        self.api.include_router(pub_router.router)

class EndpointFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.args and len(record.args) >= 3 and record.args[2] not in ["/health", "/ready"]

def app() -> FastAPI:
    config = AcmeConfig.read_config()
    validation_module = DataValidation(validation_key=config.security.data_validation_key)

    db_url = URL.create(
        drivername=config.database.driver,
        username=config.database.username,
        password=config.database.password,
        host=config.database.host,
        port=config.database.port,
        database=config.database.database
    )
    db_engine = create_engine(db_url, echo=False, pool_pre_ping=True)
    database = VismAcmeDatabase(engine=db_engine, validation_module=validation_module)

    rabbitmq_client = RabbitMQClient(config.rabbitmq)
    data_exchange_module = RabbitMQExchange(
        validation_module=validation_module,
        rabbitmq_client=rabbitmq_client,
        config=config.rabbitmq
    )

    s3_client = AsyncS3Client(config.s3)

    controller = VismACMEController(
        config=config,
        database=database,
        data_exchange_module=data_exchange_module,
        s3=s3_client
    )

    logging.getLogger("uvicorn.access").addFilter(EndpointFilter())

    return controller.api
