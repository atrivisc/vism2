"""Main Vism CA class and entrypoint."""

import asyncio

from ca.certificate import Certificate
from ca.config import CAConfig, ca_logger
from ca.database import VismCADatabase
from ca.p11 import PKCS11Client
from lib.controller import Controller
from lib.errors import VismBreakingException

class VismCA(Controller):
    """
    Handles the operations and configuration for a CA within the Vism framework.

    Provides functionality to initialize and manage certificates, update Certificate Revocation
    Lists (CRLs), and handle shutdown. The class integrates configuration and database
    models specific to the CA and allows periodic or event-driven tasks related to CA operation.

    :ivar databaseClass: The database class to be used for CA operations.
    :type databaseClass: Type[Database]
    :ivar configClass: The configuration class for the CA.
    :type configClass: Type[Config]
    """

    databaseClass = VismCADatabase
    configClass = CAConfig

    def __init__(self):
        super().__init__()
        self.certificates: dict[str, Certificate] = {}
        self.p11_client = PKCS11Client(self.config.pkcs11)

    # async def update_crl(self):
    #     """Updates CRLs for all certificates managed by the CA."""
    #     ca_logger.info("Updating CRLs for internally managed certificates")
    #     for cert_config in self.config.x509_certificates:
    #         if cert_config.externally_managed:
    #             continue
    #
    #         cert = Certificate(self, cert_config.name)
    #         await cert.update_crl()
    #
    # async def run(self):
    #     """Entrypoint for the CA. Initializes and manages the CA lifecycle."""
    #     ca_logger.info("Starting CA")
    #     try:
    #         await self.init_certificates()
    #         await self.data_exchange_module.receive_csr()
    #         await self._shutdown_event.wait()
    #     except asyncio.CancelledError:
    #         ca_logger.info("CA shutting down.")
    #     except Exception as e:
    #         ca_logger.critical(f"CA encountered a fatal error: {e}")
    #         raise e
    #     finally:
    #         await asyncio.shield(self.data_exchange_module.cleanup(full=True))
    #
    # async def init_certificates(self):
    #     """Creates and manages certificates for the CA."""
    #     ca_logger.info("Initializing certificates")
    #     for cert_config in self.config.x509_certificates:
    #         cert = None
    #         try:
    #             cert = Certificate(self, cert_config.name)
    #             await cert.create()
    #             await cert.update_crl()
    #             ca_logger.info("Done loading certificate '%s'", cert_config.name)
    #             cert.cleanup()
    #         except Exception as e:
    #             if cert is not None:
    #                 cert.cleanup()
    #             raise VismBreakingException(
    #                 f"Failed to create CA certificate '{cert_config.name}': {e}"
    #             ) from e

def main(function: str = None):
    """Async entrypoint for the CA."""
    ca = VismCA()
    try:
        if function is None:
            asyncio.run(ca.run())
        if function == "update_crl":
            asyncio.run(ca.update_crl())
    except KeyboardInterrupt:
        ca.shutdown()

if __name__ == '__main__':
    main()
