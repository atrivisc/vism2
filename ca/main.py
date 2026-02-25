"""Main Vism CA class and entrypoint."""

import asyncio
import json
from datetime import timezone, datetime

from aio_pika.abc import AbstractIncomingMessage
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.type import useful

from ca import Certificate
from ca.asn1 import get_ans1_time
from ca.config import CAConfig, ca_logger, ValidRevocationReasons
from ca.database import VismCADatabase
from ca.p11 import PKCS11Client
from lib.controller import Controller
from lib.data.exchange import DataExchangeCSRMessage, DataExchangeCertMessage
from lib.errors import VismBreakingException
from lib.s3 import AsyncS3Client
from pyasn1.codec.der.encoder import encode as der_encoder


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
    database: VismCADatabase
    config: CAConfig

    def __init__(self):
        super().__init__()
        self.certificates: dict[str, Certificate] = {}
        self.p11_client = PKCS11Client(self.config.pkcs11)
        self.s3_client = AsyncS3Client(self.config.s3)

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
    async def update_crl(self):
        pass

    async def revoke_certificates(self, serial: int | str, reason: ValidRevocationReasons):
        ca_logger.info(f"Revoking certificate with the serial: {serial} with reason: {reason}")
        issued_certificate = self.database.get_issued_certificate_by_serial(serial)
        if issued_certificate is None:
            raise VismBreakingException(f"There is no issued certificate with the serial: {serial}")

        if issued_certificate.status_flag == "r":
            raise VismBreakingException(f"Certificate {serial} was already revoked")

        issued_certificate.status_flag = "r"
        issued_certificate.revocation_reason = reason.value
        issued_certificate.revocation_date = der_encoder(get_ans1_time(datetime.now(timezone.utc)))

        self.database.save_to_db(issued_certificate)
        ca_logger.info(f"Revoked certificate: {serial} with reason {reason.value}")

    async def handle_csr_from_acme(self, message: AbstractIncomingMessage) -> DataExchangeCertMessage:
        csr_message = DataExchangeCSRMessage(**json.loads(message.body))
        csr_der_bytes = x509.load_pem_x509_csr(csr_message.csr_pem.encode("utf-8")).public_bytes(serialization.Encoding.DER)

        issuer = self.certificates[csr_message.ca_name]
        signed_cert_der = await issuer.sign_csr(csr_der_bytes, csr_message.days)
        signed_cert_pem = x509.load_der_x509_certificate(signed_cert_der).public_bytes(serialization.Encoding.PEM).decode("utf-8")

        chain = signed_cert_pem + '\n' + issuer.pem_chain

        cert_message = DataExchangeCertMessage(
            chain=chain,
            order_id=csr_message.order_id,
            ca_name=csr_message.ca_name,
            days=csr_message.days,
            original_signature=message.headers["X-Vism-Signature"],
        )

        return cert_message

    async def run(self):
        """Entrypoint for the CA. Initializes and manages the CA lifecycle."""
        ca_logger.info("Starting CA")
        try:
            await self.setup_data_exchange_module()
            await self.init_certificates()
            await self.data_exchange_module.receive_csr()
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            ca_logger.info("CA shutting down.")
        except Exception as e:
            ca_logger.critical(f"CA encountered a fatal error: {e}")
            raise e
        finally:
            await asyncio.shield(self.data_exchange_module.cleanup(full=True))

    async def init_certificates(self):
        ca_logger.info("Initializing certificates")
        for cert_config in self.config.x509_certificates:
            issuer = None
            if cert_config.signed_by is not None:
                issuer = self.certificates[cert_config.signed_by]

            cert = Certificate(self, cert_config, issuer)
            await cert.load()

            self.certificates[cert.config.name] = cert


def main(function: str = None, serial: int | str = None, revoke_reason: ValidRevocationReasons = None):
    """Async entrypoint for the CA."""
    ca = VismCA()
    try:
        if function is None:
            asyncio.run(ca.run())
        if function == "update_crl":
            asyncio.run(ca.update_crl())
        if function == "revoke":
            asyncio.run(ca.revoke_certificates(serial, revoke_reason))
    except KeyboardInterrupt:
        ca.shutdown()

if __name__ == '__main__':
    main()
