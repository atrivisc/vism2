"""Main Vism CA class and entrypoint."""

import asyncio
from datetime import timezone, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1_modules import rfc5280

from ca import CertificateManager
from ca.config import CAConfig, ca_logger, ValidRevocationReasons
from ca.crypto.signer import PKCS11Signer
from ca.crypto.util import asn1_time_to_datetime
from ca.database import VismCADatabase, CertificateEntity, IssuedCertificate
from ca.p11 import PKCS11Client, PKCS11PrivKey, PKCS11PubKey
from vism_lib.controller import Controller
from vism_lib.data.exchange import DataExchangeCSRMessage, DataExchangeCertMessage
from vism_lib.errors import VismBreakingException, VismException
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.codec.der.decoder import decode as der_decoder


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

    def __init__(self, p11_client: PKCS11Client = None):
        super().__init__()
        self.certificates: dict[str, CertificateManager] = {}

        self.p11_client = p11_client or PKCS11Client(self.config.pkcs11)

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
        issued_certificate.revocation_date = datetime.now(timezone.utc)

        self.database.save_to_db(issued_certificate)
        ca_logger.info(f"Revoked certificate: {serial} with reason {reason.value}")

    async def handle_csr_from_acme(self, message: DataExchangeCSRMessage) -> None:
        if message.ca_name not in self.certificates:
            return ca_logger.error(f"Invalid cert order '{message.order_id}': CA {message.ca_name} not found in the certificates list.")

        try:
            csr_der_bytes = x509.load_pem_x509_csr(message.csr_pem.encode("utf-8")).public_bytes(serialization.Encoding.DER)
        except Exception as e:
            return ca_logger.error(f"Invalid cert order '{message.order_id}': Failed to parse CSR: {e}")

        issuer_manager = self.certificates[message.ca_name]
        issuer_cert_db_entity = self.database.get_cert_by_name(issuer_manager.config.name)
        issuer_cert = der_decoder(issuer_cert_db_entity.crt_der, asn1Spec=rfc5280.Certificate())[0]

        signed_cert = issuer_manager.sign_csr_der(issuer_cert, csr_der_bytes, message.days, is_ca=False)
        signed_cert_der = der_encoder(signed_cert)
        signed_cert_pem = x509.load_der_x509_certificate(signed_cert_der).public_bytes(serialization.Encoding.PEM).decode("utf-8")
        chain = signed_cert_pem + '\n' + self.build_pem_chain(message.ca_name)

        cert_message = DataExchangeCertMessage(
            chain=chain,
            order_id=message.order_id,
            ca_name=message.ca_name,
            days=message.days,
        )

        return await self.data_exchange_module.send_cert(cert_message)

    async def leader_run(self):
        await self.s3.create_bucket()

        self.certificates = await self.load_certificates()

        await self.data_exchange_module.receive_csr(callback=self.handle_csr_from_acme)

    async def follower_run(self):
        if self.data_exchange_module is not None:
            await self.data_exchange_module.cleanup(full=False)

    async def async_shutdown(self):
        if self.data_exchange_module is not None:
            await self.data_exchange_module.cleanup(full=False)

    async def run(self):
        """Entrypoint for the CA. Initializes and manages the CA lifecycle."""
        ca_logger.info("Starting CA")
        try:
            resign_callback = self.async_shutdown
            leader_callback = self.leader_run
            follower_callback = self.follower_run

            await self.setup_data_exchange_module()
            await self.elect_leader_loop(resign_callback, leader_callback, follower_callback)
        except asyncio.CancelledError:
            ca_logger.info("CA shutting down.")
        except Exception as e:
            ca_logger.critical(f"CA encountered a fatal error: {e}")
            raise e
        finally:
            if self.data_exchange_module is not None:
                await self.data_exchange_module.cleanup(full=True)

    def build_pem_chain(self, cert_name: str) -> str:
        cert_entity = self.database.get_cert_by_name(cert_name)
        if cert_entity is None:
            raise VismException(f"Certificate {cert_name} not found in the database.")

        chain = ""
        while cert_entity is not None:
            if cert_entity.crt_der is None:
                raise VismException(f"Certificate {cert_name} has no crt_der in the database.")

            chain += x509.load_der_x509_certificate(cert_entity.crt_der).public_bytes(serialization.Encoding.PEM).decode("utf-8") + '\n'
            if cert_entity.signer is None:
                break

            cert_entity = cert_entity.signer

        return chain

    async def save_certificate(self, cert_name: str, cert_entity: CertificateEntity) -> CertificateEntity:
        cert_entity = self.database.save_to_db(cert_entity)

        if cert_entity.crt_der is not None:
            await self.s3.upload_bytes(cert_entity.crt_der, f"crt/{cert_name}.crt")

        if cert_entity.crl_der is not None:
            await self.s3.upload_bytes(cert_entity.crl_der, f"crl/{cert_name}.crl")

        return cert_entity

    async def load_certificate(
            self,
            cert: CertificateManager,
            db_entry: CertificateEntity,
            issuer_cert: CertificateManager | None,
            issuer_db_entity: CertificateEntity | None
    ) -> tuple[CertificateEntity, CertificateEntity]:
        if issuer_cert is None:
            issuer_cert = cert

        if issuer_db_entity is None:
            issuer_db_entity = db_entry

        if cert.config.externally_managed:
            crt_der = x509.load_pem_x509_certificate(cert.config.certificate_pem.encode("utf-8")).public_bytes(encoding=serialization.Encoding.DER)
            crl_der = x509.load_pem_x509_crl(cert.config.crl_pem.encode("utf-8")).public_bytes(encoding=serialization.Encoding.DER)

            db_entry.crt_der = crt_der
            db_entry.crl_der = crl_der

        elif issuer_cert and issuer_cert.config.externally_managed:
            if cert.config.certificate_pem and db_entry.crt_der is None:
                crt_der = x509.load_pem_x509_certificate(cert.config.certificate_pem.encode("utf-8")).public_bytes(encoding=serialization.Encoding.DER)
                db_entry.crt_der = crt_der

            elif db_entry.crt_der is None and cert.config.certificate_pem is None:
                # Generate CSR for user and display it in logs through error
                # TODO: better method?
                csr = cert.create_csr()
                csr_der = der_encoder(csr)
                csr_pem = x509.load_der_x509_csr(csr_der).public_bytes(serialization.Encoding.PEM).decode("utf-8")
                raise VismException(
                    f"Certificate {cert.config.name} needs to be manually signed "
                    f"by the external issuer {issuer_cert.config.name}. "
                    f"CSR: \n{csr_pem}"
                )

        issuer_asn1_cert = der_decoder(issuer_db_entity.crt_der, asn1Spec=rfc5280.Certificate())[0]
        issuing_cert = issuer_cert or cert
        if db_entry.crt_der is None:
            ca_logger.info(f"Creating certificate {cert.config.name}, signed by {issuing_cert.config.name}")
            csr = cert.create_csr()
            crt = issuing_cert.sign_csr(issuer_asn1_cert, csr, cert.config.x509.days, is_ca=False)
            db_entry.crt_der = der_encoder(crt)

            issued_certificate = IssuedCertificate(
                status_flag="v",
                expiration_date=asn1_time_to_datetime(crt['tbsCertificate']["validity"]["notAfter"]),
                serial=der_encoder(crt['tbsCertificate']["serialNumber"]),
                subject=der_encoder(crt['tbsCertificate']["subject"]),
                ca=issuer_db_entity
            )

            issuer_db_entity.issued_certificates.append(issued_certificate)

        if db_entry.crl_der is None:
            ca_logger.info(f"Creating CRL for certificate {cert.config.name}")
            crl = issuing_cert.create_crl(issuer_asn1_cert, self.database.get_revoked_certificates_for_issuer(db_entry.id))
            db_entry.crl_der = der_encoder(crl)

        return issuer_db_entity, db_entry

    async def load_certificates(self) -> dict[str, CertificateManager]:
        ca_logger.info("Initializing certificates")
        # In this loop we assume certs are defined in signing order
        # TODO: dont assume and figure out the order?
        certificates: dict[str, CertificateManager] = {}

        for cert_config in self.config.x509_certificates:
            if cert_config.signed_by is not None and cert_config.signed_by not in certificates:
                raise VismException(f"Certificate {cert_config.name} is signed by {cert_config.signed_by} which is not defined in the config before {cert_config.signed_by}.")

            issuer_cert = None
            issuer_db_entity = None

            if cert_config.signed_by is not None:
                issuer_cert = certificates[cert_config.signed_by]
                issuer_db_entity = self.database.get_cert_by_name(issuer_cert.config.name)

            db_entry = self.database.get_cert_by_name(cert_config.name)
            if db_entry is None:
                db_entry = CertificateEntity(
                    name=cert_config.name,
                    externally_managed=cert_config.externally_managed,
                    signer=issuer_db_entity
                )

            privkey = PKCS11PrivKey(cert_config.key_p11_attributes)
            pubkey = PKCS11PubKey(cert_config.key_p11_attributes, cert_config.key.curve)
            pubkey, privkey = self.p11_client.generate_or_load_keypair(pubkey, privkey)

            cert = CertificateManager(
                signer=PKCS11Signer(self.p11_client, privkey),
                config=cert_config,
                public_key_bytes=pubkey.public_bytes(),
            )

            issuer_db_entity, db_entry = await self.load_certificate(cert, db_entry, issuer_cert, issuer_db_entity)

            await self.save_certificate(cert.config.name, db_entry)

            if issuer_cert is None:
                issuer_cert = cert

            await self.save_certificate(issuer_cert.config.name, issuer_db_entity)

            certificates[cert.config.name] = cert

        return certificates

def main(function: str = None, serial: int | str = None, revoke_reason: ValidRevocationReasons = None):
    """Async entrypoint for the CA."""
    ca = VismCA()
    try:
        if function is None:
            asyncio.run(ca.run())
        elif function == "update_crl":
            asyncio.run(ca.update_crl())
        elif function == "revoke":
            asyncio.run(ca.revoke_certificates(serial, revoke_reason))
    except Exception as e:
        ca.shutdown()
        raise e

if __name__ == '__main__':
    main()
