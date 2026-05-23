"""Main Vism CA class and entrypoint."""

import asyncio
from datetime import timezone, datetime

from pyasn1_modules import rfc5280
from sqlalchemy import URL, create_engine
from vism_lib.data.validation import DataValidation
from vism_lib.rabbitmq import RabbitMQClient, RabbitMQExchange
from vism_lib.s3 import AsyncS3Client

from ca.abc import Election, KeyManager
from ca.certificate import CertificateManager
from ca.config import CAConfig, ca_logger, ValidRevocationReasons, CertificateConfig
from ca.crypto.util import asn1_time_to_datetime, csr_pem_to_der, crt_der_to_pem, csr_der_to_pem, crt_der_chain_to_pem_chain
from ca.database import VismCADatabase, CertificateEntity, IssuedCertificate
from vism_lib.controller import Controller
from vism_lib.data.exchange import DataExchangeCSRMessage, DataExchangeCertMessage, DataExchange
from vism_lib.errors import VismBreakingException, VismException
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.codec.der.decoder import decode as der_decoder

from ca.rabbitmq_election import RabbitMQElection


class VismCA(Controller):
    def __init__(
            self,
            config: CAConfig,
            key_manager: KeyManager,
            database: VismCADatabase,
            s3_client: AsyncS3Client,
            election: Election,
            data_exchange_module: DataExchange,
            *,
            shutdown_event: asyncio.Event = None,
    ):
        if shutdown_event is None:
            shutdown_event = asyncio.Event()

        self.shutdown_event = shutdown_event

        self.config = config
        self.key_manager = key_manager
        self.s3 = s3_client
        self.database = database
        self.election = election
        self.data_exchange_module = data_exchange_module

        self.certificates: dict[str, CertificateManager] = {}

        super().__init__(config)

    async def update_crl(self):
        pass

    def revoke_certificate(self, issued_cert: IssuedCertificate, reason: ValidRevocationReasons, *, now: datetime | None = None):
        serial = der_decoder(issued_cert.serial, asn1Spec=rfc5280.CertificateSerialNumber())[0]
        serial_int = int(serial)
        ca_logger.info(f"Revoking certificate with the serial: {serial_int} with reason: {reason}")

        if issued_cert.status_flag == "r":
            raise VismBreakingException(f"Certificate {serial} was already revoked")

        issued_cert.status_flag = "r"
        issued_cert.revocation_reason = reason.value
        issued_cert.revocation_date = now or datetime.now(timezone.utc)

        self.database.save_to_db(issued_cert)
        ca_logger.info(f"Revoked certificate: {serial} with reason {reason.value}")

    async def handle_csr_from_acme(self, message: DataExchangeCSRMessage) -> None:
        if message.ca_name not in self.certificates:
            return ca_logger.error(f"Invalid cert order '{message.order_id}': CA {message.ca_name} not found in the certificates list.")

        issuer_manager = self.certificates[message.ca_name]
        issuer_cert_db_entity = self.database.get_cert_by_name(issuer_manager.config.name)
        issuer_cert = der_decoder(issuer_cert_db_entity.crt_der, asn1Spec=rfc5280.Certificate())[0]

        try:
            csr_der_bytes = csr_pem_to_der(message.csr_pem)
        except Exception as e:
            return ca_logger.error(f"Invalid cert order '{message.order_id}': Failed to parse CSR: {e}")

        signed_cert = issuer_manager.sign_csr_der(issuer_cert, csr_der_bytes, message.days, is_ca=False)
        signed_cert_der = der_encoder(signed_cert)
        signed_cert_pem = crt_der_to_pem(signed_cert_der)
        chain = signed_cert_pem + '\n' + self.build_pem_chain(message.ca_name)

        cert_message = DataExchangeCertMessage(
            chain=chain,
            order_id=message.order_id,
            ca_name=message.ca_name,
            days=message.days,
        )

        return await self.data_exchange_module.send_message(cert_message)

    async def leader_run(self):
        await self.s3.create_bucket()
        self.certificates = await self.load_certificates()
        await self.data_exchange_module.receive_messages(DataExchangeCSRMessage, self.handle_csr_from_acme)

    async def follower_run(self):
        if self.data_exchange_module is not None:
            await self.data_exchange_module.cleanup(full=True)

    async def async_shutdown(self):
        if self.data_exchange_module is not None:
            await self.data_exchange_module.cleanup(full=True)

    async def run(self):
        """Entrypoint for the CA. Initializes and manages the CA lifecycle."""
        ca_logger.info("Starting CA")
        try:
            resign_callback = self.async_shutdown
            leader_callback = self.leader_run
            follower_callback = self.follower_run

            await self.election.run(resign_callback, leader_callback, follower_callback)
        except asyncio.CancelledError:
            ca_logger.info("CA shutting down.")
        except Exception as e:
            ca_logger.critical(f"CA encountered a fatal error: {e}")
            raise e
        finally:
            if self.data_exchange_module is not None:
                await self.data_exchange_module.cleanup(full=True)

    def build_pem_chain(self, cert_name: str) -> str:
        ders = self.database.get_chain_ders(cert_name)
        return crt_der_chain_to_pem_chain(ders)

    def _build_certificate_manager(self, cert_config: CertificateConfig) -> CertificateManager:
        pubkey, privkey = self.key_manager.make_key_descriptors(cert_config)
        pubkey, privkey = self.key_manager.generate_or_load_keypair(pubkey, privkey)

        return CertificateManager(
            key_manager=self.key_manager,
            privkey=privkey,
            pubkey=pubkey,
            config=cert_config,
        )

    async def save_certificate(self, cert_name: str, cert_entity: CertificateEntity) -> CertificateEntity:
        cert_entity = self.database.save_to_db(cert_entity)

        if cert_entity.crt_der is not None:
            await self.s3.upload_bytes(cert_entity.crt_der, f"crt/{cert_name}.crt")

        if cert_entity.crl_der is not None:
            await self.s3.upload_bytes(cert_entity.crl_der, f"crl/{cert_name}.crl")

        return cert_entity

    async def load_certificates(self) -> dict[str, CertificateManager]:
        ca_logger.info("Initializing certificates")
        # In this loop we assume certs are configured in signing order
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

            cert = self._build_certificate_manager(cert_config)

            issuer_db_entity, db_entry = await self.load_certificate(cert, db_entry, issuer_cert, issuer_db_entity)
            await self.save_certificate(cert.config.name, db_entry)

            if issuer_cert is None:
                issuer_cert = cert

            await self.save_certificate(issuer_cert.config.name, issuer_db_entity)

            certificates[cert.config.name] = cert

        return certificates

    async def load_certificate(self, cert, db_entry, issuer_cert, issuer_db_entity, *, now: datetime | None = None):
        if issuer_cert is None:
            issuer_cert = cert
        if issuer_db_entity is None:
            issuer_db_entity = db_entry

        if cert.config.externally_managed:
            db_entry.crt_der = cert.load_external_cert_der()
            db_entry.crl_der = cert.load_external_crl_der()
        elif issuer_cert.config.externally_managed:
            if cert.config.certificate_pem and db_entry.crt_der is None:
                db_entry.crt_der = cert.load_external_cert_der()
            elif db_entry.crt_der is None and cert.config.certificate_pem is None:
                csr = cert.create_csr()
                csr_pem = csr_der_to_pem(der_encoder(csr))
                raise VismException(
                    f"Certificate {cert.config.name} needs to be manually signed "
                    f"by the external issuer {issuer_cert.config.name}. CSR:\n{csr_pem}"
                )
        issuer_asn1_cert = (
            der_decoder(issuer_db_entity.crt_der, asn1Spec=rfc5280.Certificate())[0]
            if issuer_db_entity.crt_der is not None else None
        )

        if db_entry.crt_der is None:
            self._issue_cert(cert, issuer_cert, issuer_db_entity, db_entry, issuer_asn1_cert, now=now)

        if db_entry.crl_der is None:
            self._issue_crl(cert, issuer_cert, db_entry, issuer_asn1_cert, now=now)

        return issuer_db_entity, db_entry

    def _issue_cert(self, cert, issuer_cert, issuer_db_entity, db_entry, issuer_asn1_cert, *, now: datetime | None = None):
        ca_logger.info(f"Creating certificate {cert.config.name}, signed by {issuer_cert.config.name}")
        csr = cert.create_csr()
        crt = issuer_cert.sign_csr(issuer_asn1_cert, csr, cert.config.x509.days, is_ca=False, now=now)
        db_entry.crt_der = der_encoder(crt)

        issuer_db_entity.issued_certificates.append(IssuedCertificate(
            status_flag="v",
            expiration_date=asn1_time_to_datetime(crt['tbsCertificate']["validity"]["notAfter"]),
            serial=der_encoder(crt['tbsCertificate']["serialNumber"]),
            subject=der_encoder(crt['tbsCertificate']["subject"]),
            ca=issuer_db_entity,
        ))

    def _issue_crl(self, cert, issuer_cert, db_entry, issuer_asn1_cert, *, now: datetime | None = None):
        ca_logger.info(f"Creating CRL for certificate {cert.config.name}")
        revoked = self.database.get_revoked_certificates_for_issuer(db_entry.id)
        crl = issuer_cert.create_crl(issuer_asn1_cert, revoked, now=now)
        db_entry.crl_der = der_encoder(crl)

def main(function: str = None, serial: int | str = None, revoke_reason: ValidRevocationReasons = None):
    """Async entrypoint for the CA."""
    from ca.p11.client import PKCS11Client

    shutdown_event = asyncio.Event()

    config: CAConfig = CAConfig.read_config()
    validation_module = DataValidation(validation_key=config.security.data_validation_key)

    p11_client = PKCS11Client(config.pkcs11)

    db_url = URL.create(
        drivername=config.database.driver,
        username=config.database.username,
        password=config.database.password,
        host=config.database.host,
        port=config.database.port,
        database=config.database.database
    )
    db_engine = create_engine(db_url, echo=False, pool_pre_ping=True)
    database = VismCADatabase(engine=db_engine, validation_module=validation_module)

    s3_client = AsyncS3Client(config.s3)
    rabbitmq_client = RabbitMQClient(config.rabbitmq)
    data_exchange_module = RabbitMQExchange(
        validation_module=validation_module,
        rabbitmq_client=rabbitmq_client,
        config=config.rabbitmq
    )

    election = RabbitMQElection(
        shutdown_event=shutdown_event,
        election_interval=30,
        rabbitmq_client=rabbitmq_client,
        leader_queue=config.rabbitmq.leader_queue,
    )

    ca = VismCA(
        config=config,
        key_manager=p11_client,
        database=database,
        s3_client=s3_client,
        election=election,
        shutdown_event=shutdown_event,
        data_exchange_module=data_exchange_module,
    )

    try:
        if function is None:
            asyncio.run(ca.run())
        elif function == "update_crl":
            asyncio.run(ca.update_crl())
        elif function == "revoke":
            issued_cert = database.get_issued_certificate_by_serial(serial)
            if issued_cert is None:
                raise VismException(f"Certificate with serial {serial} not found")
            ca.revoke_certificate(issued_cert, revoke_reason)
    except Exception as e:
        ca.shutdown()
        raise e

if __name__ == '__main__':
    main()
