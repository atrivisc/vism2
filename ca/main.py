"""Main Vism CA class and entrypoint."""

import asyncio
from datetime import timezone, datetime

import aio_pika
from aio_pika.abc import AbstractRobustChannel, AbstractRobustConnection
from pyasn1_modules import rfc5280
from vism_lib.rabbitmq import RabbitMQClient
from vism_lib.s3 import AsyncS3Client

from ca import CertificateManager
from ca.abc import AsyncCallable, Election
from ca.config import CAConfig, ca_logger, ValidRevocationReasons
from ca.crypto.signer import PKCS11Signer
from ca.crypto.util import asn1_time_to_datetime, csr_pem_to_der, crt_der_to_pem, csr_der_to_pem, \
    crt_der_chain_to_pem_chain
from ca.database import VismCADatabase, CertificateEntity, IssuedCertificate
from ca.p11 import PKCS11Client, PKCS11PrivKey, PKCS11PubKey
from vism_lib.controller import Controller
from vism_lib.data.exchange import DataExchangeCSRMessage, DataExchangeCertMessage
from vism_lib.errors import VismBreakingException, VismException
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.codec.der.decoder import decode as der_decoder

class RabbitMQElection(Election):
    def __init__(self, shutdown_event: asyncio.Event, election_interval: int = 30, *, rabbitmq_client: RabbitMQClient, leader_queue: str):
        self.shutdown_event = shutdown_event
        self.election_interval = election_interval

        self.is_leader = False
        self._leader_queue = leader_queue
        self._rabbitmq_client = rabbitmq_client
        self._rabbitmq_channel: AbstractRobustChannel | None = None
        self._rabbitmq_connection: AbstractRobustConnection | None = None

    async def leader_heartbeat(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        ca_logger.info(f"I am the leader — heartbeat at {now}")

    async def follower_heartbeat(self) -> None:
        ca_logger.info("Nothing to do — I am secondary")

    async def _try_become_leader(self) -> bool:
        try:
            if not self._rabbitmq_connection or self._rabbitmq_connection.is_closed:
                self._rabbitmq_connection = await self._rabbitmq_client.get_connection()
            if not self._rabbitmq_channel or self._rabbitmq_channel.is_closed:
                self._rabbitmq_channel = await self._rabbitmq_connection.channel(on_return_raises=True)

            queue = await self._rabbitmq_channel.declare_queue(
                self._leader_queue,
                exclusive=True,
                auto_delete=True,
                durable=False,
            )

            await queue.consume(self._on_leader_message, no_ack=True)
            self.is_leader = True
            ca_logger.info("Won the election — I am now the leader")
            return True
        except aio_pika.exceptions.ChannelPreconditionFailed:
            return False
        except Exception as e:
            ca_logger.debug(f"Lost election round: {e}")
            if self._rabbitmq_channel and not self._rabbitmq_channel.is_closed:
                await self._rabbitmq_channel.close()
            return False

    async def _on_leader_message(self, *args, **kwargs):
        pass

    async def resign(self, resign_callback: AsyncCallable) -> None:
        if self.is_leader:
            ca_logger.info("Resigning as leader.")
            self.is_leader = False

        if not self._rabbitmq_channel.is_closed:
            await self._rabbitmq_channel.close()
        if not self._rabbitmq_connection.is_closed:
            await self._rabbitmq_connection.close()

        await resign_callback()

    async def run(self, resign_callback: AsyncCallable, leader_callback: AsyncCallable, follower_callback: AsyncCallable):
        try:
            while not self.shutdown_event.is_set():
                if not self.is_leader:
                    won = await self._try_become_leader()
                    if not won:
                        await self.follower_heartbeat()
                        await follower_callback()
                        await asyncio.sleep(self.election_interval)
                    else:
                        await leader_callback()
                else:
                    if self._rabbitmq_channel and self._rabbitmq_channel.is_closed:
                        ca_logger.warning("Lost leader channel — re-entering election")
                        self.is_leader = False
                        continue

                    await self.leader_heartbeat()
                    await asyncio.sleep(self.election_interval)
        except Exception as e:
            ca_logger.error(f"Stopping rabbitmq leadership loop: {e}")
            raise e
        finally:
            await self.resign(resign_callback)

class VismCA(Controller):
    def __init__(
            self,
            config: CAConfig,
            p11_client: PKCS11Client,
            database: VismCADatabase,
            s3_client: AsyncS3Client,
            election: Election,
            *,
            shutdown_event: asyncio.Event = None,
    ):
        if shutdown_event is None:
            shutdown_event = asyncio.Event()

        self.shutdown_event = shutdown_event

        self.config = config
        self.p11_client = p11_client
        self.s3 = s3_client
        self.database = database
        self.election = election

        self.certificates: dict[str, CertificateManager] = {}

        super().__init__(config)

    async def update_crl(self):
        pass

    def revoke_certificate(self, issued_cert: IssuedCertificate, reason: ValidRevocationReasons, *, now: datetime | None = None):
        serial = der_encoder(issued_cert.serial, asn1Spec=rfc5280.CertificateSerialNumber())[0]
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
            crt_der = cert.load_external_cert_der()
            crl_der = cert.load_external_crl_der()

            db_entry.crt_der = crt_der
            db_entry.crl_der = crl_der

        elif issuer_cert and issuer_cert.config.externally_managed:
            if cert.config.certificate_pem and db_entry.crt_der is None:
                crt_der = cert.load_external_cert_der()
                db_entry.crt_der = crt_der

            elif db_entry.crt_der is None and cert.config.certificate_pem is None:
                # Generate CSR for user and display it in logs through error
                # TODO: better method?
                csr = cert.create_csr()
                csr_der = der_encoder(csr)
                csr_pem = csr_der_to_pem(csr_der)
                raise VismException(
                    f"Certificate {cert.config.name} needs to be manually signed "
                    f"by the external issuer {issuer_cert.config.name}. "
                    f"CSR: \n{csr_pem}"
                )

        issuer_asn1_cert = der_decoder(issuer_db_entity.crt_der, asn1Spec=rfc5280.Certificate())[0] if issuer_db_entity.crt_der is not None else None

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

    async def load_certificate_crl(self, cert: CertificateManager, cert_asn1: rfc5280.Certificate, db_entry: CertificateEntity, revoked_certs: list[IssuedCertificate]) -> CertificateEntity:
        if db_entry.crl_der is None:
            ca_logger.info(f"Creating CRL for certificate {cert.config.name}")
            crl = cert.create_crl(cert_asn1, revoked_certs)
            db_entry.crl_der = der_encoder(crl)

        return db_entry

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
            revoked_cert = self.database.get_revoked_certificates_for_issuer(db_entry.id)
            db_entry = await self.load_certificate_crl(cert, der_decoder(db_entry.crt_der, asn1Spec=rfc5280.Certificate())[0], db_entry, revoked_cert)

            await self.save_certificate(cert.config.name, db_entry)

            if issuer_cert is None:
                issuer_cert = cert

            await self.save_certificate(issuer_cert.config.name, issuer_db_entity)

            certificates[cert.config.name] = cert

        return certificates

def main(function: str = None, serial: int | str = None, revoke_reason: ValidRevocationReasons = None):
    """Async entrypoint for the CA."""
    shutdown_event = asyncio.Event()

    config: CAConfig = CAConfig.read_config()
    p11_client = PKCS11Client(config.pkcs11)
    database = VismCADatabase(config.database)
    s3_client = AsyncS3Client(config.s3)
    rabbitmq_client = RabbitMQClient(config.rabbitmq)

    election = RabbitMQElection(
        shutdown_event=shutdown_event,
        election_interval=30,
        rabbitmq_client=rabbitmq_client,
        leader_queue=config.rabbitmq.leader_queue,
    )

    ca = VismCA(
        config=config,
        p11_client=p11_client,
        database=database,
        s3_client=s3_client,
        election=election,
        shutdown_event=shutdown_event,
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
