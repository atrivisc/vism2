"""
This module provides an abstraction layer for managing certificates within the Vism CA
controller. It handles certificate issuance, signing, and revocation functionalities,
making it easier to interface with the crypto module, CA database, and other components.

Classes:
    Certificate: Represents a certificate and provides methods for operations such as
                 generating, signing, and managing CRLs.
"""
from ca.database import CertificateEntity
from ca.config import CertificateConfig, ca_logger
from ca.p11 import PKCS11PrivKey
from ca.p11.key import PKCS11PubKey
from lib.errors import VismBreakingException


class Certificate:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """

    def __init__(self, controller: 'VismCA', config: CertificateConfig):
        self.controller = controller
        self.config = config

        self.priv_key = PKCS11PrivKey(self.config.p11_attributes)
        self.pub_key = PKCS11PubKey(self.config.p11_attributes)

        self._db_entry = None

    @property
    def db_entry(self) -> CertificateEntity:
        if self._db_entry is None:
            db_entry = self.controller.database.get_cert_by_name(self.config.name)
            if db_entry is None:
                db_entry = CertificateEntity(name=self.config.name, externally_managed=self.config.externally_managed)
            self._db_entry = db_entry

        return self._db_entry

    async def create(self) -> CertificateEntity:
        ca_logger.info(f"Creating certificate {self.config.name}")

        if self.config.externally_managed:
            if self.config.certificate_pem is None or self.config.crl_pem is None:
                raise VismBreakingException(f"Certificate {self.config.name} is externally managed, but no certificate or CRL was provided in the config.")

            self.db_entry.crt_pem = self.config.certificate_pem
            self.db_entry.crl_pem = self.config.crl_pem
            return self.controller.database.save_to_db(self.db_entry)

        self.controller.p11_client.generate_keypair(self.priv_key, self.pub_key)
        if self.config.signed_by is None:
            pass


    async def save_to_db(self):
        if not self.controller.s3_client.exists(f"crt/{self.config.name}.crt"):
            await self.controller.s3_client.upload_bytes(self.db_entry.crt_pem.encode("utf-8"), f"crt/{self.config.name}.crt")

        if not self.controller.s3_client.exists(f"crl/{self.config.name}.crl"):
            await self.controller.s3_client.upload_bytes(self.db_entry.crl_pem.encode("utf-8"), f"crl/{self.config.name}.crl")



    async def load(self):
        ca_logger.info(f"Loading certificate {self.config.name}")

        if self.db_entry is None or self.db_entry.crt_pem is None:
            self._db_entry = await self.create()

