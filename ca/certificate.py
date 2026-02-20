"""
This module provides an abstraction layer for managing certificates within the Vism CA
controller. It handles certificate issuance, signing, and revocation functionalities,
making it easier to interface with the crypto module, CA database, and other components.

Classes:
    Certificate: Represents a certificate and provides methods for operations such as
                 generating, signing, and managing CRLs.
"""
from typing import Self

import pkcs11
from cryptography.x509 import CertificateSigningRequestBuilder, SignatureAlgorithmOID
from pyasn1.type import univ
from pyasn1_modules.rfc2986 import CertificationRequestInfo, Name, SubjectPublicKeyInfo, AlgorithmIdentifier, \
    CertificationRequest
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from ca.database import CertificateEntity
from ca.config import CertificateConfig, ca_logger
from ca.p11 import PKCS11PrivKey, PKCS11PubKey, PKCS11Client
from lib.errors import VismBreakingException

class Certificate:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """
    CSR_VERSION = 0x0
    CSR_SIGN_HASH_ALG = "SHA256"

    def __init__(self, db_entry: CertificateEntity, config: CertificateConfig, p11_client: PKCS11Client, issuer: Self | None):
        self.db_entry = db_entry
        self.config = config
        self.p11_client = p11_client

        self.issuer = issuer

        self.priv_key = PKCS11PrivKey(self.config.key_p11_attributes)
        self.pub_key = PKCS11PubKey(self.config.key_p11_attributes)

    async def _create_csr(self) -> bytes:
        csr_info = CertificationRequestInfo()
        csr_info.setComponentByName("version", self.CSR_VERSION)

        csr_name = Name()
        csr_name.setComponentByName("rdnSequence", self.config.x509.subject_name.to_rdn_seq())
        csr_info.setComponentByName("subject", csr_name)

        pub_key_info = der_decoder(self.pub_key.public_bytes(), asn1Spec=SubjectPublicKeyInfo())
        csr_info.setComponentByName("subjectPKInfo", pub_key_info[0])

        csr = CertificationRequest()
        csr.setComponentByName("certificationRequestInfo", csr_info)

        signature_algorithm = AlgorithmIdentifier()
        if self.priv_key.key_type == pkcs11.KeyType.RSA:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'RSA_WITH_{self.CSR_SIGN_HASH_ALG}').dotted_string
        elif self.priv_key.key_type == pkcs11.KeyType.EC:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'ECDSA_WITH_{self.CSR_SIGN_HASH_ALG}').dotted_string
        else:
            raise NotImplementedError

        signature_algorithm.setComponentByName("algorithm", univ.ObjectIdentifier(algorithm_oid))
        csr.setComponentByName("signatureAlgorithm", signature_algorithm)

        signature_bytes = self.p11_client.sign_csr_info(self.priv_key, der_encoder(csr_info), self.CSR_SIGN_HASH_ALG)
        bit_string = ''.join(f'{byte:08b}' for byte in signature_bytes)
        csr.setComponentByName("signature", bit_string)

        return der_encoder(csr)

    async def create(self) -> None:
        ca_logger.info(f"Creating certificate {self.config.name}")

        self.pub_key, self.priv_key = self.p11_client.generate_keypair(self.pub_key, self.priv_key)

        if self.config.externally_managed:
            if self.config.certificate_pem is None or self.config.crl_pem is None:
                raise VismBreakingException(f"Certificate {self.config.name} is externally managed, but no certificate or CRL was provided in the config.")

            self.db_entry.crt_pem = self.config.certificate_pem
            self.db_entry.crl_pem = self.config.crl_pem
            return

        csr_der = await self._create_csr()

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
            self.db_entry = await self.create()

