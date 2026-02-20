"""
This module provides an abstraction layer for managing certificates within the Vism CA
controller. It handles certificate issuance, signing, and revocation functionalities,
making it easier to interface with the crypto module, CA database, and other components.

Classes:
    Certificate: Represents a certificate and provides methods for operations such as
                 generating, signing, and managing CRLs.
"""
import hashlib
import random
from datetime import datetime, timedelta
from typing import Self

import pkcs11
from cryptography import x509
from cryptography.x509 import CertificateSigningRequestBuilder, SignatureAlgorithmOID
from pyasn1.type import univ, useful
from pyasn1_modules.rfc2986 import CertificationRequestInfo, Name, SubjectPublicKeyInfo, AlgorithmIdentifier, \
    CertificationRequest
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules.rfc5280 import TBSCertificate, CertificateSerialNumber, Validity, Time, UniqueIdentifier, \
    Extensions, Extension

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
    CERT_VERSION = 0x2
    CSR_SIGN_HASH_ALG = "SHA256"

    def __init__(self, db_entry: CertificateEntity, config: CertificateConfig, p11_client: PKCS11Client, issuer: Self | None):
        self.db_entry = db_entry
        self.config = config
        self.p11_client = p11_client

        self.issuer = issuer

        self.priv_key = PKCS11PrivKey(self.config.key_p11_attributes)
        self.pub_key = PKCS11PubKey(self.config.key_p11_attributes)

    @property
    def signature_algorithm_oid(self) -> str:
        if self.priv_key.key_type == pkcs11.KeyType.RSA:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'RSA_WITH_{self.CSR_SIGN_HASH_ALG}').dotted_string
        elif self.priv_key.key_type == pkcs11.KeyType.EC:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'ECDSA_WITH_{self.CSR_SIGN_HASH_ALG}').dotted_string
        else:
            raise NotImplementedError

        return algorithm_oid

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
        signature_algorithm.setComponentByName("algorithm", univ.ObjectIdentifier(self.signature_algorithm_oid))
        csr.setComponentByName("signatureAlgorithm", signature_algorithm)

        signature_bytes = self.p11_client.sign_csr_info(self.priv_key, der_encoder(csr_info), self.CSR_SIGN_HASH_ALG)
        bit_string = ''.join(f'{byte:08b}' for byte in signature_bytes)
        csr.setComponentByName("signature", bit_string)

        return der_encoder(csr)

    async def _sign_csr(self, csr_der: bytes, days: int):
        csr: CertificationRequest = der_decoder(csr_der, asn1Spec=CertificationRequest())[0]
        csr_info = csr.getComponentByName("certificationRequestInfo")

        tbs_cert = TBSCertificate()
        tbs_cert.setComponentByName("version", self.CERT_VERSION)

        ### Serial ###
        serial = random.getrandbits(159)
        tbs_cert.setComponentByName("serialNumber", CertificateSerialNumber(serial))

        ### Signature ###
        signature_algorithm = AlgorithmIdentifier()
        signature_algorithm.setComponentByName("algorithm", univ.ObjectIdentifier(self.signature_algorithm_oid))
        tbs_cert.setComponentByName("signature", signature_algorithm)

        ### Issuer ###
        issuer_name = Name()
        issuer_name.setComponentByName("rdnSequence", self.config.x509.subject_name.to_rdn_seq())
        tbs_cert.setComponentByName("issuer", issuer_name)

        ### Validity ###
        validity = Validity()
        not_before = Time()
        not_before_time = datetime.now() - timedelta(hours=1)

        not_before_utc_time = useful.UTCTime.fromDateTime(not_before_time)
        not_before_generalized_time = useful.GeneralizedTime.fromDateTime(not_before_time)

        if not_before_time.year > 2049:
            not_before.setComponentByName("generalTime", not_before_generalized_time)
        else:
            not_before.setComponentByName("utcTime", not_before_utc_time)

        not_after = Time()

        not_after_time = datetime.now() + timedelta(days=days)
        not_after_utc_time = useful.UTCTime.fromDateTime(not_after_time)
        not_after_generalized_time = useful.GeneralizedTime.fromDateTime(not_after_time)

        if not_after_time.year > 2049:
            not_after.setComponentByName("generalTime", not_after_generalized_time)
        else:
            not_after.setComponentByName("utcTime", not_after_utc_time)

        validity.setComponentByName("notBefore", not_before)
        validity.setComponentByName("notAfter", not_after)
        tbs_cert.setComponentByName("validity", validity)

        ### Subject ###
        tbs_cert.setComponentByName("subject", csr_info.getComponentByName("subject"))

        ### Subject public key info ###
        tbs_cert.setComponentByName("subjectPublicKeyInfo", csr_info.getComponentByName("subjectPKInfo"))

        ### Issuer Unique ID ###
        # id_bitstring = ''.join(f'{byte:08b}' for byte in self.priv_key.id)
        # tbs_cert.setComponentByName("issuerUniqueID", UniqueIdentifier(id_bitstring))

        ### Extensions ###
        extensions = Extensions()

        ### Subject Key Identifier ###
        skid_extension = Extension()
        skid_extension.setComponentByName("extnID", x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string)

        subject_pub_key_bitstring = csr_info.getComponentByName("subjectPKInfo").getComponentByName("subjectPublicKey")
        skid = hashlib.sha1(subject_pub_key_bitstring.asOctets()).digest()
        skid_extension.setComponentByName("extnValue", univ.OctetString(skid))

        extensions.append(skid_extension)

        ### Authority Key Identifier ###
        akid_extension = Extension()
        akid_extension.setComponentByName("extnID", x509.OID_AUTHORITY_KEY_IDENTIFIER.dotted_string)

        issuer_pub_key_bytes = self.pub_key.public_bytes()
        akid = hashlib.sha1(issuer_pub_key_bytes).digest()
        akid_extension.setComponentByName("extnValue", univ.OctetString(akid))

        extensions.append(akid_extension)

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
            await self._sign_csr(csr_der, 900)

    async def save_to_db(self):
        if not self.controller.s3_client.exists(f"crt/{self.config.name}.crt"):
            await self.controller.s3_client.upload_bytes(self.db_entry.crt_pem.encode("utf-8"), f"crt/{self.config.name}.crt")

        if not self.controller.s3_client.exists(f"crl/{self.config.name}.crl"):
            await self.controller.s3_client.upload_bytes(self.db_entry.crl_pem.encode("utf-8"), f"crl/{self.config.name}.crl")



    async def load(self):
        ca_logger.info(f"Loading certificate {self.config.name}")

        if self.db_entry is None or self.db_entry.crt_pem is None:
            self.db_entry = await self.create()

