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
from datetime import datetime, timedelta, timezone
from typing import Self

import pkcs11
from cryptography import x509
from cryptography.x509 import SignatureAlgorithmOID
from cryptography.x509.certificate_transparency import SignatureAlgorithm
from pyasn1.type import univ, useful, tag, char
from pyasn1.type.base import Asn1Item
from pyasn1_modules.rfc2985 import SingleAttribute, ExtensionRequest, AttributeValues
from pyasn1_modules.rfc2986 import CertificationRequestInfo, Name, SubjectPublicKeyInfo, AlgorithmIdentifier, \
    CertificationRequest, AttributeType, Attributes
from pyasn1.codec.native.decoder import decode as dict_decoder
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules.rfc5280 import TBSCertificate, CertificateSerialNumber, Validity, Time, \
    Extensions, Extension, Certificate as ANS1Certificate

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
    CRT_SIGN_HASH_ALG = "SHA256"

    def __init__(self, db_entry: CertificateEntity, config: CertificateConfig, p11_client: PKCS11Client, issuer: Self | None):
        self.db_entry = db_entry
        self.config = config
        self.p11_client = p11_client

        self.issuer = issuer

        self.priv_key = PKCS11PrivKey(self.config.key_p11_attributes)
        self.pub_key = PKCS11PubKey(self.config.key_p11_attributes, self.config.key.curve)

    def _signature_algorithm_oid(self, hash_algorithm_name: str) -> str:
        if self.priv_key.key_type == pkcs11.KeyType.RSA:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'RSA_WITH_{hash_algorithm_name}').dotted_string
        elif self.priv_key.key_type == pkcs11.KeyType.EC:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'ECDSA_WITH_{hash_algorithm_name}').dotted_string
        else:
            raise NotImplementedError

        return algorithm_oid

    async def _sign_object(self, obj: Asn1Item, hash_algorithm_name: str) -> tuple[AlgorithmIdentifier, univ.BitString]:
        signature_algorithm_dict = {
            "algorithm": univ.ObjectIdentifier(self._signature_algorithm_oid(hash_algorithm_name))
        }

        signature_algorithm = dict_decoder(signature_algorithm_dict, asn1Spec=AlgorithmIdentifier())
        signature_bytes = self.p11_client.sign_data(self.priv_key, der_encoder(obj), hash_algorithm_name)
        bit_string = univ.BitString(''.join(f'{byte:08b}' for byte in signature_bytes))

        return signature_algorithm, bit_string

    async def _create_csr(self) -> bytes:
        attributes = Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        ext_req_attribute = SingleAttribute()
        ext_req_attribute_val = AttributeValues()

        csr_extensions = [
            self.config.x509.basic_constraints,
            self.config.x509.key_usage,
            self.config.x509.extended_key_usage,
            self.config.x509.subject_alternative_name,
            self.config.x509.authority_info_access,
            self.config.x509.crl_distribution_points
        ]

        for ext in csr_extensions:
            if ext is not None:
                ext_req_attribute_val.append(ext.to_asn1_ext())

        ext_req_attribute["type"] = univ.ObjectIdentifier("1.2.840.113549.1.9.14")
        ext_req_attribute['values'] = ext_req_attribute_val

        attributes.append(ext_req_attribute)

        csr_info = CertificationRequestInfo()
        csr_info["version"] = self.CSR_VERSION
        csr_info['subject'] = self.config.x509.subject_name.to_asn1()
        csr_info['subjectPKInfo'] = der_decoder(self.pub_key.public_bytes(), asn1Spec=SubjectPublicKeyInfo())[0]
        csr_info['attributes'] = attributes

        csr = CertificationRequest()
        csr.setComponentByName("certificationRequestInfo", csr_info)

        signature_algorithm, signature = await self._sign_object(csr_info, self.CRT_SIGN_HASH_ALG)
        csr.setComponentByName("signatureAlgorithm", signature_algorithm)
        csr.setComponentByName("signature", signature)

        return der_encoder(csr)

    def _get_ans1_time(self, dt: datetime) -> Time:
        time = Time()

        if dt.year > 2049:
            time["generalTime"] = useful.GeneralizedTime.fromDateTime(dt)
        else:
            time["utcTime"] = useful.UTCTime.fromDateTime(dt)

        return time

    async def _sign_csr(self, csr_der: bytes, days: int):
        csr: CertificationRequest = der_decoder(csr_der, asn1Spec=CertificationRequest())[0]
        csr_info = csr.getComponentByName("certificationRequestInfo")

        tbs_cert = TBSCertificate()

        ### Signature ###
        signature_algorithm = AlgorithmIdentifier()
        signature_algorithm_oid = univ.ObjectIdentifier(self._signature_algorithm_oid(self.CSR_SIGN_HASH_ALG))
        signature_algorithm["algorithm"] = signature_algorithm_oid

        ### Validity ###
        validity = Validity()

        now = datetime.now(timezone.utc)

        not_before_time = now - timedelta(hours=1)
        not_after_time = now + timedelta(days=days)

        validity["notBefore"] = self._get_ans1_time(not_before_time)
        validity["notAfter"] = self._get_ans1_time(not_after_time)

        ### Extensions ###
        extensions = Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        ### Subject Key Identifier ###
        skid_extension = Extension()
        skid_extension["extnID"] = x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string

        subject_pub_key_bitstring = csr_info.getComponentByName("subjectPKInfo").getComponentByName("subjectPublicKey")
        skid = hashlib.sha1(subject_pub_key_bitstring.asOctets()).hexdigest().upper()
        skid_string = ":".join(skid[i:i+2] for i in range(0, len(skid), 2))
        skid_extension["extnValue"] = univ.OctetString(skid_string)

        ### Authority Key Identifier ###
        akid_extension = Extension()
        akid_extension.setComponentByName("extnID", x509.OID_AUTHORITY_KEY_IDENTIFIER.dotted_string)

        issuer_pub_key_bytes = self.pub_key.public_bytes()
        akid = hashlib.sha1(issuer_pub_key_bytes).hexdigest().upper()
        akid_string = ":".join(akid[i:i+2] for i in range(0, len(akid), 2))
        akid_extension["extnValue"] = univ.OctetString(akid_string)

        ### Requested Extensions ###
        csr_attributes: Attributes = csr_info.getComponentByName("attributes")
        ext_req_attr = next(filter(lambda attr: attr['type'] == univ.ObjectIdentifier("1.2.840.113549.1.9.14"), csr_attributes), None)
        if ext_req_attr:
            requested_extensions = ext_req_attr['values']
            for ext_oct in requested_extensions:
                ext = der_decoder(ext_oct, asn1Spec=Extension())[0]
                extensions.append(ext)

        extensions.append(akid_extension)
        extensions.append(skid_extension)

        tbs_cert["version"] = self.CERT_VERSION
        tbs_cert["serialNumber"] = CertificateSerialNumber(random.getrandbits(159))
        tbs_cert["signature"] = signature_algorithm
        tbs_cert["issuer"] = self.config.x509.subject_name.to_asn1()
        tbs_cert["validity"] = validity
        tbs_cert["subject"] = csr_info.getComponentByName("subject")
        tbs_cert["subjectPublicKeyInfo"] = csr_info.getComponentByName("subjectPKInfo")
        tbs_cert["extensions"] = extensions

        ### Certificate ###
        signature_algorithm, signature = await self._sign_object(tbs_cert, self.CRT_SIGN_HASH_ALG)

        crt = ANS1Certificate()
        crt["tbsCertificate"] = tbs_cert
        crt["signatureAlgorithm"] = signature_algorithm
        crt["signature"] = signature

        with open("/tmp/d", "wb+") as f:
            f.write(der_encoder(crt))


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

        with open("/tmp/c", "wb+") as f:
            f.write(csr_der)

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

