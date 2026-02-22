""""""
import hashlib
import random
from datetime import datetime, timedelta, timezone
from typing import Self

import pkcs11
from cryptography import x509
from cryptography.x509 import SignatureAlgorithmOID
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.codec.native.decoder import decode as dict_decoder
from pyasn1.type import univ, useful, tag
from pyasn1.type.base import Asn1Item
from pyasn1_modules import rfc2985, rfc2986, rfc5280, rfc2315

from ca.config import CertificateConfig, ca_logger
from ca.database import IssuedCertificate, CertificateEntity, VismCADatabase
from ca.p11 import PKCS11PrivKey, PKCS11PubKey, PKCS11Client
from lib.errors import VismBreakingException


class Certificate:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """
    CSR_VERSION = 0x0
    CERT_VERSION = 0x2
    CRL_VERSION = 0x0
    CSR_SIGN_HASH_ALG = "SHA256"
    CRT_SIGN_HASH_ALG = "SHA256"
    CRL_SIGN_HASH_ALG = "SHA256"

    def __init__(self, controller, config: CertificateConfig, issuer: Self | None):
        self.controller = controller
        self.database: VismCADatabase = controller.database
        self.p11_client: PKCS11Client = controller.p11_client

        self.config = config

        self.issuer = issuer

        self.priv_key = PKCS11PrivKey(self.config.key_p11_attributes)
        self.pub_key = PKCS11PubKey(self.config.key_p11_attributes, self.config.key.curve)

        self._db_entry = None

    @property
    def db_entry(self) -> CertificateEntity:
        if self._db_entry is None:
            self._db_entry = self.database.get_cert_by_name(self.config.name)

        if self._db_entry is None:
            self._db_entry = CertificateEntity(
                name=self.config.name,
                externally_managed=self.config.externally_managed,
            )
            self._db_entry = self.database.save_to_db(self._db_entry)

        return self._db_entry

    def _signature_algorithm_oid(self, hash_algorithm_name: str) -> str:
        if self.priv_key.key_type == pkcs11.KeyType.RSA:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'RSA_WITH_{hash_algorithm_name}').dotted_string
        elif self.priv_key.key_type == pkcs11.KeyType.EC:
            algorithm_oid = SignatureAlgorithmOID().__getattribute__(f'ECDSA_WITH_{hash_algorithm_name}').dotted_string
        else:
            raise NotImplementedError

        return algorithm_oid

    async def _sign_object(self, obj: Asn1Item, hash_algorithm_name: str) -> tuple[rfc5280.AlgorithmIdentifier, univ.BitString]:
        signature_algorithm_dict = {
            "algorithm": univ.ObjectIdentifier(self._signature_algorithm_oid(hash_algorithm_name))
        }

        signature_algorithm = dict_decoder(signature_algorithm_dict, asn1Spec=rfc5280.AlgorithmIdentifier())
        signature_bytes = self.controller.p11_client.sign_data(self.priv_key, der_encoder(obj), hash_algorithm_name)
        bit_string = univ.BitString(''.join(f'{byte:08b}' for byte in signature_bytes))

        return signature_algorithm, bit_string

    async def _create_csr(self) -> bytes:
        attributes = rfc2986.Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        ext_req_attribute = rfc2985.SingleAttribute()
        ext_req_attribute_val = rfc2985.AttributeValues()

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

        csr_info = rfc2986.CertificationRequestInfo()
        csr_info["version"] = self.CSR_VERSION
        csr_info['subject'] = self.config.x509.subject_name.to_asn1()
        csr_info['subjectPKInfo'] = der_decoder(self.pub_key.public_bytes(), asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]
        csr_info['attributes'] = attributes

        csr = rfc2986.CertificationRequest()
        csr.setComponentByName("certificationRequestInfo", csr_info)

        signature_algorithm, signature = await self._sign_object(csr_info, self.CRT_SIGN_HASH_ALG)
        csr.setComponentByName("signatureAlgorithm", signature_algorithm)
        csr.setComponentByName("signature", signature)

        return der_encoder(csr)

    @staticmethod
    def _get_ans1_time(dt: datetime) -> rfc5280.Time:
        time = rfc5280.Time()

        if dt.year > 2049:
            time["generalTime"] = useful.GeneralizedTime.fromDateTime(dt)
        else:
            time["utcTime"] = useful.UTCTime.fromDateTime(dt)

        return time

    async def _sign_csr(self, csr_der: bytes, days: int) -> bytes:
        csr: rfc2986.CertificationRequest = der_decoder(csr_der, asn1Spec=rfc2986.CertificationRequest())[0]
        csr_info = csr.getComponentByName("certificationRequestInfo")

        tbs_cert = rfc5280.TBSCertificate()

        ### Signature ###
        signature_algorithm = rfc2986.AlgorithmIdentifier()
        signature_algorithm_oid = univ.ObjectIdentifier(self._signature_algorithm_oid(self.CSR_SIGN_HASH_ALG))
        signature_algorithm["algorithm"] = signature_algorithm_oid

        ### Validity ###
        validity = rfc5280.Validity()

        now = datetime.now(timezone.utc)

        not_before_time = now - timedelta(hours=1)
        not_after_time = now + timedelta(days=days)

        validity["notBefore"] = self._get_ans1_time(not_before_time)
        validity["notAfter"] = self._get_ans1_time(not_after_time)

        ### Extensions ###
        extensions = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        ### Subject Key Identifier ###
        skid_extension = rfc5280.Extension()
        skid_extension["extnID"] = x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string

        subject_pub_key_bitstring = csr_info.getComponentByName("subjectPKInfo").getComponentByName("subjectPublicKey")
        skid = hashlib.sha1(subject_pub_key_bitstring.asOctets()).hexdigest().upper()
        skid_string = ":".join(skid[i:i+2] for i in range(0, len(skid), 2))
        skid_extension["extnValue"] = univ.OctetString(skid_string)

        ### Authority Key Identifier ###
        akid_extension = rfc5280.Extension()
        akid_extension.setComponentByName("extnID", x509.OID_AUTHORITY_KEY_IDENTIFIER.dotted_string)

        issuer_pub_key_bytes = self.pub_key.public_bytes()
        akid = hashlib.sha1(issuer_pub_key_bytes).hexdigest().upper()
        akid_string = ":".join(akid[i:i+2] for i in range(0, len(akid), 2))
        akid_extension["extnValue"] = univ.OctetString(akid_string)

        ### Requested Extensions ###
        csr_attributes: rfc2986.Attributes = csr_info.getComponentByName("attributes")
        ext_req_attr = next(filter(lambda attr: attr['type'] == univ.ObjectIdentifier("1.2.840.113549.1.9.14"), csr_attributes), None)
        if ext_req_attr:
            requested_extensions = ext_req_attr['values']
            for ext_oct in requested_extensions:
                ext = der_decoder(ext_oct, asn1Spec=rfc5280.Extension())[0]
                extensions.append(ext)

        extensions.append(akid_extension)
        extensions.append(skid_extension)

        tbs_cert["version"] = self.CERT_VERSION
        tbs_cert["serialNumber"] = rfc5280.CertificateSerialNumber(random.getrandbits(159))
        tbs_cert["signature"] = signature_algorithm
        tbs_cert["issuer"] = self.config.x509.subject_name.to_asn1()
        tbs_cert["validity"] = validity
        tbs_cert["subject"] = csr_info.getComponentByName("subject")
        tbs_cert["subjectPublicKeyInfo"] = csr_info.getComponentByName("subjectPKInfo")
        tbs_cert["extensions"] = extensions

        ### Certificate ###
        signature_algorithm, signature = await self._sign_object(tbs_cert, self.CRT_SIGN_HASH_ALG)

        crt = rfc5280.Certificate()
        crt["tbsCertificate"] = tbs_cert
        crt["signatureAlgorithm"] = signature_algorithm
        crt["signature"] = signature

        issued_certificate = IssuedCertificate(
            status_flag = "v",
            expiration_date = der_encoder(validity["notAfter"]),
            serial = der_encoder(tbs_cert["serialNumber"]),
            subject = der_encoder(tbs_cert["subject"]),
            ca = self.db_entry
        )
        self.database.save_to_db(issued_certificate)

        return der_encoder(crt)

    def _build_crl(self):
        crl = rfc2315.TBSCertificateRevocationList()

        signature_algorithm = rfc5280.AlgorithmIdentifier()
        signature_algorithm["algorithm"] = univ.ObjectIdentifier(self._signature_algorithm_oid(self.CRL_SIGN_HASH_ALG))

        revoked_certificates = univ.SequenceOf(componentType=rfc2315.CRLEntry())

        crl["signature"] = signature_algorithm
        crl["issuer"] = self.config.x509.subject_name.to_asn1()
        crl["lastUpdate"] = useful.UTCTime.fromDateTime(datetime.now() - timedelta(hours=1))
        crl["nextUpdate"] = useful.UTCTime.fromDateTime(datetime.now() + timedelta(days=self.config.x509.crl_days))


    async def create(self) -> None:
        ca_logger.info(f"Creating certificate {self.config.name}")

        self.pub_key, self.priv_key = self.p11_client.generate_keypair(self.pub_key, self.priv_key)

        if self.config.externally_managed:
            if self.config.certificate_pem is None or self.config.crl_pem is None:
                raise VismBreakingException(f"Certificate {self.config.name} is externally managed, but no certificate or CRL was provided in the config.")

            # TODO
            # self.db_entry.crt_der = self.config.certificate_pem
            # self.db_entry.crl_pem = self.config.crl_pem
            return

        if self.config.signed_by is None:
            if self.db_entry.crt_der is None:
                csr_der = await self._create_csr()
                crt_der = await self._sign_csr(csr_der, self.config.x509.days)

                self.db_entry.crt_der = crt_der
                await self.save_to_db()

    async def save_to_db(self):
        if not await self.controller.s3_client.exists(f"crt/{self.config.name}.crt"):
            await self.controller.s3_client.upload_bytes(self.db_entry.crt_der, f"crt/{self.config.name}.crt")

        if not await self.controller.s3_client.exists(f"crl/{self.config.name}.crl"):
            await self.controller.s3_client.upload_bytes(self.db_entry.crt_der, f"crl/{self.config.name}.crl")

        self._db_entry = self.database.save_to_db(self.db_entry)


    async def load(self):
        ca_logger.info(f"Loading certificate {self.config.name}")

        if self.db_entry is None or self.db_entry.crt_der is None:
            await self.create()

