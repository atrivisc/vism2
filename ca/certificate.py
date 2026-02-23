""""""
import hashlib
import random
from datetime import datetime, timedelta, timezone
from typing import Self

import pkcs11
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import SignatureAlgorithmOID
from pyasn1 import error
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.codec.native.decoder import decode as dict_decoder
from pyasn1.type import univ, tag, useful
from pyasn1.type.base import Asn1Item
from pyasn1_modules import rfc2985, rfc2986, rfc5280, rfc2315
from pyasn1_modules.rfc5280 import CertificateList

from ca.asn1 import RevokedCertificates, RevokedCertificateEntry, get_ans1_time
from ca.config import CertificateConfig, ca_logger
from ca.database import IssuedCertificate, CertificateEntity, VismCADatabase
from ca.p11 import PKCS11PrivKey, PKCS11PubKey, PKCS11Client
from lib.errors import VismBreakingException

_revocation_reason_map = {
    "unspecified": rfc5280.CRLReason("unspecified"),
    "keyCompromise": rfc5280.CRLReason("keyCompromise"),
    "cACompromise": rfc5280.CRLReason("cACompromise"),
    "affiliationChanged": rfc5280.CRLReason("affiliationChanged"),
    "superseded": rfc5280.CRLReason("superseded"),
    "cessationOfOperation": rfc5280.CRLReason("cessationOfOperation"),
    "certificateHold": rfc5280.CRLReason("certificateHold"),
    "removeFromCRL": rfc5280.CRLReason("removeFromCRL"),
    "privilegeWithdrawn": rfc5280.CRLReason("privilegeWithdrawn"),
    "aACompromise": rfc5280.CRLReason("aACompromise"),
}

class Certificate:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """
    CSR_VERSION = 0x0
    CERT_VERSION = 0x2
    CRL_VERSION = 0x1
    CSR_SIGN_HASH_ALG = "SHA384"
    CRT_SIGN_HASH_ALG = "SHA384"
    CRL_SIGN_HASH_ALG = "SHA384"

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
        ca_logger.info(f"Certificate {self.config.name} is signing obj {obj}")
        signature_algorithm_dict = {
            "algorithm": univ.ObjectIdentifier(self._signature_algorithm_oid(hash_algorithm_name))
        }

        signature_algorithm = dict_decoder(signature_algorithm_dict, asn1Spec=rfc5280.AlgorithmIdentifier())
        signature_bytes = self.controller.p11_client.sign_data(self.priv_key, der_encoder(obj), hash_algorithm_name)
        if self.priv_key.key_type == pkcs11.KeyType.EC:
            sig_len = len(signature_bytes)
            int1 = signature_bytes[:(sig_len // 2)]
            int2 = signature_bytes[(sig_len // 2):]
            signature_bytes = encode_dss_signature(int.from_bytes(int1), int.from_bytes(int2))

        bit_string = univ.BitString.fromHexString(signature_bytes.hex())

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

        validity["notBefore"] = get_ans1_time(not_before_time)
        validity["notAfter"] = get_ans1_time(not_after_time)

        ### Extensions ###
        extensions = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

        ### Subject Key Identifier ###
        skid_extension = rfc5280.Extension()

        skid_key_hash = hashlib.sha1(der_encoder(csr_info.getComponentByName("subjectPKInfo"))).digest()
        skid_extension["extnID"] = x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string
        skid_extension["extnValue"] = der_encoder(rfc5280.SubjectKeyIdentifier(skid_key_hash))
        extensions.append(skid_extension)

        ### Authority Key Identifier ###
        akid_extension = rfc5280.Extension()
        akid_key_hash = hashlib.sha1(self.pub_key.public_bytes()).digest()

        if skid_key_hash != akid_key_hash:
            akid = rfc5280.AuthorityKeyIdentifier()
            akid['keyIdentifier'] = akid_key_hash

            akid_extension["extnID"] = x509.OID_AUTHORITY_KEY_IDENTIFIER.dotted_string
            akid_extension["extnValue"] = der_encoder(akid)
            extensions.append(akid_extension)

        ### Requested Extensions ###
        csr_attributes: rfc2986.Attributes = csr_info.getComponentByName("attributes")
        ext_req_attr = next(filter(lambda attr: attr['type'] == univ.ObjectIdentifier("1.2.840.113549.1.9.14"), csr_attributes), None)
        if ext_req_attr:
            requested_extensions = ext_req_attr['values']
            for ext_oct in requested_extensions:
                ext = der_decoder(ext_oct, asn1Spec=rfc5280.Extension())[0]
                extensions.append(ext)

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

    async def _build_crl(self):
        tbs_crl = rfc5280.TBSCertList()

        signature_algorithm = rfc5280.AlgorithmIdentifier()
        signature_algorithm["algorithm"] = univ.ObjectIdentifier(self._signature_algorithm_oid(self.CRL_SIGN_HASH_ALG))

        revoked_certificates = RevokedCertificates()
        issued_certificates = self.database.get_issued_certificate(self.db_entry.id)

        for cert in issued_certificates:
            cert_expiry_time = None
            try:
                cert_expiry_time = der_decoder(cert.expiration_date, asn1Spec=useful.UTCTime())[0]
            except error.PyAsn1Error:
                pass

            try:
                cert_expiry_time = der_decoder(cert.expiration_date, asn1Spec=useful.UTCTime())[0]
            except error.PyAsn1Error:
                pass

            if cert_expiry_time is None:
                raise VismBreakingException(f"Certificate has invalid expiration date: {cert.expiration_date}")


            if cert_expiry_time.asDateTime <= datetime.now(timezone.utc):
                cert.status_flag = "e"
                self.database.save_to_db(cert)

            if cert.status_flag == "v":
                continue

            if cert.status_flag in ["r", "e"]:
                crl_entry = RevokedCertificateEntry()
                crl_entry['userCertificate'] = der_decoder(cert.serial, asn1Spec=rfc2315.SerialNumber())[0]

                if cert.status_flag == "e":
                    crl_entry['revocationDate'] = cert_expiry_time
                elif cert.status_flag == "r":
                    cert_revocation_time = der_decoder(cert.revocation_date, asn1Spec=rfc5280.Time())[0]

                    revocation_reason = _revocation_reason_map.get(cert.revocation_reason, _revocation_reason_map["unspecified"])
                    crl_extensions = rfc5280.Extensions()

                    revocation_reason_ext = rfc5280.Extension()
                    revocation_reason_ext['extnID'] = x509.OID_CRL_REASON.dotted_string
                    revocation_reason_ext['extnValue'] = univ.OctetString(der_encoder(revocation_reason))
                    crl_extensions.append(revocation_reason_ext)

                    crl_entry['revocationDate'] = cert_revocation_time
                    crl_entry['crlEntryExtensions'] = crl_extensions

                revoked_certificates.append(crl_entry)

        tbs_crl['version'] = self.CRL_VERSION
        tbs_crl["signature"] = signature_algorithm
        tbs_crl["issuer"] = self.config.x509.subject_name.to_asn1()
        tbs_crl["thisUpdate"] = get_ans1_time(datetime.now(timezone.utc) - timedelta(hours=1))
        tbs_crl["nextUpdate"] = get_ans1_time(datetime.now(timezone.utc) + timedelta(days=self.config.x509.crl_days))
        tbs_crl["revokedCertificates"] = revoked_certificates

        signature_algorithm, signature = await self._sign_object(tbs_crl, self.CRL_SIGN_HASH_ALG)

        crl = CertificateList()
        crl['tbsCertList'] = tbs_crl
        crl['signatureAlgorithm'] = signature_algorithm
        crl['signature'] = signature

        return der_encoder(crl)

    async def create(self) -> CertificateEntity:
        ca_logger.info(f"Creating certificate {self.config.name}")

        if self.config.externally_managed or (self.issuer and self.issuer.config.externally_managed):
            if self.config.certificate_pem is None or self.config.crl_pem is None:
                raise VismBreakingException(
                    f"Certificate {self.config.name} is externally managed or "
                    f"signed by an externally managed certificate, but no certificate or CRL was provided in the config."
                )

            crt_der = x509.load_pem_x509_certificate(self.config.certificate_pem.encode("utf-8")).public_bytes(encoding=serialization.Encoding.DER)
            crl_der = x509.load_pem_x509_crl(self.config.crl_pem.encode("utf-8")).public_bytes(encoding=serialization.Encoding.DER)

            self.db_entry.crt_der = crt_der
            self.db_entry.crl_der = crl_der

            return await self.save_to_db()

        if self.config.signed_by is None:
            if self.db_entry.crt_der is None:
                csr_der = await self._create_csr()
                crt_der = await self._sign_csr(csr_der, self.config.x509.days)

                self.db_entry.crt_der = crt_der
            #
            # if self.db_entry.crl_der is None:
            #     crl_der = await self._build_crl()
            #     self.db_entry.crl_der = crl_der

            return await self.save_to_db()

        if self.issuer:
            if self.db_entry.crt_der is None:
                csr_der = await self._create_csr()
                crt_der = await self.issuer._sign_csr(csr_der, self.config.x509.days)
                self.db_entry.crt_der = crt_der

            # if self.db_entry.crl_der is None:
            #     crl_der = await self._build_crl()
            #     self.db_entry.crl_der = crl_der

            return await self.save_to_db()

        raise VismBreakingException("I dont know how you got here")

    async def save_to_db(self):
        await self.controller.s3_client.upload_bytes(self.db_entry.crt_der, f"crt/{self.config.name}.crt")
        await self.controller.s3_client.upload_bytes(self.db_entry.crt_der, f"crl/{self.config.name}.crl")

        with open(f"/home/user01/Downloads/{self.config.name}.crt", "wb+") as f:
            f.write(self.db_entry.crt_der)

        with open(f"/home/user01/Downloads/{self.config.name}.pub", "wb+") as f:
            f.write(self.pub_key.public_bytes())

        self._db_entry = self.database.save_to_db(self.db_entry)
        return self.db_entry


    async def load(self) -> CertificateEntity:
        ca_logger.info(f"Loading certificate {self.config.name}")

        # This also loads all the important attributes when the key already exists
        self.pub_key, self.priv_key = self.p11_client.generate_keypair(self.pub_key, self.priv_key)

        if self.db_entry is None or self.db_entry.crt_der is None:
            return await self.create()

        return self.db_entry

